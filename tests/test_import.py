"""F08 acceptance scenarios T01-T20 (US40858 Part 1 design §2) plus adapter boundary checks.

Shared by the SQLite regression run and the migrated PostgreSQL run.
"""
import json
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path
import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient
from sqlalchemy import func, select
from app.import_schema import json_schema_v1
from app.importer import ImportEvent, ImportRun, MalwareDetected
from app.main import create_app
from app.models import (AuditLog, Claim, EventLedger, ImportFileEvidence, ImportFileEvidenceSubject, MutationReceipt,
                        Subject, SubjectBinding)
from app.security import sha256
from app.service import canonical
from app.source_registry import SourceRegistration, default_registry
from test_acceptance import env, headers, history

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"


def record(**changes):
    base = dict(tenant_id="tenant-a", source_record_id="offer-1", source_person_ref="synthetic-001",
                source_version=1, source_updated_at="2026-01-01T00:00:00Z", event_type="offer_accepted",
                role_ref="synthetic-engineer", start_date="2026-11-01", offer_status="accepted",
                effective_from="2026-01-01T00:00:00Z")
    base.update(changes)
    return base


def file(records=None, **changes):
    records = records if records is not None else [record()]
    payload = b"".join(canonical(r) + b"\n" for r in records)
    header = dict(schema_version="1", source_system_id="ATS", tenant_id="tenant-a", snapshot_id="snapshot-1",
                  generated_at=datetime.now(timezone.utc).isoformat(), record_count=len(records),
                  content_hash=sha256(payload))
    header.update(changes)
    return canonical(header) + b"\n" + payload


def upload(client, raw, source="ATS", **identity):
    return client.post(f"/imports/{source}", content=raw,
                       headers={**headers(roles="data_administrator", **identity), "Content-Type": "application/x-ndjson"})


def counts(app):
    with app.state.sessions() as db:
        return [db.scalar(select(func.count()).select_from(m)) for m in (Subject, Claim, EventLedger)]


def rows(app, model):
    with app.state.sessions() as db:
        return db.scalars(select(model)).all()


def outcomes(report):
    return [(o["outcome"], o["reason_code"]) for o in report["outcomes"]]


def evidence(client, sid, evidence_id):
    response = client.get(f"/subjects/{sid}/evidence/{evidence_id}", params={"purpose": "audit_reconstruction"},
                          headers=headers(account="auditor", roles="auditor"))
    return response.status_code, response.content


def twin(client, sid):
    return client.get(f"/subjects/{sid}/twin", params={"purpose": "preboarding_support"},
                      headers=headers(account="support", roles="support")).json()["predicates"]


def freshness(client, tenant="tenant-a"):
    return client.get("/imports/ATS/freshness", headers=headers(tenant, roles="data_administrator")).json()


def no_values(text):
    return "synthetic-engineer" not in text and "2026-11-01" not in text and "tenant-b" not in text


# ----- T01-T03: clean import, file and record idempotency -----

def test_t01_valid_new_offer_atomic_claims_snapshot_and_events(env):
    client, app = env
    raw = file()
    report = upload(client, raw).json()
    assert report["status"] == "complete" and report["total_records"] == 1 and report["attempt_count"] == 1
    assert report["counts"] == {"accepted": 1, "superseded": 0, "historical": 0, "duplicate": 0,
                                "held_for_review": 0, "contested": 0, "rejected": 0}
    assert outcomes(report) == [("accepted", "ACCEPTED")] and counts(app) == [1, 3, 4]
    o = report["outcomes"][0]
    assert o["source_record_id"] == "offer-1" and o["source_version"] == 1
    assert {c["status"] for c in o["f01"]["claims"]} == {"current"} and len(o["f01"]["claims"]) == 3
    assert no_values(json.dumps(report))
    sid = o["f01"]["subject_id"]
    snapshot = o["f01"]["snapshot"]
    with app.state.sessions() as db:
        assert app.state.service.verify_ledger(db, sid)
        # Canonical events: one EvidenceAcquired for the shared snapshot, then one ClaimAccepted per claim.
        assert [e.event_type for e in db.scalars(select(EventLedger).order_by(EventLedger.sequence))] == [
            "EvidenceAcquired", "ClaimAccepted", "ClaimAccepted", "ClaimAccepted"]
        claims = db.scalars(select(Claim).where(Claim.subject_id == sid)).all()
        assert {c.predicate for c in claims} == {"offer_status", "offered_role", "start_date"}
        # Every mapped claim references the one per-record subject snapshot, not the raw file.
        assert {c.evidence_id for c in claims} == {snapshot["evidence_id"]}
        assert {c.evidence_hash for c in claims} == {snapshot["evidence_hash"]}
        assert db.get(ImportFileEvidenceSubject, (report["file_evidence_id"], sid))
        assert db.get(SubjectBinding, db.scalar(select(SubjectBinding.id))).authenticated_account_id is None
    status, content = evidence(client, sid, snapshot["evidence_id"])
    assert status == 200 and sha256(content) == snapshot["evidence_hash"]
    body = json.loads(content)
    assert body["record"] == json.loads(canonical(record())) and body["position"] == 1
    assert body["file_hash"] == report["file_hash"] and body["snapshot_id"] == "snapshot-1"
    assert body["record_hash"] == o["record_hash"] == sha256(raw.split(b"\n")[1])
    assert twin(client, sid)["start_date"]["value"] == "2026-11-01"
    assert twin(client, sid)["offered_role"]["value"] == "synthetic-engineer"
    assert freshness(client)["state"] == "fresh" and freshness(client, "tenant-b")["state"] == "missing"


def test_t02_same_file_twice_short_circuits_without_resubmission(env, monkeypatch):
    client, app = env
    raw = file()
    first = upload(client, raw).json()
    receipts = len(rows(app, MutationReceipt))
    monkeypatch.setattr(app.state.service, "submit_import_record",
                        lambda *a, **k: pytest.fail("record resubmitted to F01"))
    duplicate = upload(client, raw).json()
    assert duplicate["duplicate_file"] and duplicate["status"] == "complete" and duplicate["attempt_count"] == 2
    assert duplicate["outcomes"] == first["outcomes"] and duplicate["run_id"] == first["run_id"]
    assert counts(app) == [1, 3, 4] and len(rows(app, MutationReceipt)) == receipts
    assert len(rows(app, ImportFileEvidence)) == 1


def test_t03_same_record_in_another_file_is_duplicate_with_original_references(env):
    client, app = env
    first = upload(client, file()).json()["outcomes"][0]
    second = upload(client, file(snapshot_id="another")).json()
    assert outcomes(second) == [("duplicate", "DUPLICATE")]
    assert second["outcomes"][0]["f01"] == first["f01"] and counts(app) == [1, 3, 4]


# ----- T04-T06: versioning -----

def test_t04_higher_version_supersedes_and_keeps_history(env):
    client, app = env
    sid = upload(client, file()).json()["outcomes"][0]["f01"]["subject_id"]
    r = record(source_version=3, start_date="2026-11-08", event_type="offer_updated")
    report = upload(client, file([r], snapshot_id="new")).json()
    assert outcomes(report) == [("superseded", "SUPERSEDED")]
    assert len(report["outcomes"][0]["f01"]["superseded_claim_ids"]) == 3
    assert twin(client, sid)["start_date"]["value"] == "2026-11-08"
    with app.state.sessions() as db:
        statuses = sorted(db.scalars(select(Claim.status).where(Claim.subject_id == sid)))
        assert statuses == ["current"] * 3 + ["superseded"] * 3
        superseded_events = db.scalars(select(EventLedger).where(EventLedger.event_type == "ClaimSuperseded")).all()
        assert {e.claim_id for e in superseded_events} == {c for c in db.scalars(select(Claim.id).where(Claim.status == "superseded"))}
        assert app.state.service.verify_ledger(db, sid)
    assert history(client, sid, system_at="2099-01-01T00:00:00Z").json()["predicates"]["start_date"]["value"] == "2026-11-08"


def test_t05_older_version_after_newer_is_historical(env):
    client, app = env
    sid = upload(client, file()).json()["outcomes"][0]["f01"]["subject_id"]
    upload(client, file([record(source_version=3, start_date="2026-11-08", event_type="offer_updated")], snapshot_id="new"))
    late = record(source_version=2, start_date="2026-11-04", event_type="offer_updated", effective_from="2025-06-01T00:00:00Z")
    report = upload(client, file([late], snapshot_id="late")).json()
    assert outcomes(report) == [("historical", "LATE_HISTORICAL")]
    assert twin(client, sid)["start_date"]["value"] == "2026-11-08"
    # Correct valid time: the late version only fills the earlier, uncovered interval.
    assert history(client, sid, valid_at="2025-07-01T00:00:00Z", system_at="2099-01-01T00:00:00Z").json()["predicates"]["start_date"]["value"] == "2026-11-04"


def test_t06_same_version_different_content_is_contested(env):
    client, app = env
    sid = upload(client, file()).json()["outcomes"][0]["f01"]["subject_id"]
    conflict = record(start_date="2026-11-15")
    report = upload(client, file([conflict], snapshot_id="conflict")).json()
    assert outcomes(report) == [("contested", "VERSION_CONFLICT")]
    assert twin(client, sid)["start_date"] == {"state": "unknown", "reason": "contested"}
    p = history(client, sid, system_at="2099-01-01T00:00:00Z").json()["predicates"]["start_date"]
    assert p["conflict_state"] == "unresolved" and len(p["claims"]) == 2
    with app.state.sessions() as db:
        assert app.state.service.verify_ledger(db, sid)
        events = [e.event_type for e in db.scalars(select(EventLedger).order_by(EventLedger.sequence))]
        # Only the value-conflicting start_date claims are contested; the identical offer_status and
        # offered_role claims of the conflicting record are accepted as historical.
        assert events == ["EvidenceAcquired"] + ["ClaimAccepted"] * 3 + ["EvidenceAcquired", "ClaimAccepted",
                          "ClaimAccepted", "ClaimProposed", "ClaimContested", "ClaimContested"]


# ----- T07-T11: tenant, source and file gates -----

def test_t07_record_tenant_mismatch_rejected_without_state(env):
    client, app = env
    response = upload(client, file([record(tenant_id="tenant-b")]))
    assert response.status_code == 200 and outcomes(response.json()) == [("rejected", "WRONG_TENANT")]
    assert "synthetic-engineer" not in response.text and "2026-11-01" not in response.text
    assert counts(app) == [0, 0, 0] and freshness(client)["state"] == "missing"


@pytest.mark.parametrize("change,reason", [
    (dict(source_system_id="HR"), "SOURCE_NOT_REGISTERED"),          # T08
    (dict(tenant_id="tenant-b"), "FILE_TENANT_MISMATCH"),             # T09
    (dict(schema_version="2"), "SCHEMA_VERSION_UNSUPPORTED"),         # T10
    (dict(schema_version=1), "SCHEMA_VERSION_UNSUPPORTED"),
    (dict(source_system_id=["ATS"]), "SOURCE_NOT_REGISTERED"),
    (dict(content_hash="0" * 64), "FILE_INTEGRITY_FAILED"),           # T11
    (dict(record_count=2), "FILE_INTEGRITY_FAILED"),                  # T11
    (dict(generated_at="2099-01-01T00:00:00Z"), "FILE_INTEGRITY_FAILED"),
    (dict(signature="x"), "FILE_STRUCTURE_INVALID"),
])
def test_t08_t11_file_gate_rejects_whole_file_without_canonical_state(env, change, reason):
    client, app = env
    raw = file(**change)
    response = upload(client, raw)
    assert response.status_code == 422 and response.json()["detail"] == reason
    assert counts(app) == [0, 0, 0] and freshness(client)["state"] == "missing"
    assert rows(app, ImportRun) == [] and rows(app, ImportFileEvidence) == []
    events = rows(app, ImportEvent)
    assert [(e.event_type, e.reason_code) for e in events] == [("ImportFileRejected", reason)]
    assert events[0].detail == {"file_hash": sha256(raw)} and events[0].actor == "sync"


def test_t08_unregistered_path_source_is_rejected(env):
    client, app = env
    response = upload(client, file(source_system_id="HR"), source="HR")
    assert response.status_code == 422 and response.json()["detail"] == "SOURCE_NOT_REGISTERED"
    assert client.get("/imports/HR/freshness", headers=headers(roles="data_administrator")).status_code == 422
    assert counts(app) == [0, 0, 0]


def test_t11_signature_verified_when_configured(tmp_path):
    registration = SourceRegistration("ATS", frozenset({"1"}), default_registry()["ATS"].field_mapping, b"poc-secret")
    app = create_app(f"sqlite:///{tmp_path}/edt.db", str(tmp_path / "evidence"), source_registry={"ATS": registration})
    with TestClient(app) as client:
        unsigned = upload(client, file())
        assert unsigned.status_code == 422 and unsigned.json()["detail"] == "FILE_INTEGRITY_FAILED"
        content_hash = json.loads(file().split(b"\n")[0])["content_hash"]
        wrong = upload(client, file(signature=registration.signature_for("0" * 64)))
        assert wrong.status_code == 422 and wrong.json()["detail"] == "FILE_INTEGRITY_FAILED"
        signed = upload(client, file(signature=registration.signature_for(content_hash)))
        assert signed.status_code == 200 and outcomes(signed.json()) == [("accepted", "ACCEPTED")]
        assert counts(app) == [1, 3, 4]


def test_malware_scan_hook_rejects_before_parsing(tmp_path):
    class Scanner:
        def scan(self, content):
            raise MalwareDetected("synthetic signature")
    app = create_app(f"sqlite:///{tmp_path}/edt.db", str(tmp_path / "evidence"), malware_scanner=Scanner())
    with TestClient(app) as client:
        response = upload(client, file())
        assert response.status_code == 422 and response.json()["detail"] == "FILE_REJECTED_MALWARE"
        assert counts(app) == [0, 0, 0] and rows(app, ImportRun) == []


# ----- T12-T15: holds, record validation, authority and atomicity -----

def test_t12_update_for_unbound_subject_is_held_outside_twin(env):
    client, app = env
    report = upload(client, file([record(event_type="offer_updated")])).json()
    assert outcomes(report) == [("held_for_review", "UNBOUND_SUBJECT")]
    held = report["outcomes"][0]
    assert held["f01"] is None and held["retention_rule"] == "import_hold_short_review"
    assert held["evidence_ref"] == {"file_evidence_id": report["file_evidence_id"], "position": 1,
                                    "record_hash": held["record_hash"]}
    assert counts(app) == [0, 0, 0] and rows(app, SubjectBinding) == []
    events = rows(app, ImportEvent)
    assert [(e.event_type, e.reason_code, e.run_id) for e in events] == [("ImportRecordHeld", "UNBOUND_SUBJECT", report["run_id"])]
    assert events[0].detail["position"] == 1 and no_values(json.dumps(events[0].detail))
    assert freshness(client)["state"] == "missing"
    # Once the subject is bound, the retried update (new snapshot) is accepted.
    upload(client, file(snapshot_id="bind"))
    retry = upload(client, file([record(source_version=2, event_type="offer_updated")], snapshot_id="retry")).json()
    assert outcomes(retry) == [("superseded", "SUPERSEDED")]


def test_t13_one_invalid_record_among_valid_records(env):
    client, app = env
    bad = record(source_record_id="offer-2", source_person_ref="synthetic-002", source_version=0)
    other = record(source_record_id="offer-3", source_person_ref="synthetic-003")
    report = upload(client, file([record(), bad, other])).json()
    assert outcomes(report) == [("accepted", "ACCEPTED"), ("rejected", "INVALID_RECORD"), ("accepted", "ACCEPTED")]
    assert report["counts"]["accepted"] == 2 and report["counts"]["rejected"] == 1
    assert counts(app) == [2, 6, 8]
    with app.state.sessions() as db:
        assert db.scalar(select(func.count()).select_from(Claim).where(Claim.source_record_id == "offer-2")) == 0


@pytest.mark.parametrize("change,reason", [
    ({"work_location": "excluded"}, "NOT_AUTHORITATIVE"),
    ({"manager_ref": "excluded"}, "NOT_AUTHORITATIVE"),
    ({"preferred_name": "excluded"}, "NOT_AUTHORITATIVE"),
    ({"source_version": 0}, "INVALID_RECORD"),
    ({"source_version": True}, "INVALID_RECORD"),
    ({"source_version": "1"}, "INVALID_RECORD"),
    ({"start_date": "invalid"}, "INVALID_RECORD"),
    ({"source_updated_at": "no-zone"}, "INVALID_RECORD"),
    ({"event_type": "offer_withdrawn"}, "INVALID_RECORD"),
    ({"offer_status": "withdrawn"}, "INVALID_RECORD"),
    ({"source_updated_at": "2099-01-01T00:00:00Z"}, "INVALID_RECORD"),
])
def test_t14_non_authoritative_or_invalid_record_rejected_entirely(env, change, reason):
    client, app = env
    r = record(); r.update(change)
    response = upload(client, file([r]))
    assert response.status_code == 200 and outcomes(response.json()) == [("rejected", reason)]
    assert no_values(response.text) and counts(app) == [0, 0, 0]


def test_t14_missing_required_field_rejected(env):
    client, app = env
    r = record(); del r["start_date"]
    assert outcomes(upload(client, file([r])).json()) == [("rejected", "INVALID_RECORD")]
    assert counts(app) == [0, 0, 0]


def test_t15_one_failing_mapped_claim_fails_the_whole_record(env, monkeypatch):
    client, app = env
    original = app.state.service._mutate

    def fail_second(db, identity, sid, body, correlation, commit=True, **kwargs):
        if body.predicate == "offered_role":
            raise HTTPException(422, "INJECTED_FAILURE")
        return original(db, identity, sid, body, correlation, commit, **kwargs)
    monkeypatch.setattr(app.state.service, "_mutate", fail_second)
    report = upload(client, file()).json()
    assert outcomes(report) == [("rejected", "INJECTED_FAILURE")]
    assert counts(app) == [0, 0, 0] and rows(app, SubjectBinding) == [] and rows(app, MutationReceipt) == []


# ----- T16-T17: crash/resume and concurrency -----

def test_t16_incomplete_run_resumes_only_unfinished_records(env, monkeypatch):
    client, app = env
    original = app.state.service.submit_import_record
    calls = []

    def crash_after_first(*args, **kwargs):
        result = original(*args, **kwargs)
        calls.append(result["subject_id"])
        if len(calls) == 1:
            raise RuntimeError("crash after canonical commit, before F08 outcome")
        return result
    monkeypatch.setattr(app.state.service, "submit_import_record", crash_after_first)
    second = record(source_record_id="offer-2", source_person_ref="synthetic-002")
    raw = file([record(), second], snapshot_id="crash")
    with pytest.raises(RuntimeError):
        upload(client, raw)
    assert counts(app) == [1, 3, 4]
    with app.state.sessions() as db:
        run = db.get(ImportRun, sha256(canonical(["tenant-a", "ATS", "crash", json.loads(raw.split(b"\n")[0])["content_hash"]])))
        assert run.status == "in_progress" and run.completed_at is None
    resumed = upload(client, raw).json()
    assert resumed["status"] == "complete" and resumed["attempt_count"] == 2 and not resumed["duplicate_file"]
    # The committed record reuses its F01 receipt and reports as a clean acceptance, not a duplicate.
    assert outcomes(resumed) == [("accepted", "ACCEPTED"), ("accepted", "ACCEPTED")]
    assert resumed["outcomes"][0]["f01"]["subject_id"] == calls[0]
    assert len(calls) == 3 and counts(app) == [2, 6, 8]
    assert len(rows(app, ImportFileEvidence)) == 1
    with app.state.sessions() as db:
        assert db.scalar(select(func.count()).select_from(MutationReceipt)) == 8


def test_t17_parallel_imports_of_same_file_converge(env):
    client, app = env
    raw = file()
    with ThreadPoolExecutor(max_workers=2) as pool:
        responses = list(pool.map(lambda _: upload(client, raw), range(2)))
    assert all(r.status_code == 200 for r in responses)
    assert sum(r.json()["duplicate_file"] for r in responses) == 1
    assert counts(app) == [1, 3, 4] and len(rows(app, ImportRun)) == 1


# ----- T18-T19: write boundary and evidence linkage -----

def test_t18_adapter_cannot_write_canonical_state_directly(env):
    client, app = env
    importer = app.state.importer
    assert not hasattr(importer, "claims") and not hasattr(importer.f01, "sessions")
    assert {name for name in dir(importer.f01) if not name.startswith("_")} == {"store_file_evidence", "submit_record"}
    sid = upload(client, file()).json()["outcomes"][0]["f01"]["subject_id"]
    with app.state.sessions() as db:
        claim = db.scalars(select(Claim)).first()
    for forbidden in (Subject(tenant_id="tenant-a"),
                      Claim(**{c.name: getattr(claim, c.name) for c in Claim.__table__.columns if c.name != "id"}),
                      EventLedger(tenant_id="tenant-a", subject_id=sid, claim_id=claim.id, sequence=99, ciphertext=b"x",
                                  metadata_json={}, previous_hash="0" * 64, record_hash="0" * 64),
                      ImportFileEvidence(id="x" * 64, tenant_id="tenant-a", source_system_id="ATS", snapshot_id="s",
                                         file_hash="0" * 64, evidence_uri="localblob://x", manifest={}, retention_rule="r")):
        with importer.sessions() as db:
            db.add(forbidden)
            with pytest.raises(PermissionError):
                db.flush()
    with importer.sessions() as db:
        with pytest.raises(PermissionError):
            db.get(Claim, claim.id).status = "superseded"; db.flush()
    assert counts(app) == [1, 3, 4]
    with app.state.sessions() as db:
        assert app.state.service.verify_ledger(db, sid)


def test_t19_file_evidence_manifest_subject_snapshots_and_erasure(env):
    client, app = env
    second = record(source_record_id="offer-2", source_person_ref="synthetic-002", role_ref="synthetic-analyst")
    raw = file([record(), second])
    report = upload(client, raw).json()
    header, line1, line2 = raw.split(b"\n")[:3]
    sids = [o["f01"]["subject_id"] for o in report["outcomes"]]
    assert len(set(sids)) == 2
    service = app.state.service
    with app.state.sessions() as db:
        file_evidence = db.get(ImportFileEvidence, report["file_evidence_id"])
        assert file_evidence.file_hash == json.loads(header)["content_hash"]
        assert file_evidence.retention_rule == "preboarding_source_evidence_file"
        assert file_evidence.manifest["records"] == [{"position": 1, "record_hash": sha256(line1)},
                                                     {"position": 2, "record_hash": sha256(line2)}]
        assert file_evidence.wrapped_key and file_evidence.key_reference != db.get(Subject, sids[0]).key_reference
        assert service.read_import_file_evidence(db, file_evidence.id) == raw
        assert {l.subject_id for l in db.scalars(select(ImportFileEvidenceSubject))} == set(sids)
        # The encrypted file object must not be the subject-key snapshot object.
        assert file_evidence.evidence_uri not in {c.evidence_uri for c in db.scalars(select(Claim))}
    for o, line in zip(report["outcomes"], (line1, line2)):
        status, content = evidence(client, o["f01"]["subject_id"], o["f01"]["snapshot"]["evidence_id"])
        body = json.loads(content)
        assert status == 200 and body["record_hash"] == sha256(line) and body["position"] == o["position"]
        assert body["file_hash"] == report["file_hash"] and body["file_evidence_id"] == report["file_evidence_id"]
        assert body["record_hash"] == file_evidence.manifest["records"][o["position"] - 1]["record_hash"]
    # Erasure of one contained subject destroys the shared file key; the other subject keeps its snapshot.
    with app.state.sessions() as db:
        service.crypto_shred_subject(db, sids[0]); db.commit()
    with app.state.sessions() as db:
        file_evidence = db.get(ImportFileEvidence, report["file_evidence_id"])
        assert file_evidence.wrapped_key is None and file_evidence.key_destroyed_reason == "subject_erasure"
        assert file_evidence.manifest["records"][0]["record_hash"] == sha256(line1)
        with pytest.raises(HTTPException) as denied:
            service.read_import_file_evidence(db, file_evidence.id)
        assert denied.value.status_code == 410
    assert evidence(client, sids[0], report["outcomes"][0]["f01"]["snapshot"]["evidence_id"])[0] == 410
    assert evidence(client, sids[1], report["outcomes"][1]["f01"]["snapshot"]["evidence_id"])[0] == 200


# ----- T20: run report over the shipped mixed fixture -----

def test_t20_run_report_counts_over_mixed_fixture(env):
    client, app = env
    raw = (FIXTURES / "offer-update-v1-mixed.jsonl").read_bytes()
    report = upload(client, raw).json()
    assert outcomes(report) == [
        ("accepted", "ACCEPTED"), ("superseded", "SUPERSEDED"), ("historical", "LATE_HISTORICAL"),
        ("contested", "VERSION_CONFLICT"), ("duplicate", "DUPLICATE"), ("held_for_review", "UNBOUND_SUBJECT"),
        ("rejected", "WRONG_TENANT"), ("rejected", "NOT_AUTHORITATIVE"), ("rejected", "INVALID_RECORD")]
    assert report["counts"] == {"accepted": 1, "superseded": 1, "historical": 1, "duplicate": 1,
                                "held_for_review": 1, "contested": 1, "rejected": 3}
    assert sum(report["counts"].values()) == report["total_records"] == 9
    assert set(report) >= {"run_id", "source_system_id", "tenant_id", "snapshot_id", "file_hash", "started_at",
                           "completed_at", "status", "total_records"}
    assert no_values(json.dumps(report)) and "2026-11-08" not in json.dumps(report)
    assert counts(app) == [1, 12, 21]
    sid = report["outcomes"][0]["f01"]["subject_id"]
    assert twin(client, sid)["start_date"] == {"state": "unknown", "reason": "contested"}
    assert twin(client, sid)["offer_status"]["value"] == "accepted"
    assert upload(client, (FIXTURES / "offer-update-v1.jsonl").read_bytes()).json()["counts"]["duplicate"] == 1


def test_published_json_schema_fixture_matches_models():
    assert json.loads((FIXTURES / "offer-update-v1.schema.json").read_text()) == json_schema_v1()
    schema = json_schema_v1()
    assert "authenticated_account_id" not in schema["record"]["properties"]
    assert set(schema["record"]["required"]) == {"tenant_id", "source_record_id", "source_person_ref", "source_version",
        "source_updated_at", "event_type", "role_ref", "start_date", "offer_status", "effective_from"}
    assert schema["header"]["required"] == ["schema_version", "source_system_id", "tenant_id", "snapshot_id",
                                            "generated_at", "record_count", "content_hash"]
    assert "signature" in schema["header"]["properties"]


# ----- Further decision-table rows and operational behaviour -----

def test_future_effective_from_accepted_but_not_current(env):
    client, app = env
    report = upload(client, file([record(effective_from="2099-01-01T00:00:00Z")])).json()
    assert outcomes(report) == [("accepted", "FUTURE_VALID")]
    sid = report["outcomes"][0]["f01"]["subject_id"]
    assert twin(client, sid)["start_date"] == {"state": "unknown", "reason": "not_yet_valid"}
    assert history(client, sid, valid_at="2099-06-01T00:00:00Z", system_at="2099-06-01T00:00:00Z").json()["predicates"]["start_date"]["value"] == "2026-11-01"
    assert history(client, sid, system_at="2099-06-01T00:00:00Z").json()["predicates"]["start_date"]["state"] == "unknown"


def test_binding_integrity_error_raises_alert(env):
    client, app = env
    upload(client, file())
    moved = record(source_person_ref="another-person", source_version=2)
    report = upload(client, file([moved], snapshot_id="moved")).json()
    assert outcomes(report) == [("rejected", "BINDING_INTEGRITY_ERROR")]
    assert counts(app) == [1, 3, 4] and len(rows(app, SubjectBinding)) == 1
    assert [(e.event_type, e.reason_code) for e in rows(app, ImportEvent)] == [("BindingIntegrityAlert", "BINDING_INTEGRITY_ERROR")]
    with app.state.sessions() as db:
        assert db.scalar(select(func.count()).select_from(AuditLog).where(AuditLog.outcome == "integrity_alert")) == 1


def test_account_binding_after_source_import_enables_candidate_view(env):
    client, app = env
    sid = upload(client, file()).json()["outcomes"][0]["f01"]["subject_id"]
    denied = client.get(f"/subjects/{sid}/twin", params={"purpose": "candidate_self_view"},
                        headers=headers(account="candidate-a", roles="candidate"))
    assert denied.status_code == 404
    bound = client.post("/subjects", headers=headers(), json={
        "source_system": "ATS", "source_person_ref": "synthetic-001", "authenticated_account_id": "candidate-a"})
    assert bound.json() == {"subject_id": sid, "created": False}
    allowed = client.get(f"/subjects/{sid}/twin", params={"purpose": "candidate_self_view"},
                         headers=headers(account="candidate-a", roles="candidate"))
    assert allowed.status_code == 200 and allowed.json()["predicates"]["start_date"]["value"] == "2026-11-01"
    assert counts(app) == [1, 3, 4]


@pytest.mark.parametrize("rights,reason", [("restricted", "RESTRICTED"), ("erased", "ERASED")])
def test_restricted_or_erased_subject_import_is_rejected(env, rights, reason):
    client, app = env
    sid = upload(client, file()).json()["outcomes"][0]["f01"]["subject_id"]
    with app.state.sessions() as db:
        subject = db.get(Subject, sid)
        if rights == "restricted":
            subject.restricted = True
        else:
            app.state.service.crypto_shred_subject(db, sid)
        db.commit()
    report = upload(client, file([record(source_version=2, event_type="offer_updated")], snapshot_id="rights")).json()
    assert outcomes(report) == [("rejected", reason)] and counts(app) == [1, 3, 4]


def test_role_type_size_and_structure(env):
    client, app = env
    assert client.post("/imports/ATS", content=file(), headers=headers()).status_code == 403
    assert client.post("/imports/ATS", content=file(), headers=headers(roles="data_administrator,candidate")).status_code == 403
    assert client.post("/imports/ATS", content=file(), headers=headers(roles="data_administrator")).status_code == 415
    assert upload(client, b"x" * 262145).status_code == 413
    for broken in (b"{}\nnot-json\n", b"[]\n", b'{"a":1,"a":2}\n', b"\xff\xfe\n", b""):
        response = upload(client, broken)
        assert response.status_code in (413, 422) and response.json()["detail"] in ("FILE_STRUCTURE_INVALID", "FILE_SIZE_INVALID", "SOURCE_NOT_REGISTERED")
    assert counts(app) == [0, 0, 0]


def test_freshness_stale_and_duplicate_does_not_refresh(env):
    client, _ = env
    old = (datetime.now(timezone.utc) - timedelta(days=8)).isoformat()
    raw = file(generated_at=old)
    assert upload(client, raw).status_code == 200
    assert freshness(client)["state"] == "stale"
    assert upload(client, raw).json()["duplicate_file"]
    assert freshness(client)["state"] == "stale" and freshness(client)["task_completion"] == "unknown"


def test_restart_reuses_completed_run(env):
    client, app = env
    raw = file()
    first = upload(client, raw).json()
    restarted = create_app(app.state.engine.url.render_as_string(hide_password=False), str(app.state.service.evidence.root))
    with TestClient(restarted) as fresh:
        result = upload(fresh, raw).json()
        assert result["duplicate_file"] and result["outcomes"] == first["outcomes"]
        assert freshness(fresh)["state"] == "fresh"
    assert counts(app) == [1, 3, 4]
