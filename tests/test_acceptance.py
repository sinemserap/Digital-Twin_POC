import base64
import hashlib
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select
from app.main import create_app
from app.models import AuditLog, Claim, EventLedger, Subject, SubjectBinding
from app.security import decrypt


@pytest.fixture()
def env(tmp_path, request):
    if request.config.getoption("--postgres-url"):
        database_url = request.getfixturevalue("postgres_database")
    else:
        database_url = f"sqlite:///{tmp_path}/edt.db"
    app = create_app(database_url, str(tmp_path / "evidence"))
    with TestClient(app) as client:
        yield client, app


def headers(tenant="tenant-a", account="sync", roles="source_service"):
    return {"X-Tenant-ID": tenant, "X-Account-ID": account, "X-Roles": roles, "X-Correlation-ID": "test-request"}


def import_subject(client, ref="candidate-001", account="candidate-a", tenant="tenant-a"):
    return client.post("/subjects", headers=headers(tenant=tenant), json={
        "source_system": "ATS", "source_person_ref": ref, "authenticated_account_id": account
    })


def mutation(value="2026-11-01", version=1, idem="mutation-1", source="ATS", predicate="start_date",
             claim_class="authoritative", purpose="source_sync"):
    evidence = f"synthetic {source} record {value} v{version}".encode()
    return {
        "idempotency_key": idem, "predicate": predicate, "value": value,
        "claim_class": claim_class, "record_kind": "canonical_claim",
        "source": {"system": source, "record_id": "record-1", "authority": "authoritative", "version": version},
        "evidence": {"evidence_id": f"ev-{idem}", "hash": hashlib.sha256(evidence).hexdigest(),
                     "content_base64": base64.b64encode(evidence).decode()},
        "purpose_id": purpose, "valid_from": "2026-01-01T00:00:00Z", "valid_to": None,
        "observed_at": "2026-01-01T00:00:00Z", "retention_rule": "poc-30-days", "confidence_band": "confirmed"
    }


def test_subject_deduplication_and_tenant_boundary(env):
    client, app = env
    first = import_subject(client); second = import_subject(client); third = import_subject(client)
    assert first.status_code == 201 and first.json()["created"] is True
    assert first.json()["subject_id"] == second.json()["subject_id"] == third.json()["subject_id"]
    with app.state.sessions() as db:
        assert db.scalar(select(func.count()).select_from(Subject)) == 1
        assert db.scalar(select(func.count()).select_from(SubjectBinding)) == 1
    sid = first.json()["subject_id"]
    response = client.get(f"/subjects/{sid}/twin?purpose=candidate_self_view",
                          headers=headers("tenant-b", "candidate-a", "candidate"))
    assert response.status_code == 404


def test_idempotency_conflict_unknowns_and_audit(env):
    client, app = env; sid = import_subject(client).json()["subject_id"]
    first = client.post(f"/subjects/{sid}/claims", headers=headers(), json=mutation())
    replay = client.post(f"/subjects/{sid}/claims", headers=headers(), json=mutation())
    assert first.status_code == 201 and replay.json() == first.json()
    changed = mutation(value="2026-11-08")
    assert client.post(f"/subjects/{sid}/claims", headers=headers(), json=changed).status_code == 409
    twin = client.get(f"/subjects/{sid}/twin?purpose=candidate_self_view",
                      headers=headers(account="candidate-a", roles="candidate"))
    assert twin.status_code == 200
    assert twin.json()["predicates"]["start_date"]["value"] == "2026-11-01"
    assert twin.json()["predicates"]["manager_or_sponsor"] == {"state": "unknown", "reason": "no_claim"}
    assert len(twin.json()["predicates"]) == 11
    with app.state.sessions() as db:
        # EvidenceAcquired + ClaimAccepted for the one accepted claim; the replay adds nothing.
        assert db.scalar(select(func.count()).select_from(EventLedger)) == 2
        operations = set(db.scalars(select(AuditLog.operation)))
        assert {"subject_import", "claim_mutation", "twin_read"} <= operations


def test_concurrent_identical_mutation_creates_one_event(env):
    client, app = env; sid = import_subject(client).json()["subject_id"]
    def send(_):
        return client.post(f"/subjects/{sid}/claims", headers=headers(), json=mutation(idem="parallel")).status_code
    with ThreadPoolExecutor(max_workers=2) as pool:
        statuses = list(pool.map(send, range(2)))
    assert statuses == [201, 201]
    with app.state.sessions() as db:
        assert db.scalar(select(func.count()).select_from(EventLedger)) == 2


@pytest.mark.parametrize("change,expected", [
    ({"predicate": "salary"}, "unknown predicate"),
    ({"claim_class": "self_declared"}, "requires authoritative"),
    ({"claim_class": "prediction"}, "requires authoritative"),
])
def test_invalid_predicate_and_claim_classes(env, change, expected):
    client, _ = env; sid = import_subject(client).json()["subject_id"]
    body = mutation(); body.update(change)
    response = client.post(f"/subjects/{sid}/claims", headers=headers(), json=body)
    assert response.status_code == 422 and expected in response.json()["detail"]


def test_required_evidence_retention_and_prohibited_purpose(env):
    client, _ = env; sid = import_subject(client).json()["subject_id"]
    for field in ("hash",):
        body = mutation(); body["evidence"].pop(field)
        assert client.post(f"/subjects/{sid}/claims", headers=headers(), json=body).status_code == 422
    body = mutation(); body.pop("retention_rule")
    assert client.post(f"/subjects/{sid}/claims", headers=headers(), json=body).status_code == 422
    denied = client.get(f"/subjects/{sid}/twin?purpose=performance_evaluation",
                        headers=headers(account="candidate-a", roles="candidate"))
    assert denied.status_code == 403


def test_candidate_cannot_read_other_candidate(env):
    client, _ = env
    a = import_subject(client, "a", "candidate-a").json()["subject_id"]
    b = import_subject(client, "b", "candidate-b").json()["subject_id"]
    assert client.get(f"/subjects/{a}/twin?purpose=candidate_self_view", headers=headers(account="candidate-a", roles="candidate")).status_code == 200
    assert client.get(f"/subjects/{b}/twin?purpose=candidate_self_view", headers=headers(account="candidate-a", roles="candidate")).status_code == 404
    assert client.post(f"/subjects/{b}/claims", headers=headers(account="candidate-a", roles="candidate"), json=mutation()).status_code == 403


def test_supersession_history_and_multisource_contest(env):
    client, app = env; sid = import_subject(client).json()["subject_id"]
    assert client.post(f"/subjects/{sid}/claims", headers=headers(), json=mutation()).status_code == 201
    newer = mutation("2026-11-08", 2, "mutation-2")
    assert client.post(f"/subjects/{sid}/claims", headers=headers(), json=newer).json()["status"] == "current"
    with app.state.sessions() as db:
        claims = list(db.scalars(select(Claim).order_by(Claim.source_version)))
        assert [c.status for c in claims] == ["superseded", "current"]
        assert [e.event_type for e in db.scalars(select(EventLedger).order_by(EventLedger.sequence))] == [
            "EvidenceAcquired", "ClaimAccepted", "EvidenceAcquired", "ClaimAccepted", "ClaimSuperseded"]
    conflict = mutation("2026-11-15", 1, "mutation-3", "HR")
    assert client.post(f"/subjects/{sid}/claims", headers=headers(), json=conflict).json()["status"] == "contested"
    twin = client.get(f"/subjects/{sid}/twin?purpose=preboarding_support", headers=headers(account="support", roles="support"))
    assert twin.json()["predicates"]["start_date"] == {"state": "unknown", "reason": "contested"}


def test_evidence_encryption_verification_crypto_shred_and_ledger(env):
    client, app = env; sid = import_subject(client).json()["subject_id"]
    body = mutation(); client.post(f"/subjects/{sid}/claims", headers=headers(), json=body)
    evidence = client.get(f"/subjects/{sid}/evidence/ev-mutation-1?purpose=candidate_self_view",
                          headers=headers(account="candidate-a", roles="candidate"))
    assert evidence.status_code == 200 and evidence.content.startswith(b"synthetic ATS")
    with app.state.sessions() as db:
        subject = db.get(Subject, sid); claim = db.scalar(select(Claim).where(Claim.subject_id == sid))
        key = app.state.service.keys.unwrap(sid, subject.wrapped_key, subject.key_reference)
        assert b"2026-11-01" not in claim.value_ciphertext
        assert b"2026-11-01" in decrypt(key, claim.value_ciphertext, f"{sid}:start_date".encode())
        assert app.state.service.verify_ledger(db, sid)
        subject.wrapped_key = None; subject.key_reference = None; db.commit()
        assert app.state.service.verify_ledger(db, sid)


@pytest.fixture()
def acceptance_clock(monkeypatch):
    """Freeze the server's timestamp source, without editing accepted records."""
    current = datetime(2026, 10, 1, tzinfo=timezone.utc)

    class Clock(datetime):
        @classmethod
        def now(cls, tz=None):
            return current.astimezone(tz) if tz else current.replace(tzinfo=None)

    def set_time(value):
        nonlocal current
        current = datetime.fromisoformat(value.replace("Z", "+00:00"))

    monkeypatch.setattr("app.models.datetime", Clock)
    return set_time


def history(client, sid, valid_at="2026-10-01T00:00:00Z", system_at="2026-10-10T00:00:00Z",
            purpose="audit_reconstruction", identity_headers=None):
    return client.get(f"/subjects/{sid}/twin/history", params={
        "purpose": purpose, "valid_at": valid_at, "system_at": system_at,
    }, headers=identity_headers or headers(account="auditor", roles="auditor"))


def accept(client, sid, body):
    response = client.post(f"/subjects/{sid}/claims", headers=headers(), json=body)
    assert response.status_code == 201, response.text
    return response.json()


def test_bitemporal_late_correction_and_current_contract(env, acceptance_clock):
    client, app = env
    sid = import_subject(client).json()["subject_id"]
    first = accept(client, sid, mutation())
    acceptance_clock("2026-10-05T00:00:00Z")
    correction = mutation("2026-11-08", 2, "late-correction")
    correction["valid_from"] = "2026-09-15T00:00:00Z"
    # Source observation and client-supplied extras must not backdate knowledge.
    correction["observed_at"] = "2026-09-14T00:00:00Z"
    correction["ingested_at"] = "2026-09-14T00:00:00Z"
    second = accept(client, sid, correction)
    before = history(client, sid, system_at="2026-10-04T23:59:59.999999Z").json()
    at = history(client, sid, system_at="2026-10-05T00:00:00Z").json()
    assert before["predicates"]["start_date"]["value"] == "2026-11-01"
    corrected = at["predicates"]["start_date"]
    assert corrected["value"] == "2026-11-08" and corrected["conflict_state"] == "none"
    proof = corrected["claims"][0]
    assert proof["claim_id"] == second["claim_id"]
    assert proof["evidence_id"] == "ev-late-correction"
    assert proof["evidence_hash"] == correction["evidence"]["hash"]
    assert proof["evidence_uri"].endswith("/ev-late-correction")
    assert proof["record_hash"] == second["record_hash"] and proof["event_sequence"] == 4
    assert proof["ingested_at"] == "2026-10-05T00:00:00+00:00"
    # With later knowledge, the old assertion still covers the earlier valid time.
    earlier_valid = history(client, sid, valid_at="2026-09-14T23:59:59Z").json()
    assert earlier_valid["predicates"]["start_date"]["claims"][0]["claim_id"] == first["claim_id"]
    at_valid_start = history(client, sid, valid_at="2026-09-15T00:00:00Z").json()
    assert at_valid_start["predicates"]["start_date"]["value"] == "2026-11-08"
    unknown = history(client, sid, system_at="2026-09-30T23:59:59Z").json()
    assert unknown["predicates"]["start_date"] == {
        "state": "unknown", "reason": "no_claim", "conflict_state": "none", "claims": []}
    # Historical reads do not rewrite today's projection or the original ledger.
    current = client.get(f"/subjects/{sid}/twin?purpose=preboarding_support",
                         headers=headers(account="support", roles="support")).json()
    assert set(current) == {"subject_id", "predicates"}
    assert current["predicates"]["start_date"]["value"] == "2026-11-08"
    assert current["predicates"]["manager_or_sponsor"] == {"state": "unknown", "reason": "no_claim"}
    assert accept(client, sid, correction) == second
    with app.state.sessions() as db:
        assert db.scalar(select(func.count()).select_from(EventLedger)) == 5
        assert app.state.service.verify_ledger(db, sid)
        assert [c.status for c in db.scalars(select(Claim).order_by(Claim.event_sequence))] == ["superseded", "current"]


def test_bitemporal_valid_interval_boundaries_and_timezone(env, acceptance_clock):
    client, _ = env
    sid = import_subject(client).json()["subject_id"]
    body = mutation()
    body.update(valid_from="2026-09-01T02:00:00+02:00", valid_to="2026-10-01T02:00:00+02:00")
    accept(client, sid, body)
    for instant, state in [
        ("2026-08-31T23:59:59.999999Z", "unknown"),
        ("2026-09-01T00:00:00Z", "known"),
        ("2026-09-30T23:59:59.999999Z", "known"),
        ("2026-10-01T00:00:00Z", "unknown"),
    ]:
        assert history(client, sid, valid_at=instant).json()["predicates"]["start_date"]["state"] == state
    utc = history(client, sid, valid_at="2026-09-01T00:00:00Z", system_at="2026-10-01T00:00:00Z")
    offset = history(client, sid, valid_at="2026-09-01T02:00:00+02:00", system_at="2026-10-01T02:00:00+02:00")
    assert utc.json() == offset.json()


@pytest.mark.parametrize("conflicting_source", ["ATS", "HR"])
def test_bitemporal_conflicts_retain_both_evidence_and_do_not_leak_future_state(env, acceptance_clock, conflicting_source):
    client, app = env
    sid = import_subject(client).json()["subject_id"]
    first = accept(client, sid, mutation())
    acceptance_clock("2026-10-03T00:00:00Z")
    conflict = mutation("2026-11-15", 1, "conflict", conflicting_source)
    second = accept(client, sid, conflict)
    assert second["status"] == "contested"
    past = history(client, sid, system_at="2026-10-02T00:00:00Z").json()["predicates"]["start_date"]
    assert past["state"] == "known" and past["value"] == "2026-11-01"
    disputed = history(client, sid, system_at="2026-10-03T00:00:00Z").json()["predicates"]["start_date"]
    assert disputed["state"] == "unknown" and disputed["reason"] == "contested"
    assert disputed["conflict_state"] == "unresolved" and "value" not in disputed
    assert {c["claim_id"] for c in disputed["claims"]} == {first["claim_id"], second["claim_id"]}
    assert {c["evidence_id"] for c in disputed["claims"]} == {"ev-mutation-1", "ev-conflict"}
    assert {c["value"] for c in disputed["claims"]} == {"2026-11-01", "2026-11-15"}
    for claim in disputed["claims"]:
        evidence = client.get(f"/subjects/{sid}/evidence/{claim['evidence_id']}",
                              params={"purpose": "audit_reconstruction"}, headers=headers(roles="auditor"))
        assert evidence.status_code == 200
        assert hashlib.sha256(evidence.content).hexdigest() == claim["evidence_hash"]
    # A later source correction can remove a disagreement at the new cutoff;
    # it must leave the earlier dispute and both evidence references reconstructible.
    acceptance_clock("2026-10-05T00:00:00Z")
    accept(client, sid, mutation("2026-11-01", 2, "agreement", conflicting_source))
    assert history(client, sid).json()["predicates"]["start_date"]["conflict_state"] == "none"
    assert history(client, sid, system_at="2026-10-03T00:00:00Z").json()["predicates"]["start_date"] == disputed
    with app.state.sessions() as db:
        # Conflict: ClaimProposed plus ClaimContested for both claims. Agreement supersedes
        # both same-source ATS claims, or only the HR claim when HR was the conflicting source.
        events = [e.event_type for e in db.scalars(select(EventLedger).order_by(EventLedger.sequence))]
        assert events[2:6] == ["EvidenceAcquired", "ClaimProposed", "ClaimContested", "ClaimContested"]
        assert events.count("ClaimSuperseded") == (2 if conflicting_source == "ATS" else 1)
        assert len(events) == (10 if conflicting_source == "ATS" else 9)
        assert app.state.service.verify_ledger(db, sid)


def test_bitemporal_late_older_version_only_fills_uncovered_valid_time(env, acceptance_clock):
    client, _ = env
    sid = import_subject(client).json()["subject_id"]
    newer = mutation("2026-11-08", 2, "newer")
    newer["valid_from"] = "2026-09-15T00:00:00Z"
    accept(client, sid, newer)
    acceptance_clock("2026-10-03T00:00:00Z")
    accept(client, sid, mutation())
    assert history(client, sid).json()["predicates"]["start_date"]["value"] == "2026-11-08"
    assert history(client, sid, valid_at="2026-09-01T00:00:00Z").json()["predicates"]["start_date"]["value"] == "2026-11-01"
    before_import = history(client, sid, valid_at="2026-09-01T00:00:00Z", system_at="2026-10-02T00:00:00Z")
    assert before_import.json()["predicates"]["start_date"]["state"] == "unknown"


@pytest.mark.parametrize("purpose,tenant,account,roles,status", [
    ("audit_reconstruction", "tenant-a", "auditor", "auditor", 200),
    ("audit_reconstruction", "tenant-b", "auditor", "auditor", 404),
    ("audit_reconstruction", "tenant-a", "candidate-a", "candidate", 403),
    ("audit_reconstruction", "tenant-a", "candidate-b", "candidate,auditor", 404),
    ("candidate_self_view", "tenant-a", "candidate-a", "candidate", 403),
    ("preboarding_support", "tenant-a", "support", "support", 403),
    ("performance_evaluation", "tenant-a", "auditor", "auditor", 403),
])
def test_history_authorization_and_audit(env, acceptance_clock, purpose, tenant, account, roles, status):
    client, app = env
    sid = import_subject(client).json()["subject_id"]
    accept(client, sid, mutation())
    response = history(client, sid, purpose=purpose, identity_headers=headers(tenant, account, roles))
    assert response.status_code == status
    if status != 200:
        assert "2026-11-01" not in response.text and "ev-mutation-1" not in response.text
    with app.state.sessions() as db:
        logs = list(db.scalars(select(AuditLog).where(AuditLog.purpose == purpose, AuditLog.actor == account)))
        assert any(log.outcome == ("allowed" if status == 200 else "denied") and
                   log.correlation_id == "test-request" for log in logs)
        if status == 200:
            assert any(log.operation == "twin_reconstruction" for log in logs)


@pytest.mark.parametrize("field,value", [("valid_at", None), ("system_at", None),
    ("valid_at", "2026-10-01T00:00:00"), ("system_at", "2026-10-01T00:00:00"),
    ("valid_at", "not-a-time"), ("system_at", "not-a-time")])
def test_history_requires_two_timezone_aware_timestamps(env, field, value):
    client, _ = env
    sid = import_subject(client).json()["subject_id"]
    params = {"purpose": "audit_reconstruction", "valid_at": "2026-10-01T00:00:00Z", "system_at": "2026-10-10T00:00:00Z"}
    if value is None:
        params.pop(field)
    else:
        params[field] = value
    response = client.get(f"/subjects/{sid}/twin/history", params=params, headers=headers(roles="auditor"))
    assert response.status_code == 422


@pytest.mark.parametrize("rights_state,status", [("restricted", 403), ("erased", 410)])
def test_current_rights_precede_history_payload_selection_and_survive_restart(env, acceptance_clock, monkeypatch, rights_state, status):
    client, app = env
    sid = import_subject(client).json()["subject_id"]
    body = mutation()
    accept(client, sid, body)
    before = history(client, sid)
    assert before.status_code == 200 and before.json()["predicates"]["start_date"]["value"] == "2026-11-01"
    with app.state.sessions() as db:
        ledger_before = [(e.id, e.ciphertext, e.record_hash) for e in db.scalars(select(EventLedger))]
        subject = db.get(Subject, sid)
        if rights_state == "restricted":
            subject.restricted = True
        else:
            subject.wrapped_key = subject.key_reference = None
        db.commit()
        # All encrypted claim/evidence/ledger data remain, as in a replay/rebuild.
        assert db.scalar(select(func.count()).select_from(Claim)) == 1
        assert app.state.service.verify_ledger(db, sid)

    def forbidden(*args, **kwargs):
        pytest.fail("restricted/erased payloads must not be selected, decrypted, or read")

    def reject_payload_selects(conn, cursor, statement, parameters, context, executemany):
        if statement.lstrip().upper().startswith("SELECT"):
            assert "FROM claim" not in statement and "FROM event_ledger" not in statement

    from sqlalchemy import event
    event.listen(app.state.engine, "before_cursor_execute", reject_payload_selects)
    monkeypatch.setattr(app.state.service.keys, "unwrap", forbidden)
    monkeypatch.setattr(app.state.service.evidence, "read_verified", forbidden)
    monkeypatch.setattr("app.service.decrypt", forbidden)
    # The past timestamp predates restriction/erasure; current rights still win.
    for response in [
        history(client, sid),
        client.get(f"/subjects/{sid}/twin?purpose=candidate_self_view", headers=headers(account="candidate-a", roles="candidate")),
        client.get(f"/subjects/{sid}/evidence/ev-mutation-1?purpose=audit_reconstruction", headers=headers(roles="auditor")),
        client.post(f"/subjects/{sid}/claims", headers=headers(), json=body),
    ]:
        assert response.status_code == status
        assert "2026-11-01" not in response.text and "ev-mutation-1" not in response.text
    event.remove(app.state.engine, "before_cursor_execute", reject_payload_selects)
    with app.state.sessions() as db:
        assert [(e.id, e.ciphertext, e.record_hash) for e in db.scalars(select(EventLedger))] == ledger_before
        assert app.state.service.verify_ledger(db, sid)
        assert db.scalar(select(AuditLog.id).where(AuditLog.operation == "twin_reconstruction", AuditLog.outcome == rights_state))
    # A fresh service has no allowed-read cache and cannot reconstruct from the
    # retained ciphertext without the subject's current key/access state.
    restarted = create_app(app.state.engine.url.render_as_string(hide_password=False),
                           str(app.state.service.evidence.root))
    monkeypatch.setattr(restarted.state.service.keys, "unwrap", forbidden)
    with TestClient(restarted) as fresh_client:
        assert history(fresh_client, sid).status_code == status
