import base64
import hashlib
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select
from app.main import create_app
from app.models import AuditLog, Claim, EventLedger, Subject, SubjectBinding
from app.security import decrypt


@pytest.fixture()
def env(tmp_path):
    app = create_app(f"sqlite:///{tmp_path}/edt.db", str(tmp_path / "evidence"))
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
        assert db.scalar(select(func.count()).select_from(EventLedger)) == 1
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
        assert db.scalar(select(func.count()).select_from(EventLedger)) == 1


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
        assert db.scalar(select(func.count()).select_from(EventLedger)) == 2
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
