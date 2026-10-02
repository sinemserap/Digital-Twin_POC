import base64
import json
import os
from datetime import datetime, timezone
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from fastapi import HTTPException
from .constants import ALLOWED_PURPOSES, AUTHORITATIVE, DENIED_PURPOSES, PREDICATES, SELF_DECLARED
from .models import AuditLog, Claim, EventLedger, MutationReceipt, Subject, SubjectBinding
from .security import Identity, decrypt, encrypt, sha256


def canonical(data) -> bytes:
    return json.dumps(data, sort_keys=True, separators=(",", ":"), default=str).encode()


class ClaimService:
    def __init__(self, session_factory, evidence_store, key_protector):
        self.sessions = session_factory
        self.evidence = evidence_store
        self.keys = key_protector

    def audit(self, db, identity, subject, purpose, operation, outcome, correlation):
        db.add(AuditLog(actor=identity.account_id, tenant_id=identity.tenant_id,
                         subject_id=subject, purpose=purpose, operation=operation,
                         outcome=outcome, correlation_id=correlation))

    def authorize(self, db, identity: Identity, purpose: str, operation: str, subject_id: str | None, correlation: str):
        rule = ALLOWED_PURPOSES.get(purpose)
        if purpose in DENIED_PURPOSES or not rule or rule[0] != operation or not (identity.roles & rule[1]):
            self.audit(db, identity, subject_id, purpose, operation, "denied", correlation)
            db.commit()
            raise HTTPException(403, "purpose is not authorized for this identity and endpoint")

    def _subject(self, db, identity, subject_id, purpose, operation, correlation):
        subject = db.scalar(select(Subject).where(Subject.id == subject_id, Subject.tenant_id == identity.tenant_id))
        if not subject:
            self.audit(db, identity, subject_id, purpose, operation, "denied", correlation)
            db.commit()
            raise HTTPException(404, "subject not found")
        if "candidate" in identity.roles:
            owns = db.scalar(select(SubjectBinding.id).where(
                SubjectBinding.subject_id == subject_id,
                SubjectBinding.tenant_id == identity.tenant_id,
                SubjectBinding.authenticated_account_id == identity.account_id))
            if not owns:
                self.audit(db, identity, subject_id, purpose, operation, "denied", correlation)
                db.commit()
                raise HTTPException(404, "subject not found")
        return subject

    def import_subject(self, identity, body, correlation):
        with self.sessions() as db:
            self.authorize(db, identity, "source_sync", "mutation", None, correlation)
            binding = db.scalar(select(SubjectBinding).where(
                SubjectBinding.tenant_id == identity.tenant_id,
                SubjectBinding.source_system == body.source_system,
                SubjectBinding.source_person_ref == body.source_person_ref))
            if binding:
                self.audit(db, identity, binding.subject_id, "source_sync", "subject_import", "replayed", correlation)
                db.commit()
                return {"subject_id": binding.subject_id, "created": False}
            subject = Subject(tenant_id=identity.tenant_id)
            db.add(subject); db.flush()
            key = os.urandom(32)
            subject.wrapped_key, subject.key_reference = self.keys.wrap(subject.id, key)
            binding = SubjectBinding(subject_id=subject.id, tenant_id=identity.tenant_id,
                authenticated_account_id=body.authenticated_account_id,
                source_system=body.source_system, source_person_ref=body.source_person_ref)
            db.add(binding)
            self.audit(db, identity, subject.id, "source_sync", "subject_import", "accepted", correlation)
            try:
                db.commit()
            except IntegrityError:
                db.rollback()
                binding = db.scalar(select(SubjectBinding).where(
                    SubjectBinding.tenant_id == identity.tenant_id,
                    SubjectBinding.source_system == body.source_system,
                    SubjectBinding.source_person_ref == body.source_person_ref))
                return {"subject_id": binding.subject_id, "created": False}
            return {"subject_id": subject.id, "created": True}

    def mutate(self, identity, subject_id, body, correlation):
        with self.sessions() as db:
            self.authorize(db, identity, body.purpose_id, "mutation", subject_id, correlation)
            subject = self._subject(db, identity, subject_id, body.purpose_id, "mutation", correlation)
            if body.predicate not in PREDICATES:
                return self._reject(db, identity, subject_id, body.purpose_id, correlation, 422, "unknown predicate")
            required = "authoritative" if body.predicate in AUTHORITATIVE else "self_declared"
            if body.claim_class != required:
                return self._reject(db, identity, subject_id, body.purpose_id, correlation, 422, f"predicate requires {required} claim class")
            if body.record_kind != "canonical_claim" or body.claim_class in {"inference", "prediction", "hypothesis"}:
                return self._reject(db, identity, subject_id, body.purpose_id, correlation, 422, "only factual canonical claims are accepted")
            try:
                evidence_content = base64.b64decode(body.evidence.content_base64, validate=True)
            except Exception:
                return self._reject(db, identity, subject_id, body.purpose_id, correlation, 422, "invalid evidence content")
            if sha256(evidence_content) != body.evidence.hash.lower():
                return self._reject(db, identity, subject_id, body.purpose_id, correlation, 422, "evidence hash does not match content")

            request_data = body.model_dump(mode="json", exclude={"evidence": {"content_base64"}})
            request_data["evidence_content_hash"] = sha256(evidence_content)
            request_hash = sha256(canonical(request_data))
            receipt = MutationReceipt(tenant_id=identity.tenant_id, idempotency_key=body.idempotency_key,
                                      request_hash=request_hash)
            db.add(receipt)
            try:
                db.flush()
            except IntegrityError:
                db.rollback()
                existing = db.scalar(select(MutationReceipt).where(
                    MutationReceipt.tenant_id == identity.tenant_id,
                    MutationReceipt.idempotency_key == body.idempotency_key))
                if existing and existing.request_hash == request_hash:
                    self.audit(db, identity, subject_id, body.purpose_id, "claim_mutation", "replayed", correlation)
                    db.commit()
                    return existing.response_json
                self.audit(db, identity, subject_id, body.purpose_id, "claim_mutation", "idempotency_conflict", correlation)
                db.commit()
                raise HTTPException(409, "idempotency key was already used with different content")

            key = self.keys.unwrap(subject.id, subject.wrapped_key, subject.key_reference)
            value_bytes = canonical(body.value)
            ciphertext = encrypt(key, value_bytes, f"{subject.id}:{body.predicate}".encode())
            evidence_uri = self.evidence.put(identity.tenant_id, subject.id, body.evidence.evidence_id, evidence_content, key)
            existing_claims = list(db.scalars(select(Claim).where(
                Claim.subject_id == subject.id, Claim.predicate == body.predicate,
                Claim.status.in_(["current", "contested"]))).all())
            status = "current"
            for old in existing_claims:
                old_value = decrypt(key, old.value_ciphertext, f"{subject.id}:{body.predicate}".encode())
                if old.source_system == body.source.system:
                    if body.source.version > old.source_version:
                        old.status = "superseded"
                    elif body.source.version < old.source_version:
                        status = "historical"
                    elif old_value != value_bytes:
                        old.status = status = "contested"
                    else:
                        status = "historical"
                elif old_value != value_bytes:
                    old.status = status = "contested"
            seq = (db.scalar(select(func.max(EventLedger.sequence)).where(EventLedger.subject_id == subject.id)) or 0) + 1
            previous = db.scalar(select(EventLedger.record_hash).where(EventLedger.subject_id == subject.id).order_by(EventLedger.sequence.desc()).limit(1)) or "0" * 64
            metadata = {"subject_id": subject.id, "tenant_id": identity.tenant_id, "predicate": body.predicate,
                        "claim_class": body.claim_class, "record_kind": body.record_kind, "status": status,
                        "source": body.source.model_dump(), "evidence_id": body.evidence.evidence_id,
                        "evidence_uri": evidence_uri, "evidence_hash": body.evidence.hash.lower(),
                        "purpose_ids": [body.purpose_id], "valid_from": str(body.valid_from), "valid_to": str(body.valid_to),
                        "observed_at": str(body.observed_at), "retention_rule": body.retention_rule,
                        "confidence_band": body.confidence_band, "event_sequence": seq}
            record_hash = sha256(ciphertext + canonical(metadata) + previous.encode())
            claim = Claim(subject_id=subject.id, tenant_id=identity.tenant_id, predicate=body.predicate,
                value_ciphertext=ciphertext, claim_class=body.claim_class, record_kind=body.record_kind, status=status,
                source_system=body.source.system, source_record_id=body.source.record_id,
                source_authority=body.source.authority, source_version=body.source.version,
                evidence_id=body.evidence.evidence_id, evidence_uri=evidence_uri, evidence_hash=body.evidence.hash.lower(),
                purpose_ids=[body.purpose_id], valid_from=body.valid_from, valid_to=body.valid_to,
                observed_at=body.observed_at, retention_rule=body.retention_rule,
                confidence_band=body.confidence_band, event_sequence=seq, record_hash=record_hash)
            db.add(claim); db.flush()
            db.add(EventLedger(tenant_id=identity.tenant_id, subject_id=subject.id, claim_id=claim.id,
                sequence=seq, ciphertext=ciphertext, metadata_json=metadata, previous_hash=previous, record_hash=record_hash))
            result = {"claim_id": claim.id, "subject_id": subject.id, "status": status,
                      "event_sequence": seq, "record_hash": record_hash}
            receipt.claim_id, receipt.response_json = claim.id, result
            self.audit(db, identity, subject.id, body.purpose_id, "claim_mutation", "accepted", correlation)
            db.commit()
            return result

    def _reject(self, db, identity, subject, purpose, correlation, code, detail):
        self.audit(db, identity, subject, purpose, "claim_mutation", "rejected", correlation)
        db.commit()
        raise HTTPException(code, detail)

    def twin(self, identity, subject_id, purpose, correlation):
        with self.sessions() as db:
            self.authorize(db, identity, purpose, "read", subject_id, correlation)
            subject = self._subject(db, identity, subject_id, purpose, "read", correlation)
            key = self.keys.unwrap(subject.id, subject.wrapped_key, subject.key_reference)
            result = {}
            now = datetime.now(timezone.utc)
            for predicate in PREDICATES:
                claims = list(db.scalars(select(Claim).where(
                    Claim.subject_id == subject.id, Claim.predicate == predicate,
                    Claim.status.in_(["current", "contested"]))).all())
                if not claims:
                    result[predicate] = {"state": "unknown", "reason": "no_claim"}
                elif any(c.status == "contested" for c in claims) or len(claims) > 1:
                    result[predicate] = {"state": "unknown", "reason": "contested"}
                else:
                    c = claims[0]
                    valid_to = c.valid_to
                    if valid_to and (valid_to if valid_to.tzinfo else valid_to.replace(tzinfo=timezone.utc)) <= now:
                        result[predicate] = {"state": "unknown", "reason": "expired"}
                        continue
                    value = json.loads(decrypt(key, c.value_ciphertext, f"{subject.id}:{predicate}".encode()))
                    ingested = c.ingested_at if c.ingested_at.tzinfo else c.ingested_at.replace(tzinfo=timezone.utc)
                    result[predicate] = {"value": value, "claim_id": c.id, "source": c.source_system,
                        "authority": c.source_authority, "evidence_id": c.evidence_id, "evidence_uri": c.evidence_uri,
                        "purpose_ids": c.purpose_ids, "valid_from": c.valid_from.isoformat(),
                        "valid_to": c.valid_to.isoformat() if c.valid_to else None,
                        "ingested_at": ingested.isoformat(), "confidence": c.confidence_band,
                        "stale": False, "data_age_seconds": max(0, int((now - ingested).total_seconds()))}
            self.audit(db, identity, subject.id, purpose, "twin_read", "allowed", correlation)
            db.commit()
            return {"subject_id": subject.id, "predicates": result}

    def verify_ledger(self, db, subject_id):
        previous = "0" * 64
        for event in db.scalars(select(EventLedger).where(EventLedger.subject_id == subject_id).order_by(EventLedger.sequence)):
            if event.previous_hash != previous or sha256(event.ciphertext + canonical(event.metadata_json) + previous.encode()) != event.record_hash:
                return False
            previous = event.record_hash
        return True

