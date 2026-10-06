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


def as_utc(value: datetime) -> datetime:
    # SQLite drops tzinfo; existing naive Part 1 timestamps are interpreted as UTC.
    return value.astimezone(timezone.utc) if value.tzinfo else value.replace(tzinfo=timezone.utc)


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
        # These are CURRENT access conditions, even for a query about the past.
        # Check before selecting payloads, unwrapping a key, or replaying a receipt.
        if subject.restricted:
            self.audit(db, identity, subject_id, purpose, operation, "restricted", correlation)
            db.commit()
            raise HTTPException(403, "subject is restricted")
        if not subject.wrapped_key or not subject.key_reference:
            self.audit(db, identity, subject_id, purpose, operation, "erased", correlation)
            db.commit()
            raise HTTPException(410, "subject payload has been erased")
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
            return self._mutate(db, identity, subject_id, body, correlation)

    def _mutate(self, db, identity, subject_id, body, correlation, commit=True):
        self.authorize(db, identity, body.purpose_id, "mutation", subject_id, correlation)
        subject = self._subject(db, identity, subject_id, body.purpose_id, "mutation", correlation)
        if body.predicate not in PREDICATES:
            return self._reject(db, identity, subject_id, body.purpose_id, correlation, 422, "unknown predicate", commit=commit)
        required = "authoritative" if body.predicate in AUTHORITATIVE else "self_declared"
        if body.claim_class != required:
            return self._reject(db, identity, subject_id, body.purpose_id, correlation, 422, f"predicate requires {required} claim class", commit=commit)
        if body.record_kind != "canonical_claim" or body.claim_class in {"inference", "prediction", "hypothesis"}:
            return self._reject(db, identity, subject_id, body.purpose_id, correlation, 422, "only factual canonical claims are accepted", commit=commit)
        try:
            evidence_content = base64.b64decode(body.evidence.content_base64, validate=True)
        except Exception:
            return self._reject(db, identity, subject_id, body.purpose_id, correlation, 422, "invalid evidence content", commit=commit)
        if sha256(evidence_content) != body.evidence.hash.lower():
            return self._reject(db, identity, subject_id, body.purpose_id, correlation, 422, "evidence hash does not match content", commit=commit)

        request_data = body.model_dump(mode="json", exclude={"evidence": {"content_base64"}})
        request_data["evidence_content_hash"] = sha256(evidence_content)
        request_hash = sha256(canonical(request_data))
        receipt = MutationReceipt(tenant_id=identity.tenant_id, idempotency_key=body.idempotency_key,
                                  request_hash=request_hash)
        db.add(receipt)
        try:
            db.flush()
        except IntegrityError:
            if not commit:
                raise
            db.rollback()
            existing = db.scalar(select(MutationReceipt).where(
                MutationReceipt.tenant_id == identity.tenant_id,
                MutationReceipt.idempotency_key == body.idempotency_key))
            if existing and existing.request_hash == request_hash:
                self.audit(db, identity, subject_id, body.purpose_id, "claim_mutation", "replayed", correlation)
                db.commit() if commit else db.flush()
                return existing.response_json
            self.audit(db, identity, subject_id, body.purpose_id, "claim_mutation", "idempotency_conflict", correlation)
            db.commit() if commit else db.flush()
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
            purpose_ids=[body.purpose_id], valid_from=as_utc(body.valid_from),
            valid_to=as_utc(body.valid_to) if body.valid_to else None,
            observed_at=as_utc(body.observed_at), retention_rule=body.retention_rule,
            confidence_band=body.confidence_band, event_sequence=seq, record_hash=record_hash)
        db.add(claim); db.flush()
        db.add(EventLedger(tenant_id=identity.tenant_id, subject_id=subject.id, claim_id=claim.id,
            sequence=seq, ciphertext=ciphertext, metadata_json=metadata, previous_hash=previous, record_hash=record_hash))
        result = {"claim_id": claim.id, "subject_id": subject.id, "status": status,
                  "event_sequence": seq, "record_hash": record_hash}
        receipt.claim_id, receipt.response_json = claim.id, result
        self.audit(db, identity, subject.id, body.purpose_id, "claim_mutation", "accepted", correlation)
        db.commit() if commit else db.flush()
        return result


    def _reject(self, db, identity, subject, purpose, correlation, code, detail, commit=True):
        self.audit(db, identity, subject, purpose, "claim_mutation", "rejected", correlation)
        if commit:
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

    def historical_twin(self, identity, subject_id, purpose, valid_at, system_at, correlation):
        """Reconstruct from retained claims, never from their mutable current status."""
        with self.sessions() as db:
            self.authorize(db, identity, purpose, "read", subject_id, correlation)
            if purpose != "audit_reconstruction":
                self.audit(db, identity, subject_id, purpose, "twin_reconstruction", "denied", correlation)
                db.commit()
                raise HTTPException(403, "historical reads require audit_reconstruction")
            subject = self._subject(db, identity, subject_id, purpose, "twin_reconstruction", correlation)
            valid_at, system_at = as_utc(valid_at), as_utc(system_at)
            claims = list(db.scalars(select(Claim).where(
                Claim.subject_id == subject.id, Claim.tenant_id == identity.tenant_id,
                Claim.ingested_at <= system_at, Claim.valid_from <= valid_at,
                (Claim.valid_to.is_(None) | (Claim.valid_to > valid_at))
            ).order_by(Claim.event_sequence, Claim.id)))
            key = self.keys.unwrap(subject.id, subject.wrapped_key, subject.key_reference)
            result = {}
            for predicate in PREDICATES:
                candidates = [c for c in claims if c.predicate == predicate]
                if not candidates:
                    result[predicate] = {"state": "unknown", "reason": "no_claim",
                                         "conflict_state": "none", "claims": []}
                    continue
                # A version only supersedes the same source within its validity
                # interval. Later knowledge must not affect an earlier cutoff.
                versions = {}
                for claim in candidates:
                    versions[claim.source_system] = max(versions.get(claim.source_system, -1), claim.source_version)
                candidates = [c for c in candidates if c.source_version == versions[c.source_system]]
                values, provenance = [], []
                for claim in candidates:
                    value = json.loads(decrypt(key, claim.value_ciphertext, f"{subject.id}:{predicate}".encode()))
                    values.append(canonical(value))
                    provenance.append({
                        "claim_id": claim.id, "value": value,
                        "source": claim.source_system, "source_record_id": claim.source_record_id,
                        "source_version": claim.source_version, "authority": claim.source_authority,
                        "evidence_id": claim.evidence_id, "evidence_uri": claim.evidence_uri,
                        "evidence_hash": claim.evidence_hash, "event_sequence": claim.event_sequence,
                        "record_hash": claim.record_hash, "purpose_ids": claim.purpose_ids,
                        "valid_from": as_utc(claim.valid_from).isoformat(),
                        "valid_to": as_utc(claim.valid_to).isoformat() if claim.valid_to else None,
                        "observed_at": as_utc(claim.observed_at).isoformat(),
                        "ingested_at": as_utc(claim.ingested_at).isoformat(),
                        "confidence": claim.confidence_band,
                    })
                if len(set(values)) > 1:
                    result[predicate] = {"state": "unknown", "reason": "contested",
                                         "conflict_state": "unresolved", "claims": provenance}
                else:
                    result[predicate] = {"state": "known", "value": provenance[0]["value"],
                                         "conflict_state": "none", "claims": provenance}
            self.audit(db, identity, subject.id, purpose, "twin_reconstruction", "allowed", correlation)
            db.commit()
            return {"subject_id": subject.id, "valid_at": valid_at.isoformat(),
                    "system_at": system_at.isoformat(), "predicates": result}

    def verify_ledger(self, db, subject_id):
        previous = "0" * 64
        for event in db.scalars(select(EventLedger).where(EventLedger.subject_id == subject_id).order_by(EventLedger.sequence)):
            if event.previous_hash != previous or sha256(event.ciphertext + canonical(event.metadata_json) + previous.encode()) != event.record_hash:
                return False
            previous = event.record_hash
        return True


    def import_offer(self, identity, record, record_key, correlation):
        """F01 atomic record boundary; adapter never owns canonical credentials.

        Resolve/create the binding and commit all mapped claims in one transaction.
        Called only after the controlled adapter has validated the entire record.
        """
        from .schemas import ClaimMutation
        if record.tenant_id != identity.tenant_id:
            raise HTTPException(422, "WRONG_TENANT")
        with self.sessions() as db:
            self.authorize(db, identity, "source_sync", "mutation", None, correlation)
            binding = db.scalar(select(SubjectBinding).where(
                SubjectBinding.tenant_id == identity.tenant_id,
                SubjectBinding.source_system == 'ATS',
                SubjectBinding.source_person_ref == record.source_person_ref))
            if binding:
                if binding.authenticated_account_id != record.authenticated_account_id:
                    raise HTTPException(422, 'SUBJECT_BINDING_MISMATCH')
                subject = db.scalar(select(Subject).where(Subject.id == binding.subject_id).with_for_update())
                self._subject(db, identity, subject.id, 'source_sync', 'mutation', correlation)
            else:
                if record.event_type == 'offer_updated':
                    raise HTTPException(422, 'UNBOUND_SUBJECT')
                subject = Subject(tenant_id=identity.tenant_id)
                db.add(subject); db.flush()
                subject.wrapped_key, subject.key_reference = self.keys.wrap(subject.id, os.urandom(32))
                db.add(SubjectBinding(subject_id=subject.id, tenant_id=identity.tenant_id,
                    source_system='ATS', source_person_ref=record.source_person_ref,
                    authenticated_account_id=record.authenticated_account_id))
            # Prevent an offer identity from being silently moved to another person.
            other = db.scalar(select(Claim.id).where(Claim.tenant_id == identity.tenant_id,
                Claim.source_system == 'ATS', Claim.source_record_id == record.source_record_id,
                Claim.subject_id != subject.id))
            if other:
                raise HTTPException(422, 'SOURCE_RECORD_BINDING_MISMATCH')
            batch_key = 'f08-record:' + record_key
            receipt = db.scalar(select(MutationReceipt).where(
                MutationReceipt.tenant_id == identity.tenant_id, MutationReceipt.idempotency_key == batch_key))
            if receipt:
                return {**receipt.response_json, 'duplicate': True}
            # Evidence is the exact canonical subject record; no shared plaintext
            # file is retained. The same bytes/key can serve all three claims.
            content = canonical(record.model_dump(mode='json'))
            results = []
            for predicate, value in [('offer_status', record.offer_status),
                                     ('offered_role', record.role_ref),
                                     ('start_date', record.start_date.isoformat())]:
                evidence_id = sha256((record_key + predicate).encode())[:36]
                body = ClaimMutation(idempotency_key=batch_key + ':' + predicate,
                    predicate=predicate, value=value, claim_class='authoritative', record_kind='canonical_claim',
                    source={'system':'ATS', 'record_id':record.source_record_id, 'authority':'authoritative',
                            'version':record.source_version},
                    evidence={'evidence_id':evidence_id, 'hash':sha256(content),
                              'content_base64':base64.b64encode(content).decode()},
                    purpose_id='source_sync', valid_from=record.effective_from,
                    observed_at=record.source_updated_at, retention_rule='preboarding_source_evidence',
                    confidence_band='confirmed')
                results.append(self._mutate(db, identity, subject.id, body, correlation, commit=False))
            result = {'subject_id':subject.id, 'claims':results, 'duplicate':False}
            db.add(MutationReceipt(tenant_id=identity.tenant_id, idempotency_key=batch_key,
                                   request_hash=record_key, response_json=result))
            db.commit()
            return result
