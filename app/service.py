import base64
import json
import os
import uuid
from datetime import datetime, timezone
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from fastapi import HTTPException
from .constants import ALLOWED_PURPOSES, AUTHORITATIVE, DENIED_PURPOSES, PREDICATES, SELF_DECLARED
from .models import (AuditLog, Claim, EventLedger, ImportFileEvidence, ImportFileEvidenceSubject,
                     MutationReceipt, Subject, SubjectBinding)
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
                if binding.authenticated_account_id is None:
                    # A controlled import created this binding without an account (F08 schema v1
                    # carries no account field); the first account assertion binds it.
                    binding.authenticated_account_id = body.authenticated_account_id
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

    def _append_event(self, db, tenant_id, subject_id, claim_id, event_type, ciphertext, metadata):
        """Append one hash-chained canonical event (EvidenceAcquired, ClaimProposed,
        ClaimAccepted, ClaimSuperseded, ClaimContested) to the subject's ledger."""
        seq = (db.scalar(select(func.max(EventLedger.sequence)).where(EventLedger.subject_id == subject_id)) or 0) + 1
        previous = db.scalar(select(EventLedger.record_hash).where(EventLedger.subject_id == subject_id)
                             .order_by(EventLedger.sequence.desc()).limit(1)) or "0" * 64
        metadata = {**metadata, "event_type": event_type, "event_sequence": seq}
        record_hash = sha256(ciphertext + canonical(metadata) + previous.encode())
        db.add(EventLedger(tenant_id=tenant_id, subject_id=subject_id, claim_id=claim_id, sequence=seq,
                           event_type=event_type, ciphertext=ciphertext, metadata_json=metadata,
                           previous_hash=previous, record_hash=record_hash))
        db.flush()
        return seq, record_hash

    def _mutate(self, db, identity, subject_id, body, correlation, commit=True, stored_evidence_uri=None,
                emit_evidence_event=True):
        """One claim mutation. stored_evidence_uri lets an atomic record set share one
        per-record evidence snapshot already written under the subject key; the first claim
        of such a set emits the EvidenceAcquired event for the shared snapshot."""
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
        evidence_uri = stored_evidence_uri or self.evidence.put(
            identity.tenant_id, subject.id, body.evidence.evidence_id, evidence_content, key)
        existing_claims = list(db.scalars(select(Claim).where(
            Claim.subject_id == subject.id, Claim.predicate == body.predicate,
            Claim.status.in_(["current", "contested"]))).all())
        status, superseded, contested = "current", [], []
        for old in existing_claims:
            old_value = decrypt(key, old.value_ciphertext, f"{subject.id}:{body.predicate}".encode())
            if old.source_system == body.source.system:
                if body.source.version > old.source_version:
                    old.status = "superseded"; superseded.append(old)
                elif body.source.version < old.source_version:
                    status = "historical"
                elif old_value != value_bytes:
                    old.status = status = "contested"; contested.append(old)
                else:
                    status = "historical"
            elif old_value != value_bytes:
                old.status = status = "contested"; contested.append(old)
        metadata = {"subject_id": subject.id, "tenant_id": identity.tenant_id, "predicate": body.predicate,
                    "claim_class": body.claim_class, "record_kind": body.record_kind, "status": status,
                    "source": body.source.model_dump(), "evidence_id": body.evidence.evidence_id,
                    "evidence_uri": evidence_uri, "evidence_hash": body.evidence.hash.lower(),
                    "purpose_ids": [body.purpose_id], "valid_from": str(body.valid_from), "valid_to": str(body.valid_to),
                    "observed_at": str(body.observed_at), "retention_rule": body.retention_rule,
                    "confidence_band": body.confidence_band}
        claim = Claim(subject_id=subject.id, tenant_id=identity.tenant_id, predicate=body.predicate,
            value_ciphertext=ciphertext, claim_class=body.claim_class, record_kind=body.record_kind, status=status,
            source_system=body.source.system, source_record_id=body.source.record_id,
            source_authority=body.source.authority, source_version=body.source.version,
            evidence_id=body.evidence.evidence_id, evidence_uri=evidence_uri, evidence_hash=body.evidence.hash.lower(),
            purpose_ids=[body.purpose_id], valid_from=as_utc(body.valid_from),
            valid_to=as_utc(body.valid_to) if body.valid_to else None,
            observed_at=as_utc(body.observed_at), retention_rule=body.retention_rule,
            confidence_band=body.confidence_band, event_sequence=0, record_hash="")
        db.add(claim); db.flush()
        # Canonical events (F08 design §1.11 / F01 AC8). Every claim gets exactly one of
        # ClaimProposed (recorded but contested, so not accepted as current) or ClaimAccepted
        # (current or historical); affected claims then get ClaimSuperseded / ClaimContested.
        base = {"subject_id": subject.id, "tenant_id": identity.tenant_id, "predicate": body.predicate}
        if emit_evidence_event:
            self._append_event(db, identity.tenant_id, subject.id, claim.id, "EvidenceAcquired", b"", {
                **base, "claim_id": claim.id, "evidence_id": body.evidence.evidence_id, "evidence_uri": evidence_uri,
                "evidence_hash": body.evidence.hash.lower(), "retention_rule": body.retention_rule})
        seq, record_hash = self._append_event(db, identity.tenant_id, subject.id, claim.id,
            "ClaimProposed" if status == "contested" else "ClaimAccepted", ciphertext, metadata)
        claim.event_sequence, claim.record_hash = seq, record_hash
        for old in superseded:
            self._append_event(db, identity.tenant_id, subject.id, old.id, "ClaimSuperseded", b"", {
                **base, "claim_id": old.id, "superseded_by": claim.id,
                "source": {"system": old.source_system, "version": old.source_version}})
        for affected in contested + ([claim] if contested else []):
            self._append_event(db, identity.tenant_id, subject.id, affected.id, "ClaimContested", b"", {
                **base, "claim_id": affected.id, "contested_with": [c.id for c in contested + [claim] if c is not affected],
                "source": {"system": affected.source_system, "version": affected.source_version}})
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
                    if as_utc(c.valid_from) > now:
                        result[predicate] = {"state": "unknown", "reason": "not_yet_valid"}
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


    # ----- F01 import contract used by the F08 controlled source import adapter -----

    IMPORT_FILE_RETENTION = "preboarding_source_evidence_file"
    IMPORT_SNAPSHOT_RETENTION = "preboarding_source_evidence"

    def store_import_file_evidence(self, identity, source_system_id, file_key, snapshot_id, file_hash,
                                   content, manifest, correlation):
        """File-level import evidence under a separate file key (design §1.8, D8).

        Idempotent on the file identity: a resumed run reuses the stored evidence.
        """
        with self.sessions() as db:
            self.authorize(db, identity, "source_sync", "mutation", None, correlation)
            existing = db.get(ImportFileEvidence, file_key)
            if existing and existing.tenant_id == identity.tenant_id:
                return self._file_evidence_ref(existing)
            file_dek = os.urandom(32)
            wrapped, reference = self.keys.wrap("import-file:" + file_key, file_dek)
            # A fresh object name per attempt keeps overwrite=False object stores safe on retry.
            evidence_uri = self.evidence.put(identity.tenant_id, "import-files", str(uuid.uuid4()), content, file_dek)
            # file_hash is the record-payload hash from the header (the file identity); upload_hash
            # covers the exact stored bytes including the header line.
            manifest = {**manifest, "upload_hash": sha256(content)}
            evidence = ImportFileEvidence(id=file_key, tenant_id=identity.tenant_id, source_system_id=source_system_id,
                snapshot_id=snapshot_id, file_hash=file_hash, wrapped_key=wrapped, key_reference=reference,
                evidence_uri=evidence_uri, manifest=manifest, retention_rule=self.IMPORT_FILE_RETENTION)
            db.add(evidence)
            self.audit(db, identity, None, "source_sync", "import_file_evidence", "accepted", correlation)
            try:
                db.commit()
            except IntegrityError:
                db.rollback()
                return self._file_evidence_ref(db.get(ImportFileEvidence, file_key))
            return self._file_evidence_ref(evidence)

    @staticmethod
    def _file_evidence_ref(evidence):
        return {"file_evidence_id": evidence.id, "file_hash": evidence.file_hash,
                "evidence_uri": evidence.evidence_uri, "manifest_hash": sha256(canonical(evidence.manifest)),
                "retention_rule": evidence.retention_rule, "key_destroyed": evidence.wrapped_key is None}

    def read_import_file_evidence(self, db, file_evidence_id):
        """Decrypt the stored raw file; 410 once its key is destroyed. No endpoint exposes it."""
        evidence = db.get(ImportFileEvidence, file_evidence_id)
        if not evidence:
            raise HTTPException(404, "file evidence not found")
        if not evidence.wrapped_key or not evidence.key_reference:
            raise HTTPException(410, "file evidence key has been destroyed")
        key = self.keys.unwrap("import-file:" + evidence.id, evidence.wrapped_key, evidence.key_reference)
        name = evidence.evidence_uri.rsplit("/", 1)[-1]
        return self.evidence.read_verified(evidence.evidence_uri, name, evidence.manifest["upload_hash"], key)

    def destroy_import_file_key(self, db, file_evidence_id, reason):
        """Retention end (F07) or erasure of any contained subject (F02). Manifest is kept."""
        evidence = db.get(ImportFileEvidence, file_evidence_id)
        if evidence and evidence.wrapped_key is not None:
            evidence.wrapped_key, evidence.key_reference = None, None
            evidence.key_destroyed_at, evidence.key_destroyed_reason = datetime.now(timezone.utc), reason

    def crypto_shred_subject(self, db, subject_id):
        """Rights-triggered erasure hook executed by F02: destroy the subject key and the key of
        every shared import file containing the subject. Other subjects keep their own snapshots."""
        subject = db.get(Subject, subject_id)
        subject.wrapped_key, subject.key_reference = None, None
        for link in db.scalars(select(ImportFileEvidenceSubject).where(ImportFileEvidenceSubject.subject_id == subject_id)):
            self.destroy_import_file_key(db, link.file_evidence_id, "subject_erasure")

    def submit_import_record(self, identity, record, keys, snapshot, file_evidence_id, correlation):
        """F01 atomic record-scoped mutation set (design §1.2 step 4, D1).

        Resolve the deterministic binding, store one per-record snapshot under the subject key,
        validate and commit every mapped claim in one transaction. If one mapped claim fails,
        nothing from the record is accepted. Called only after the adapter validated the record.
        """
        from .schemas import ClaimMutation
        from .source_registry import ATS_FIELD_MAPPING
        values = record.model_dump(mode="json")
        # Registered authority only (F01 registry entry for the ATS source, D11).
        mapped = [(predicate, values[field]) for field, predicate in ATS_FIELD_MAPPING.items()]
        if record.tenant_id != identity.tenant_id:
            raise HTTPException(422, "WRONG_TENANT")
        with self.sessions() as db:
            self.authorize(db, identity, "source_sync", "mutation", None, correlation)
            bindings = list(db.scalars(select(SubjectBinding).where(
                SubjectBinding.tenant_id == identity.tenant_id,
                SubjectBinding.source_system == snapshot["source_system_id"],
                SubjectBinding.source_person_ref == record.source_person_ref)))
            if len(bindings) > 1:
                return self._integrity_alert(db, identity, None, correlation)
            if bindings:
                subject = db.scalar(select(Subject).where(Subject.id == bindings[0].subject_id).with_for_update())
                self._subject(db, identity, subject.id, "source_sync", "mutation", correlation)
            else:
                if record.event_type == "offer_updated":
                    raise HTTPException(422, "UNBOUND_SUBJECT")
                subject = Subject(tenant_id=identity.tenant_id)
                db.add(subject); db.flush()
                subject.wrapped_key, subject.key_reference = self.keys.wrap(subject.id, os.urandom(32))
                db.add(SubjectBinding(subject_id=subject.id, tenant_id=identity.tenant_id,
                    source_system=snapshot["source_system_id"], source_person_ref=record.source_person_ref,
                    authenticated_account_id=None))
            # One offer identity may never map to a second subject (D9).
            other = db.scalar(select(Claim.id).where(Claim.tenant_id == identity.tenant_id,
                Claim.source_system == snapshot["source_system_id"],
                Claim.source_record_id == record.source_record_id, Claim.subject_id != subject.id))
            if other:
                return self._integrity_alert(db, identity, subject.id, correlation)
            batch_key = "f08-record:" + keys.idempotency_key
            receipt = db.scalar(select(MutationReceipt).where(
                MutationReceipt.tenant_id == identity.tenant_id, MutationReceipt.idempotency_key == batch_key))
            if receipt:
                return {**receipt.response_json, "duplicate": True}
            superseded = list(db.scalars(select(Claim.id).where(
                Claim.subject_id == subject.id, Claim.source_system == snapshot["source_system_id"],
                Claim.predicate.in_([p for p, _ in mapped]), Claim.status.in_(["current", "contested"]),
                Claim.source_version < record.source_version)))
            # Per-record snapshot under the subject key; every mapped claim references it.
            content = canonical(snapshot)
            evidence_id = sha256((keys.idempotency_key + ":snapshot").encode())[:36]
            key = self.keys.unwrap(subject.id, subject.wrapped_key, subject.key_reference)
            evidence_uri = self.evidence.put(identity.tenant_id, subject.id, evidence_id, content, key)
            results = []
            for index, (predicate, value) in enumerate(mapped):
                body = ClaimMutation(idempotency_key=batch_key + ":" + predicate,
                    predicate=predicate, value=value, claim_class="authoritative", record_kind="canonical_claim",
                    source={"system": snapshot["source_system_id"], "record_id": record.source_record_id,
                            "authority": "authoritative", "version": record.source_version},
                    evidence={"evidence_id": evidence_id, "hash": sha256(content),
                              "content_base64": base64.b64encode(content).decode()},
                    purpose_id="source_sync", valid_from=record.effective_from,
                    observed_at=record.source_updated_at, retention_rule=self.IMPORT_SNAPSHOT_RETENTION,
                    confidence_band="confirmed")
                results.append(self._mutate(db, identity, subject.id, body, correlation, commit=False,
                                            stored_evidence_uri=evidence_uri, emit_evidence_event=index == 0))
            if file_evidence_id and not db.get(ImportFileEvidenceSubject, (file_evidence_id, subject.id)):
                db.add(ImportFileEvidenceSubject(file_evidence_id=file_evidence_id, subject_id=subject.id))
            result = {"subject_id": subject.id, "claims": results, "superseded_claim_ids": superseded,
                      "snapshot": {"evidence_id": evidence_id, "evidence_hash": sha256(content),
                                   "evidence_uri": evidence_uri, "file_evidence_id": file_evidence_id},
                      "duplicate": False}
            db.add(MutationReceipt(tenant_id=identity.tenant_id, idempotency_key=batch_key,
                                   request_hash=keys.idempotency_key, response_json=result))
            db.commit()
            return result

    def _integrity_alert(self, db, identity, subject_id, correlation):
        db.rollback()
        self.audit(db, identity, subject_id, "source_sync", "claim_mutation", "integrity_alert", correlation)
        db.commit()
        raise HTTPException(422, "BINDING_INTEGRITY_ERROR")


class F01ImportContract:
    """The only F01 surface handed to the F08 adapter (design §1.11).

    It exposes the evidence and atomic record-mutation contracts and nothing else:
    no session factory, no claim/ledger/evidence writers.
    """
    __slots__ = ("_service",)

    def __init__(self, service: ClaimService):
        self._service = service

    def store_file_evidence(self, *args, **kwargs):
        return self._service.store_import_file_evidence(*args, **kwargs)

    def submit_record(self, *args, **kwargs):
        return self._service.submit_import_record(*args, **kwargs)
