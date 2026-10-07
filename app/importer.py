"""F08 controlled source import adapter (US40858 Part 1, December PoC).

The adapter validates, persists its own operational state (import_run,
import_record_outcome, import_attempt, import_event) and submits through the
F01 contract. File-level evidence, per-record subject snapshots and all claim
changes are written by F01 only; the adapter's session factory refuses every
other table (design §1.11).
"""
import json
import threading
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from fastapi import HTTPException
from pydantic import ValidationError
from sqlalchemy import DateTime, ForeignKey, Integer, JSON, String, event, select, text
from sqlalchemy.orm import Mapped, mapped_column, sessionmaker
from .database import Base
from .import_schema import ImportHeader, RecordRejected, record_keys, validate_record
from .models import utcnow, uuid_str
from .security import Identity, sha256
from .service import as_utc, canonical

OUTCOMES = ("accepted", "superseded", "historical", "duplicate", "held_for_review", "contested", "rejected")
# Outcomes whose record reached F01 and therefore carry F01 result references.
CANONICAL_OUTCOMES = frozenset({"accepted", "superseded", "historical", "contested", "duplicate"})
F08_TABLES = frozenset({"import_run", "import_record_outcome", "import_attempt", "import_event"})
HOLD_RETENTION = "import_hold_short_review"


class ImportRun(Base):
    """One run per file identity (tenant + source + snapshot + content hash); design §1.9."""
    __tablename__ = "import_run"
    run_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(128), index=True)
    source_system_id: Mapped[str] = mapped_column(String(128))
    snapshot_id: Mapped[str] = mapped_column(String(128))
    content_hash: Mapped[str] = mapped_column(String(64))
    generated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    file_evidence_id: Mapped[str | None] = mapped_column(String(64))
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    status: Mapped[str] = mapped_column(String(20))  # in_progress | complete
    attempt_count: Mapped[int] = mapped_column(Integer, default=0)
    last_attempt_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    total_records: Mapped[int] = mapped_column(Integer)


class ImportRecordOutcome(Base):
    """Durable per-record outcome; identifiers, hashes and reason codes only, never field values."""
    __tablename__ = "import_record_outcome"
    run_id: Mapped[str] = mapped_column(ForeignKey("import_run.run_id"), primary_key=True)
    position: Mapped[int] = mapped_column(Integer, primary_key=True)
    source_record_id: Mapped[str | None] = mapped_column(String(256))
    source_version: Mapped[int | None] = mapped_column(Integer)
    identity_key: Mapped[str | None] = mapped_column(String(64), index=True)
    idempotency_key: Mapped[str | None] = mapped_column(String(64), index=True)
    record_hash: Mapped[str] = mapped_column(String(64))
    outcome: Mapped[str] = mapped_column(String(20))
    reason_code: Mapped[str] = mapped_column(String(40))
    f01_result: Mapped[dict | None] = mapped_column(JSON)
    evidence_ref: Mapped[dict | None] = mapped_column(JSON)
    retention_rule: Mapped[str | None] = mapped_column(String(128))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class ImportAttempt(Base):
    """Audit of every upload attempt: user, file hash (via run) and outcome (design §1.7)."""
    __tablename__ = "import_attempt"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_str)
    run_id: Mapped[str] = mapped_column(ForeignKey("import_run.run_id"), index=True)
    actor: Mapped[str] = mapped_column(String(128))
    correlation_id: Mapped[str] = mapped_column(String(128))
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    outcome: Mapped[str] = mapped_column(String(20))  # started | resumed | duplicate_file | complete


class ImportEvent(Base):
    """Adapter-level events: ImportFileRejected, ImportRecordHeld, BindingIntegrityAlert (design §1.11)."""
    __tablename__ = "import_event"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_str)
    tenant_id: Mapped[str] = mapped_column(String(128), index=True)
    source_system_id: Mapped[str] = mapped_column(String(128))
    event_type: Mapped[str] = mapped_column(String(40))
    run_id: Mapped[str | None] = mapped_column(String(64))
    reason_code: Mapped[str] = mapped_column(String(40))
    detail: Mapped[dict] = mapped_column(JSON)
    actor: Mapped[str] = mapped_column(String(128))
    correlation_id: Mapped[str] = mapped_column(String(128))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class MalwareDetected(Exception):
    pass


class NoMalwareScanner:
    """PoC default for synthetic data: no scan is performed. Deployment injects a real adapter."""
    configured = False

    def scan(self, content: bytes) -> None:
        return None


def operational_sessions(engine):
    """Session factory limited to F08 tables: the adapter identity cannot write canonical rows."""
    factory = sessionmaker(bind=engine, expire_on_commit=False)

    @event.listens_for(factory, "before_flush")
    def deny_canonical_writes(session, flush_context, instances):
        for obj in list(session.new) + list(session.dirty) + list(session.deleted):
            if obj.__tablename__ not in F08_TABLES:
                raise PermissionError(f"F08 adapter has no write permission on {obj.__tablename__}")
    return factory


def unique_pairs(pairs):
    """Duplicate JSON keys are ambiguous and must not pass an integrity gate."""
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate key")
        result[key] = value
    return result


class ControlledImporter:
    MAX_BYTES = 256 * 1024
    FRESHNESS = timedelta(days=7)

    def __init__(self, engine, f01, registry, scanner=None):
        self.engine, self.f01, self.registry = engine, f01, registry
        self.sessions = operational_sessions(engine)
        self.scanner = scanner or NoMalwareScanner()
        self.lock = threading.RLock()

    def authorize(self, identity):
        if "data_administrator" not in identity.roles or "candidate" in identity.roles:
            raise HTTPException(403, "import requires data_administrator")

    @contextmanager
    def serialized(self, tenant, source_system_id):
        # SQLite demo uses one process. PostgreSQL serializes this source across
        # service instances with a session advisory lock, released on disconnect.
        with self.lock:
            if self.engine.dialect.name != "postgresql":
                yield
                return
            key = int(sha256(f"{tenant}:{source_system_id}:f08".encode())[:15], 16)
            with self.engine.connect() as conn:
                conn.execute(text("SELECT pg_advisory_lock(:key)"), {"key": key}); conn.commit()
                try:
                    yield
                finally:
                    conn.execute(text("SELECT pg_advisory_unlock(:key)"), {"key": key}); conn.commit()

    # ----- file gate (design §1.2 steps 1-2, §1.3) -----

    def _reject_file(self, identity, source_system_id, reason, file_hash, correlation):
        with self.sessions() as db:
            db.add(ImportEvent(tenant_id=identity.tenant_id, source_system_id=source_system_id,
                event_type="ImportFileRejected", reason_code=reason, detail={"file_hash": file_hash},
                actor=identity.account_id, correlation_id=correlation))
            db.commit()
        raise HTTPException(422, reason)

    def gate(self, identity, source_system_id, raw, correlation):
        file_hash = sha256(raw)

        def reject(reason):
            self._reject_file(identity, source_system_id, reason, file_hash, correlation)
        if not raw or len(raw) > self.MAX_BYTES:
            reject("FILE_SIZE_INVALID")
        try:
            self.scanner.scan(raw)
        except MalwareDetected:
            reject("FILE_REJECTED_MALWARE")
        try:
            lines = raw.decode("utf-8").split("\n")
            if lines and lines[-1] == "":
                lines.pop()
            raw_header = json.loads(lines[0], object_pairs_hook=unique_pairs)
            if not isinstance(raw_header, dict):
                raise ValueError("header must be an object")
        except (ValueError, IndexError):
            reject("FILE_STRUCTURE_INVALID")
        source, version = raw_header.get("source_system_id"), raw_header.get("schema_version")
        registration = self.registry.get(source) if isinstance(source, str) else None
        if not registration or registration.source_system_id != source_system_id:
            reject("SOURCE_NOT_REGISTERED")
        if raw_header.get("tenant_id") != identity.tenant_id:
            reject("FILE_TENANT_MISMATCH")
        if not isinstance(version, str) or version not in registration.schema_versions:
            reject("SCHEMA_VERSION_UNSUPPORTED")
        try:
            header = ImportHeader.model_validate(raw_header)
            objects = [json.loads(line, object_pairs_hook=unique_pairs) for line in lines[1:]]
        except (ValueError, ValidationError):
            reject("FILE_STRUCTURE_INVALID")
        payload = ("\n".join(lines[1:]) + "\n").encode()
        if len(objects) != header.record_count or sha256(payload) != header.content_hash:
            reject("FILE_INTEGRITY_FAILED")
        if registration.signing_secret and not registration.signature_valid(header.content_hash, header.signature):
            reject("FILE_INTEGRITY_FAILED")
        if header.generated_at > datetime.now(timezone.utc):
            reject("FILE_INTEGRITY_FAILED")
        return registration, header, lines[1:], objects

    # ----- run processing (design §1.2 steps 3-5, §1.4, §1.9) -----

    def import_file(self, identity, source_system_id, raw, correlation):
        self.authorize(identity)
        registration, header, lines, objects = self.gate(identity, source_system_id, raw, correlation)
        file_key = sha256(canonical([identity.tenant_id, source_system_id, header.snapshot_id, header.content_hash]))
        with self.serialized(identity.tenant_id, source_system_id):
            now = datetime.now(timezone.utc)
            with self.sessions() as db:
                run = db.get(ImportRun, file_key)
                if run:
                    run.attempt_count += 1
                    run.last_attempt_at = now
                    attempt = "duplicate_file" if run.status == "complete" else "resumed"
                else:
                    run = ImportRun(run_id=file_key, tenant_id=identity.tenant_id, source_system_id=source_system_id,
                        snapshot_id=header.snapshot_id, content_hash=header.content_hash,
                        generated_at=header.generated_at, started_at=now, status="in_progress",
                        attempt_count=1, last_attempt_at=now, total_records=header.record_count)
                    db.add(run); db.flush()
                    attempt = "started"
                attempt_row = ImportAttempt(run_id=file_key, actor=identity.account_id,
                                            correlation_id=correlation, started_at=now, outcome=attempt)
                db.add(attempt_row)
                db.commit()
                if attempt == "duplicate_file":
                    # Completed exact file: no record is resubmitted to F01.
                    attempt_row.finished_at = datetime.now(timezone.utc)
                    db.commit()
                    return self.report(db, run, duplicate_file=True)
                file_evidence_id, attempt_id = run.file_evidence_id, attempt_row.id
            if file_evidence_id is None:
                manifest = {"file_hash": header.content_hash, "snapshot_id": header.snapshot_id,
                            "record_count": header.record_count,
                            "records": [{"position": i, "record_hash": sha256(line.encode())}
                                        for i, line in enumerate(lines, 1)]}
                stored = self.f01.store_file_evidence(self._f01_identity(identity), source_system_id, file_key,
                    header.snapshot_id, header.content_hash, raw, manifest, correlation)
                file_evidence_id = stored["file_evidence_id"]
                with self.sessions() as db:
                    db.get(ImportRun, file_key).file_evidence_id = file_evidence_id
                    db.commit()
            with self.sessions() as db:
                done = set(db.scalars(select(ImportRecordOutcome.position).where(ImportRecordOutcome.run_id == file_key)))
            for position, (line, obj) in enumerate(zip(lines, objects), 1):
                if position in done:
                    continue  # already durable from an earlier attempt
                outcome = self.process_record(identity, registration, header, file_evidence_id, position, line, obj, correlation)
                with self.sessions() as db:
                    db.add(ImportRecordOutcome(run_id=file_key, **outcome))
                    if outcome["outcome"] == "held_for_review":
                        self._event(db, identity, source_system_id, "ImportRecordHeld", file_key, outcome, correlation)
                    elif outcome["reason_code"] == "BINDING_INTEGRITY_ERROR":
                        self._event(db, identity, source_system_id, "BindingIntegrityAlert", file_key, outcome, correlation)
                    db.commit()
            with self.sessions() as db:
                run = db.get(ImportRun, file_key)
                run.status, run.completed_at = "complete", datetime.now(timezone.utc)
                attempt_row = db.get(ImportAttempt, attempt_id)
                attempt_row.outcome, attempt_row.finished_at = "complete", run.completed_at
                db.commit()
                return self.report(db, run)

    @staticmethod
    def _f01_identity(identity):
        # The adapter calls F01 with the internal source-service role after admin validation.
        return Identity(identity.tenant_id, identity.account_id, frozenset({"source_service"}))

    @staticmethod
    def _event(db, identity, source_system_id, event_type, run_id, outcome, correlation):
        db.add(ImportEvent(tenant_id=identity.tenant_id, source_system_id=source_system_id, event_type=event_type,
            run_id=run_id, reason_code=outcome["reason_code"], actor=identity.account_id, correlation_id=correlation,
            detail={"position": outcome["position"], "record_hash": outcome["record_hash"],
                    "source_record_id": outcome.get("source_record_id"), "source_version": outcome.get("source_version")}))

    def process_record(self, identity, registration, header, file_evidence_id, position, line, obj, correlation):
        """Design §1.3 decision table for one record. Returns the durable outcome columns."""
        base = {"position": position, "record_hash": sha256(line.encode()), "source_record_id": None,
                "source_version": None, "identity_key": None, "idempotency_key": None,
                "f01_result": None, "evidence_ref": None, "retention_rule": None}
        try:
            record = validate_record(obj)
            base.update(source_record_id=record.source_record_id, source_version=record.source_version)
            if record.tenant_id != identity.tenant_id:
                raise RecordRejected("WRONG_TENANT")
            if record.source_updated_at > header.generated_at:
                raise RecordRejected("INVALID_RECORD")
            keys = record_keys(identity.tenant_id, registration.source_system_id, record, line, position)
            base.update(identity_key=keys.identity_key, idempotency_key=keys.idempotency_key)
            with self.sessions() as db:
                seen = select(ImportRecordOutcome).join(ImportRun).where(
                    ImportRun.tenant_id == identity.tenant_id,
                    ImportRun.source_system_id == registration.source_system_id,
                    ImportRecordOutcome.outcome.in_(CANONICAL_OUTCOMES))
                prior = db.scalar(seen.where(ImportRecordOutcome.idempotency_key == keys.idempotency_key)
                                  .order_by(ImportRecordOutcome.created_at).limit(1))
                if prior:
                    # Exact record already processed: no-op, original F01 references.
                    return {**base, "outcome": "duplicate", "reason_code": "DUPLICATE", "f01_result": prior.f01_result}
                conflicting = db.scalar(seen.where(ImportRecordOutcome.identity_key == keys.identity_key,
                                                   ImportRecordOutcome.idempotency_key != keys.idempotency_key).limit(1))
            snapshot = {"record": record.model_dump(mode="json"), "source_system_id": registration.source_system_id,
                        "file_hash": header.content_hash, "snapshot_id": header.snapshot_id,
                        "source_record_id": record.source_record_id, "source_version": record.source_version,
                        "record_hash": keys.line_hash, "content_hash": keys.content_hash, "position": position,
                        "file_evidence_id": file_evidence_id}
            result = self.f01.submit_record(self._f01_identity(identity), record, keys, snapshot, file_evidence_id, correlation)
            statuses = {claim["status"] for claim in result["claims"]}
            if conflicting is not None or "contested" in statuses:
                outcome, reason = "contested", "VERSION_CONFLICT"
            elif statuses == {"historical"}:
                outcome, reason = "historical", "LATE_HISTORICAL"
            elif result.get("superseded_claim_ids"):
                outcome, reason = "superseded", "SUPERSEDED"
            else:
                outcome, reason = "accepted", "ACCEPTED"
            if outcome in ("accepted", "superseded") and record.effective_from > datetime.now(timezone.utc):
                reason = "FUTURE_VALID"
            return {**base, "outcome": outcome, "reason_code": reason, "f01_result": result}
        except RecordRejected as exc:
            return {**base, "outcome": "rejected", "reason_code": exc.reason_code}
        except HTTPException as exc:
            if exc.status_code not in (403, 409, 410, 422):
                raise
            reason = exc.detail if exc.status_code == 422 else {
                403: "RESTRICTED", 409: "IDEMPOTENCY_CONFLICT", 410: "ERASED"}[exc.status_code]
            if reason == "UNBOUND_SUBJECT":
                # Held outside the canonical twin: metadata and an evidence reference only.
                return {**base, "outcome": "held_for_review", "reason_code": reason, "retention_rule": HOLD_RETENTION,
                        "evidence_ref": {"file_evidence_id": file_evidence_id, "position": position,
                                         "record_hash": base["record_hash"]}}
            return {**base, "outcome": "rejected", "reason_code": reason}

    # ----- run report (design §1.10) -----

    def report(self, db, run, duplicate_file=False):
        rows = db.scalars(select(ImportRecordOutcome).where(ImportRecordOutcome.run_id == run.run_id)
                          .order_by(ImportRecordOutcome.position)).all()
        counts = {outcome: 0 for outcome in OUTCOMES}
        for row in rows:
            counts[row.outcome] += 1
        return {"run_id": run.run_id, "source_system_id": run.source_system_id, "tenant_id": run.tenant_id,
                "snapshot_id": run.snapshot_id, "file_hash": run.content_hash,
                "started_at": as_utc(run.started_at).isoformat(),
                "completed_at": as_utc(run.completed_at).isoformat() if run.completed_at else None,
                "status": run.status, "total_records": run.total_records, "attempt_count": run.attempt_count,
                "duplicate_file": duplicate_file, "file_evidence_id": run.file_evidence_id, "counts": counts,
                "outcomes": [{"position": r.position, "source_record_id": r.source_record_id,
                              "source_version": r.source_version, "record_hash": r.record_hash,
                              "outcome": r.outcome, "reason_code": r.reason_code, "f01": r.f01_result,
                              "evidence_ref": r.evidence_ref, "retention_rule": r.retention_rule} for r in rows]}

    def freshness(self, identity, source_system_id):
        """Retained operator status from the earlier F08 acceptance criteria (outside §1.12)."""
        self.authorize(identity)
        if source_system_id not in self.registry:
            raise HTTPException(422, "SOURCE_NOT_REGISTERED")
        with self.sessions() as db:
            # A rejected file or an all-rejected file cannot claim successful source activity.
            times = [as_utc(t) for t in db.scalars(select(ImportRun.generated_at).join(ImportRecordOutcome).where(
                ImportRun.tenant_id == identity.tenant_id, ImportRun.source_system_id == source_system_id,
                ImportRun.status == "complete", ImportRecordOutcome.outcome.in_(CANONICAL_OUTCOMES)).distinct())]
        latest = max(times) if times else None
        age = max(0, int((datetime.now(timezone.utc) - latest).total_seconds())) if latest else None
        return {"source_system_id": source_system_id, "state": "missing" if latest is None else
                "stale" if age >= self.FRESHNESS.total_seconds() else "fresh",
                "generated_at": latest.isoformat() if latest else None,
                "age_seconds": age, "stale_after_seconds": int(self.FRESHNESS.total_seconds()),
                "task_completion": "unknown"}
