"""Bounded adapter: only operational state; all person changes belong to F01."""
import json
import threading
from contextlib import contextmanager
from datetime import datetime, timezone, timedelta
from fastapi import HTTPException
from pydantic import ValidationError
from sqlalchemy import select, text
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy import String, JSON, DateTime
from .database import Base
from .import_schema import ImportHeader, OfferRecord
from .security import Identity, sha256
from .service import canonical, as_utc


class ImportRun(Base):
    __tablename__ = 'import_run'
    file_key: Mapped[str] = mapped_column(String(64), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(128), index=True)
    source: Mapped[str] = mapped_column(String(128))
    generated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    report: Mapped[dict] = mapped_column(JSON)


class ControlledImporter:
    MAX_BYTES = 256 * 1024
    FRESHNESS = timedelta(days=7)

    def __init__(self, sessions, engine, claims):
        self.sessions, self.engine, self.claims = sessions, engine, claims
        self.lock = threading.RLock()

    def authorize(self, identity):
        if 'data_administrator' not in identity.roles or 'candidate' in identity.roles:
            raise HTTPException(403, 'import requires data_administrator')

    @contextmanager
    def serialized(self, tenant):
        # SQLite demo uses one process. PostgreSQL serializes this source across
        # service instances with a session advisory lock, released on disconnect.
        with self.lock:
            if self.engine.dialect.name != 'postgresql':
                yield
                return
            key = int(sha256((tenant + ':ATS:f08').encode())[:15], 16)
            with self.engine.connect() as conn:
                conn.execute(text('SELECT pg_advisory_lock(:key)'), {'key':key}); conn.commit()
                try:
                    yield
                finally:
                    conn.execute(text('SELECT pg_advisory_unlock(:key)'), {'key':key}); conn.commit()

    def import_file(self, identity, raw, correlation):
        self.authorize(identity)
        if not raw or len(raw) > self.MAX_BYTES:
            raise HTTPException(422, 'FILE_SIZE_INVALID')
        try:
            # Reject duplicate JSON keys; ambiguity must not pass an integrity gate.
            def unique(pairs):
                result = {}
                for k, v in pairs:
                    if k in result:
                        raise ValueError('duplicate key')
                    result[k] = v
                return result
            lines = raw.decode('utf-8').splitlines()
            header = ImportHeader.model_validate(json.loads(lines[0], object_pairs_hook=unique))
            objects = [json.loads(line, object_pairs_hook=unique) for line in lines[1:]]
        except (ValueError, ValidationError, IndexError):
            raise HTTPException(422, 'FILE_STRUCTURE_INVALID')
        if header.tenant_id != identity.tenant_id:
            raise HTTPException(422, 'FILE_TENANT_MISMATCH')
        # Hash exact UTF-8 record lines joined by LF with one trailing LF.
        payload = ('\n'.join(lines[1:]) + '\n').encode()
        if len(objects) != header.record_count or sha256(payload) != header.content_hash:
            raise HTTPException(422, 'FILE_INTEGRITY_FAILED')
        now = datetime.now(timezone.utc)
        if header.generated_at > now:
            raise HTTPException(422, 'FUTURE_SOURCE_TIMESTAMP')
        file_key = sha256(canonical([identity.tenant_id, 'ATS', header.snapshot_id, header.content_hash]))
        with self.serialized(identity.tenant_id):
            with self.sessions() as db:
                run = db.get(ImportRun, file_key)
                if run and run.report['complete']:
                    return {**run.report, 'duplicate_file':True}
                if not run:
                    run = ImportRun(file_key=file_key, tenant_id=identity.tenant_id, source='ATS',
                        generated_at=header.generated_at, report={'run_id':file_key, 'complete':False,
                        'duplicate_file':False, 'outcomes':[]})
                    db.add(run); db.commit()
                report = dict(run.report)
            for position, obj in enumerate(objects, 1):
                if position <= len(report['outcomes']):
                    continue
                outcome = {'position':position, 'record_hash':sha256(canonical(obj))}
                try:
                    record = OfferRecord.model_validate(obj)
                    if record.tenant_id != identity.tenant_id:
                        raise HTTPException(422, 'WRONG_TENANT')
                    if record.source_updated_at > header.generated_at:
                        raise HTTPException(422, 'SOURCE_TIMESTAMP_INVALID')
                    record_key = sha256(canonical([identity.tenant_id, 'ATS', record.source_record_id,
                                                  record.source_version, record.model_dump(mode='json')]))
                    # Use only the internal source-service identity after admin validation.
                    result = self.claims.import_offer(Identity(identity.tenant_id, identity.account_id,
                        frozenset({'source_service'})), record, record_key, correlation)
                    states = {c['status'] for c in result['claims']}
                    status = ('duplicate' if result['duplicate'] else 'contested' if 'contested' in states
                              else 'historical' if states == {'historical'} else 'accepted')
                    outcome.update(outcome=status, reason_code=status.upper(), f01=result)
                except ValidationError:
                    outcome.update(outcome='quarantined', reason_code='INVALID_RECORD')
                except HTTPException as exc:
                    if exc.status_code not in (403, 404, 409, 410, 422):
                        raise
                    reason = exc.detail if exc.status_code == 422 else {403:'RESTRICTED',404:'UNBOUND_SUBJECT',
                        409:'IDEMPOTENCY_CONFLICT',410:'ERASED'}[exc.status_code]
                    outcome.update(outcome='held' if reason == 'UNBOUND_SUBJECT' else 'quarantined', reason_code=reason)
                report['outcomes'] = report['outcomes'] + [outcome]
                with self.sessions() as db:
                    run = db.get(ImportRun, file_key); run.report = report; db.commit()
            report['complete'] = True
            with self.sessions() as db:
                db.get(ImportRun, file_key).report = report
                self.claims.audit(db, identity, None, 'source_sync', 'file_import', 'complete', correlation)
                db.commit()
            return report

    def freshness(self, identity):
        self.authorize(identity)
        with self.sessions() as db:
            runs = list(db.scalars(select(ImportRun).where(ImportRun.tenant_id == identity.tenant_id,
                                                       ImportRun.source == 'ATS')))
        # A valid header or all-invalid file cannot claim successful source activity.
        times = [as_utc(r.generated_at) for r in runs if r.report['complete'] and
                 any(o['outcome'] in {'accepted','historical','contested','duplicate'} for o in r.report['outcomes'])]
        latest = max(times) if times else None
        age = max(0, int((datetime.now(timezone.utc) - latest).total_seconds())) if latest else None
        return {'source_system_id':'ATS', 'state':'missing' if latest is None else
                'stale' if age >= self.FRESHNESS.total_seconds() else 'fresh',
                'generated_at':latest.isoformat() if latest else None,
                'age_seconds':age, 'stale_after_seconds':int(self.FRESHNESS.total_seconds()),
                'task_completion':'unknown'}
