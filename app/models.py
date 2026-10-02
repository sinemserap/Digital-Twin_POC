import uuid
from datetime import datetime, timezone
from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, JSON, LargeBinary, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column
from .database import Base


def uuid_str(): return str(uuid.uuid4())
def utcnow(): return datetime.now(timezone.utc)


class Subject(Base):
    __tablename__ = "subject"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_str)
    tenant_id: Mapped[str] = mapped_column(String(128), index=True)
    wrapped_key: Mapped[bytes | None] = mapped_column(LargeBinary)
    key_reference: Mapped[str | None] = mapped_column(String(512))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class SubjectBinding(Base):
    __tablename__ = "subject_binding"
    __table_args__ = (UniqueConstraint("tenant_id", "source_system", "source_person_ref", name="uq_subject_source_person"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_str)
    subject_id: Mapped[str] = mapped_column(ForeignKey("subject.id"), index=True)
    tenant_id: Mapped[str] = mapped_column(String(128), index=True)
    authenticated_account_id: Mapped[str] = mapped_column(String(128), index=True)
    source_system: Mapped[str] = mapped_column(String(128))
    source_person_ref: Mapped[str] = mapped_column(String(256))


class Claim(Base):
    __tablename__ = "claim"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_str)
    subject_id: Mapped[str] = mapped_column(ForeignKey("subject.id"), index=True)
    tenant_id: Mapped[str] = mapped_column(String(128), index=True)
    predicate: Mapped[str] = mapped_column(String(80), index=True)
    value_ciphertext: Mapped[bytes] = mapped_column(LargeBinary)
    claim_class: Mapped[str] = mapped_column(String(40))
    record_kind: Mapped[str] = mapped_column(String(40))
    status: Mapped[str] = mapped_column(String(40), index=True)
    source_system: Mapped[str] = mapped_column(String(128))
    source_record_id: Mapped[str] = mapped_column(String(256))
    source_authority: Mapped[str] = mapped_column(String(80))
    source_version: Mapped[int] = mapped_column(Integer)
    evidence_id: Mapped[str] = mapped_column(String(36))
    evidence_uri: Mapped[str] = mapped_column(String(1024))
    evidence_hash: Mapped[str] = mapped_column(String(64))
    purpose_ids: Mapped[list] = mapped_column(JSON)
    valid_from: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    valid_to: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    ingested_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    retention_rule: Mapped[str] = mapped_column(String(128))
    confidence_band: Mapped[str] = mapped_column(String(40))
    event_sequence: Mapped[int] = mapped_column(Integer)
    record_hash: Mapped[str] = mapped_column(String(64))


class EventLedger(Base):
    __tablename__ = "event_ledger"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_str)
    tenant_id: Mapped[str] = mapped_column(String(128), index=True)
    subject_id: Mapped[str] = mapped_column(ForeignKey("subject.id"), index=True)
    claim_id: Mapped[str] = mapped_column(ForeignKey("claim.id"))
    sequence: Mapped[int] = mapped_column(Integer)
    event_type: Mapped[str] = mapped_column(String(80), default="ClaimAccepted")
    ciphertext: Mapped[bytes] = mapped_column(LargeBinary)
    metadata_json: Mapped[dict] = mapped_column(JSON)
    previous_hash: Mapped[str] = mapped_column(String(64))
    record_hash: Mapped[str] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class MutationReceipt(Base):
    __tablename__ = "mutation_receipt"
    __table_args__ = (UniqueConstraint("tenant_id", "idempotency_key", name="uq_tenant_idempotency"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_str)
    tenant_id: Mapped[str] = mapped_column(String(128), index=True)
    idempotency_key: Mapped[str] = mapped_column(String(256))
    request_hash: Mapped[str] = mapped_column(String(64))
    claim_id: Mapped[str | None] = mapped_column(String(36))
    response_json: Mapped[dict | None] = mapped_column(JSON)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class PredicateRegistry(Base):
    __tablename__ = "predicate_registry"
    predicate: Mapped[str] = mapped_column(String(80), primary_key=True)
    required_claim_class: Mapped[str] = mapped_column(String(40))


class PurposeRegistry(Base):
    __tablename__ = "purpose_registry"
    purpose: Mapped[str] = mapped_column(String(80), primary_key=True)
    operation: Mapped[str] = mapped_column(String(20))
    required_role: Mapped[str] = mapped_column(String(80))
    allowed: Mapped[bool] = mapped_column(Boolean)


class AuditLog(Base):
    __tablename__ = "audit_log"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_str)
    actor: Mapped[str] = mapped_column(String(128))
    tenant_id: Mapped[str] = mapped_column(String(128), index=True)
    subject_id: Mapped[str | None] = mapped_column(String(36), index=True)
    purpose: Mapped[str] = mapped_column(String(80))
    operation: Mapped[str] = mapped_column(String(80))
    outcome: Mapped[str] = mapped_column(String(40))
    correlation_id: Mapped[str] = mapped_column(String(128))
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

