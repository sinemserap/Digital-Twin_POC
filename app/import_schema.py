"""Synthetic ATS offer/update JSONL contract, schema v1 (US40858 F08 Part 1 §1.1).

The record carries exactly the agreed fields. A field outside the registered
authority mapping is NOT_AUTHORITATIVE and rejects the entire record (D6); a
missing or malformed required field is INVALID_RECORD. Withdrawal is out of scope.
"""
from dataclasses import dataclass
from datetime import date
from typing import Literal
from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, ValidationError
from .security import sha256
from .service import canonical


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class ImportHeader(StrictModel):
    """First JSONL line: the file gate."""
    schema_version: Literal["1"]
    source_system_id: str = Field(min_length=1, max_length=128)
    tenant_id: str = Field(min_length=1, max_length=128)
    snapshot_id: str = Field(min_length=1, max_length=128)
    generated_at: AwareDatetime
    record_count: int = Field(ge=1, le=100, strict=True)
    # SHA-256 of the exact record lines joined with LF plus one trailing LF; header excluded.
    content_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    # HMAC-SHA256(source signing secret, content_hash); required and verified only when configured.
    signature: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")


class OfferRecord(StrictModel):
    """One offer/update record. Subject binding is deterministic through source_person_ref."""
    tenant_id: str = Field(min_length=1, max_length=128)
    source_record_id: str = Field(min_length=1, max_length=256)
    source_person_ref: str = Field(min_length=1, max_length=256)
    # Required and monotonic: the only ordering key (D4).
    source_version: int = Field(ge=1, le=2147483647, strict=True)
    # Observed-at timestamp only; never an ordering fallback.
    source_updated_at: AwareDatetime
    event_type: Literal["offer_accepted", "offer_updated"]
    role_ref: str = Field(min_length=1, max_length=256)
    start_date: date = Field(strict=False)
    offer_status: Literal["accepted"]
    # Valid time of the change (F01 valid_from).
    effective_from: AwareDatetime


RECORD_FIELDS = frozenset(OfferRecord.model_fields)


class RecordRejected(Exception):
    """Whole-record rejection with a design §1.3 reason code."""
    def __init__(self, reason_code: str):
        super().__init__(reason_code)
        self.reason_code = reason_code


def validate_record(obj) -> OfferRecord:
    if not isinstance(obj, dict):
        raise RecordRejected("INVALID_RECORD")
    if set(obj) - RECORD_FIELDS:
        # e.g. work_location, manager_ref: never dropped silently, the record is rejected.
        raise RecordRejected("NOT_AUTHORITATIVE")
    try:
        return OfferRecord.model_validate(obj)
    except ValidationError:
        raise RecordRejected("INVALID_RECORD")


@dataclass(frozen=True)
class RecordKeys:
    """Design §1.4 identity values for one record."""
    identity_key: str      # SHA-256(tenant_id + source_system_id + source_record_id + source_version)
    content_hash: str      # SHA-256 of the canonical validated record
    idempotency_key: str   # SHA-256(identity_key + content_hash)
    line_hash: str         # SHA-256 of the exact JSONL line (lineage to the file manifest)
    position: int          # 1-based record position after the header line


def record_keys(tenant_id: str, source_system_id: str, record: OfferRecord, line: str, position: int) -> RecordKeys:
    identity = sha256(canonical([tenant_id, source_system_id, record.source_record_id, record.source_version]))
    content = sha256(canonical(record.model_dump(mode="json")))
    return RecordKeys(identity, content, sha256((identity + content).encode()), sha256(line.encode()), position)


def json_schema_v1() -> dict:
    """Published JSON Schema for both line kinds; fixtures/offer-update-v1.schema.json mirrors it."""
    return {"header": ImportHeader.model_json_schema(), "record": OfferRecord.model_json_schema()}
