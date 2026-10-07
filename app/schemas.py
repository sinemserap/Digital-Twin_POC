from datetime import datetime
from typing import Any, Literal
from pydantic import BaseModel, Field


class SubjectImport(BaseModel):
    source_system: str = Field(min_length=1)
    source_person_ref: str = Field(min_length=1)
    authenticated_account_id: str = Field(min_length=1)


class SourceInfo(BaseModel):
    system: str = Field(min_length=1)
    record_id: str = Field(min_length=1)
    authority: str = Field(min_length=1)
    version: int = Field(ge=0)


class EvidenceInfo(BaseModel):
    evidence_id: str = Field(min_length=1)
    hash: str = Field(pattern=r"^[0-9a-fA-F]{64}$")
    content_base64: str = Field(min_length=1)


class ClaimMutation(BaseModel):
    idempotency_key: str = Field(min_length=1)
    predicate: str
    value: Any
    claim_class: str
    record_kind: str
    source: SourceInfo
    evidence: EvidenceInfo
    purpose_id: str
    valid_from: datetime
    valid_to: datetime | None = None
    observed_at: datetime
    retention_rule: str = Field(min_length=1)
    confidence_band: str = Field(min_length=1)

