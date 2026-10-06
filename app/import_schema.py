"""Synthetic ATS offer/update JSONL v1. Extra fields are rejected."""
from datetime import date
from typing import Literal
from pydantic import BaseModel, ConfigDict, Field, AwareDatetime


class StrictModel(BaseModel):
    model_config = ConfigDict(extra='forbid')


class ImportHeader(StrictModel):
    schema_version: Literal['1']
    source_system_id: Literal['ATS']
    tenant_id: str = Field(min_length=1, max_length=128)
    snapshot_id: str = Field(min_length=1, max_length=128)
    generated_at: AwareDatetime
    record_count: int = Field(ge=1, le=100)
    content_hash: str = Field(pattern=r'^[0-9a-f]{64}$')


class OfferRecord(StrictModel):
    tenant_id: str = Field(min_length=1, max_length=128)
    source_record_id: str = Field(min_length=1, max_length=256)
    source_person_ref: str = Field(min_length=1, max_length=256)
    # Required for offer_accepted; checked against the existing binding on updates.
    authenticated_account_id: str = Field(min_length=1, max_length=128)
    source_version: int = Field(ge=1, le=2147483647, strict=True)
    source_updated_at: AwareDatetime
    event_type: Literal['offer_accepted', 'offer_updated']
    role_ref: str = Field(min_length=1, max_length=256)
    start_date: date = Field(strict=False)
    offer_status: Literal['accepted']
    effective_from: AwareDatetime
