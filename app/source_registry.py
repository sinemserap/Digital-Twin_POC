"""Registered import sources and their authority scope (F01 Part 1 §1.1 registry entry).

A source may only assert the predicates listed in its field mapping. F08 never
widens this scope: for December schema v1 the synthetic ATS source is authoritative
for offer_status, offered_role (via role_ref) and start_date only. work_location
and manager_ref remain owned by HR/directory and are deliberately absent (D11).
"""
import hashlib
import hmac
import os
from dataclasses import dataclass
from types import MappingProxyType


@dataclass(frozen=True)
class SourceRegistration:
    source_system_id: str
    schema_versions: frozenset[str]
    # F08 record field -> F01 predicate. Every target predicate is ATS-authoritative in F01.
    field_mapping: MappingProxyType
    # Optional file signature: HMAC-SHA256(secret, content_hash). Verified only when configured.
    signing_secret: bytes | None = None

    def signature_for(self, content_hash: str) -> str:
        return hmac.new(self.signing_secret, content_hash.encode(), hashlib.sha256).hexdigest()

    def signature_valid(self, content_hash: str, signature: str | None) -> bool:
        return signature is not None and hmac.compare_digest(self.signature_for(content_hash), signature)


ATS_FIELD_MAPPING = MappingProxyType({
    "offer_status": "offer_status",
    "role_ref": "offered_role",
    "start_date": "start_date",
})


def default_registry(signing_secrets: dict[str, bytes] | None = None) -> dict[str, SourceRegistration]:
    """One agreed ATS-like source for the December PoC. Secrets come from injection or environment."""
    secrets = dict(signing_secrets or {})
    env_secret = os.getenv("IMPORT_SIGNING_SECRET_ATS")
    if "ATS" not in secrets and env_secret:
        secrets["ATS"] = env_secret.encode()
    return {"ATS": SourceRegistration("ATS", frozenset({"1"}), ATS_FIELD_MAPPING, secrets.get("ATS"))}
