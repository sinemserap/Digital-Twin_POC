#!/usr/bin/env python3
"""Load the synthetic F03 fixtures into a running EDT PoC service through its public contracts.

Step 1  POST /imports/ATS            (F08 JSONL import -> F01)   offered_role, offer_status, start_date
Step 2  POST /subjects               (F01 account binding)        candidate account -> subject
Step 3  POST /subjects/{id}/claims   (F01 mutation contract)      org_unit, manager_or_sponsor,
                                                                   preboarding_dependency_status (synthetic HR/ITSM)
Nothing here writes to the graph: F03 only sees this data after POST /graph/v1/projections/rebuild.

Usage: python scripts/load_f03_fixtures.py [BASE_URL]   (default http://localhost:8000)
Prints a JSON map of source_person_ref -> subject_id for the demo script.
"""
import base64
import hashlib
import json
import sys
import urllib.error
import urllib.request
from pathlib import Path

BASE = (sys.argv[1] if len(sys.argv) > 1 else "http://localhost:8000").rstrip("/")
ROOT = Path(__file__).resolve().parents[1]
FIX = json.loads((ROOT / "fixtures/f03/synthetic_context_v1.json").read_text())
TENANT = FIX["tenant_id"]


def call(method, path, body=None, *, account, roles, content_type="application/json", raw=None):
    data = raw if raw is not None else (json.dumps(body).encode() if body is not None else None)
    req = urllib.request.Request(BASE + path, data=data, method=method, headers={
        "Content-Type": content_type, "X-Tenant-ID": TENANT, "X-Account-ID": account, "X-Roles": roles,
        "X-Correlation-ID": "f03-fixture-load"})
    try:
        with urllib.request.urlopen(req) as resp:
            return resp.status, json.loads(resp.read() or b"null")
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read() or b"null")


def main():
    status, report = call("POST", "/imports/ATS", raw=(ROOT / "fixtures/f03/offer-update-f03.jsonl").read_bytes(),
                          account="data-admin", roles="data_administrator", content_type="application/x-ndjson")
    print(f"F08 import: HTTP {status} status={report.get('status')} counts={report.get('counts')}", file=sys.stderr)
    subjects = {}
    for candidate in FIX["candidates"]:
        ref = candidate["source_person_ref"]
        status, body = call("POST", "/subjects", {"source_system": "ATS", "source_person_ref": ref,
                                                   "authenticated_account_id": candidate["account_id"]},
                            account="ats-sync", roles="source_service")
        subjects[ref] = body["subject_id"]
        for c in candidate["claims"]:
            idem = f"f03-fixture:{ref}:{c['predicate']}:{c['source']}:{c['version']}"
            evidence = json.dumps({"fixture": "f03", "source": c["source"], "record_id": c["record_id"],
                                   "version": c["version"], "value": c["value"]}, sort_keys=True).encode()
            mutation = {"idempotency_key": idem, "predicate": c["predicate"], "value": c["value"],
                        "claim_class": "authoritative", "record_kind": "canonical_claim",
                        "source": {"system": c["source"], "record_id": c["record_id"], "authority": "authoritative",
                                   "version": c["version"]},
                        "evidence": {"evidence_id": "ev-" + hashlib.sha256(idem.encode()).hexdigest()[:30],
                                     "hash": hashlib.sha256(evidence).hexdigest(),
                                     "content_base64": base64.b64encode(evidence).decode()},
                        "purpose_id": "source_sync", "valid_from": "2026-10-01T00:00:00Z", "valid_to": None,
                        "observed_at": "2026-10-01T00:00:00Z", "retention_rule": "preboarding_context",
                        "confidence_band": "confirmed"}
            status, result = call("POST", f"/subjects/{subjects[ref]}/claims", mutation,
                                  account="hr-sync" if c["source"] == "HR" else "itsm-sync", roles="source_service")
            print(f"  {ref} {c['predicate']:<30} HTTP {status} status={result.get('status', result)}", file=sys.stderr)
    print(json.dumps(subjects, indent=2))


if __name__ == "__main__":
    main()
