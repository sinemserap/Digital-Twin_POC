#!/usr/bin/env python3
"""Pretty-print an F03 template response from stdin (used by scripts/demo_f03.sh)."""
import json
import sys


def main():
    d = json.load(sys.stdin)
    print(f"result: {d['result']} | stale: {d['stale']} | denied_hops: {d['denied_hops']} | projection: {d['projection_version']}")
    for path in d.get("paths", []):
        for h in path["hops"]:
            pr = h["edge"]["provenance"]
            print(f"  {h['from']['type']} -{h['edge']['type']}-> {h['to']['type']} {h['to']['properties']}")
            print(f"      claim={pr['claim_id']} event={pr['event_type']}#{pr['event_sequence']} ({pr['event_id']})")
            print(f"      source={pr['source_system']} v{pr['source_version']} valid_from={pr['valid_from']} "
                  f"evidence={pr['evidence']['evidence_id']} sha256={pr['evidence']['evidence_hash'][:16]}…")
        if "blocking_event" in path:
            print(f"      reason: {path['reason_code']} — {path.get('reason')}")
            print(f"      blocking_event: {path['blocking_event']}")
    for h in d.get("context", []):
        print(f"  context: {h['from']['type']} -{h['edge']['type']}-> {h['to']['type']} {h['to']['properties']} "
              f"(claim {h['edge']['provenance']['claim_id'][:8]}…)")
    if d.get("exclusions"):
        print("  exclusions:", d["exclusions"])
    print("explanation:")
    for line in d["explanation"]:
        print("  -", line)
    print("audit:", d["audit"])


if __name__ == "__main__":
    main()
