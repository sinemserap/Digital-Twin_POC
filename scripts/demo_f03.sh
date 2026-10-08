#!/usr/bin/env bash
# Repeatable F03 Part 1 demonstration (US40852 Part G) against a running EDT PoC service.
#   1. canonical F01 input (F08 JSONL import + synthetic HR/ITSM claims through the F01 mutation contract)
#   2. F03 projection (full rebuild) and the active projection summary
#   3. authorized role-context query (candidate self-view, two hops with provenance)
#   4. blocker explanation (support purpose, PreboardingDependencyBlocked event reference)
#   5. rejected unauthorized access (other candidate, foreign tenant, prohibited purpose, arbitrary query)
#   6. deterministic rebuild (second rebuild + verify -> identical graph hash)
# Usage: BASE_URL=http://localhost:8000 scripts/demo_f03.sh   (requires python3 and curl; jq optional)
set -euo pipefail
BASE_URL="${BASE_URL:-http://localhost:8000}"
HERE="$(cd "$(dirname "$0")" && pwd)"
TENANT="tenant-a"
pretty() { if command -v jq >/dev/null 2>&1; then jq .; else python3 -m json.tool; fi; }
hdr() { H=(-H "X-Tenant-ID: $1" -H "X-Account-ID: $2" -H "X-Roles: $3" -H "X-Correlation-ID: demo-f03"); }
step() { printf '\n\033[1;34m== %s ==\033[0m\n' "$1"; }

step "0. Service health"
curl -sf "$BASE_URL/health" | pretty

step "1. Canonical F01 input: F08 import + synthetic HR/ITSM claims (nothing touches the graph)"
SUBJECTS_JSON="$(python3 "$HERE/load_f03_fixtures.py" "$BASE_URL")"
echo "$SUBJECTS_JSON" | pretty
S1="$(echo "$SUBJECTS_JSON" | python3 -c 'import json,sys; print(json.load(sys.stdin)["synthetic-f03-001"])')"
S2="$(echo "$SUBJECTS_JSON" | python3 -c 'import json,sys; print(json.load(sys.stdin)["synthetic-f03-002"])')"

step "2. F03 projection: full deterministic rebuild (graph_administrator)"
hdr $TENANT graph-admin graph_administrator; R1="$(curl -sf -X POST "$BASE_URL/graph/v1/projections/rebuild" "${H[@]}")"
echo "$R1" | pretty
H1="$(echo "$R1" | python3 -c 'import json,sys; print(json.load(sys.stdin)["graph_hash"])')"
hdr $TENANT graph-admin graph_administrator; curl -sf "$BASE_URL/graph/v1/projections/current" "${H[@]}" \
  | python3 -c 'import json,sys; d=json.load(sys.stdin); print(json.dumps({k:d[k] for k in ("node_count","edge_count","rejected_count","node_types","edge_types","rejections")}, indent=1))'

step "3. Template A — role context, candidate self-view (two hops, provenance on every edge)"
hdr $TENANT candidate-001 candidate; curl -sf "$BASE_URL/graph/v1/subjects/$S1/role-context?purpose=candidate_self_view" "${H[@]}" \
  | python3 "$HERE/f03_print.py"

step "4. Template B — blocker explanation, preboarding_support (PreboardingDependencyBlocked reference)"
hdr $TENANT support-001 support; curl -sf "$BASE_URL/graph/v1/subjects/$S1/blocker-explanation?purpose=preboarding_support" "${H[@]}" \
  | python3 "$HERE/f03_print.py"

step "5. Rejected unauthorized access"
hdr $TENANT candidate-001 candidate; printf 'candidate-001 asks for candidate-002 subject      -> HTTP %s\n' "$(curl -s -o /dev/null -w '%{http_code}' "$BASE_URL/graph/v1/subjects/$S2/role-context?purpose=candidate_self_view" "${H[@]}")"
hdr tenant-x support-9 support; printf 'foreign tenant (tenant-x) support asks for S1       -> HTTP %s\n' "$(curl -s -o /dev/null -w '%{http_code}' "$BASE_URL/graph/v1/subjects/$S1/role-context?purpose=preboarding_support" "${H[@]}")"
hdr $TENANT candidate-001 candidate; printf 'candidate self-assigns preboarding_support purpose  -> HTTP %s\n' "$(curl -s -o /dev/null -w '%{http_code}' "$BASE_URL/graph/v1/subjects/$S1/role-context?purpose=preboarding_support" "${H[@]}")"
hdr $TENANT support-001 support; printf 'prohibited purpose performance_evaluation           -> HTTP %s\n' "$(curl -s -o /dev/null -w '%{http_code}' "$BASE_URL/graph/v1/subjects/$S1/role-context?purpose=performance_evaluation" "${H[@]}")"
hdr $TENANT candidate-001 candidate; printf 'arbitrary query parameter (cypher=...)              -> HTTP %s\n' "$(curl -s -o /dev/null -w '%{http_code}' "$BASE_URL/graph/v1/subjects/$S1/role-context?purpose=candidate_self_view&cypher=MATCH%%20(n)%%20RETURN%%20n" "${H[@]}")"
hdr $TENANT candidate-001 candidate; printf 'unregistered template (shortest-path)               -> HTTP %s\n' "$(curl -s -o /dev/null -w '%{http_code}' "$BASE_URL/graph/v1/subjects/$S1/shortest-path?purpose=candidate_self_view" "${H[@]}")"
hdr $TENANT candidate-001 candidate; printf 'rebuild by a candidate                              -> HTTP %s\n' "$(curl -s -o /dev/null -w '%{http_code}' -X POST "$BASE_URL/graph/v1/projections/rebuild" "${H[@]}")"

step "6. Deterministic rebuild: drop + rebuild from the same canonical state, then verify"
AS_OF="$(echo "$R1" | python3 -c 'import json,sys; print(json.load(sys.stdin)["as_of"])')"
hdr $TENANT graph-admin graph_administrator; R2="$(curl -sf -X POST "$BASE_URL/graph/v1/projections/rebuild" -H 'Content-Type: application/json' -d "{\"as_of\": \"$AS_OF\"}" "${H[@]}")"
H2="$(echo "$R2" | python3 -c 'import json,sys; print(json.load(sys.stdin)["graph_hash"])')"
echo "first  graph_hash: $H1"
echo "second graph_hash: $H2"
[ "$H1" = "$H2" ] && echo "IDENTICAL: yes" || { echo "IDENTICAL: NO"; exit 1; }
hdr $TENANT graph-admin graph_administrator; curl -sf -X POST "$BASE_URL/graph/v1/projections/verify" "${H[@]}" | pretty
printf '\nDemo complete.\n'
