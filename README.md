# Employee Digital Twin — Claim and Evidence Service

Part 1 of the EDT PoC is a deliberately small trusted core. It imports synthetic candidates, accepts only the eleven registered facts, preserves encrypted claim history and evidence, and exposes a purpose-controlled current-twin view. A bounded F01 extension adds auditor-only bitemporal reconstruction. It contains no AI, recommendations, graph, real ATS/HR connector, or candidate UI.

## Security and trust boundaries

* **One writer:** this service owns the database credentials and is the only component that writes canonical claims.
* **Tenant from identity:** the temporary local auth adapter reads trusted identity headers; request bodies have no tenant field. Replace `authenticated_identity` with Entra JWT validation without changing the authorization/service layer.
* **Purpose and role:** `source_sync` is mutation-only for `source_service`; candidate self-view, support, and auditor reads have distinct roles. Prohibited evaluation, monitoring, marketing, and cross-customer training purposes are explicitly denied.
* **Candidate isolation:** candidate-role reads additionally require an account binding. Cross-tenant and cross-candidate misses both return 404.
* **Encryption:** values and evidence use AES-256-GCM with a random subject data-encryption key. The production adapter wraps it with an Azure Key Vault RSA key. The development adapter is synthetic-data-only. Ledger hashes cover ciphertext, canonical metadata, and the previous hash.
* **Evidence:** the Azure adapter writes only encrypted bytes to a private Blob container. The local adapter has identical encrypt/verify semantics. Evidence reads pass through this service and verify SHA-256 after decryption.

## Run locally

```bash
python -m venv .venv && . .venv/bin/activate
pip install -e '.[test]'
docker compose up -d postgres
python -m app
```

Authentication is mocked locally with `X-Tenant-ID`, `X-Account-ID`, and `X-Roles`. Every request may carry `X-Correlation-ID`; otherwise the server creates one.

### Demo

Import the synthetic candidate:

```bash
curl -s localhost:8000/subjects -X POST \
  -H 'content-type: application/json' -H 'X-Tenant-ID: demo' \
  -H 'X-Account-ID: ats-sync' -H 'X-Roles: source_service' \
  -d '{"source_system":"ATS","source_person_ref":"synthetic-001","authenticated_account_id":"candidate-001"}'
```

Then POST a claim to `/subjects/{id}/claims`; see `mutation()` in `tests/test_acceptance.py` for a complete payload. Read it with:

```bash
curl -s 'localhost:8000/subjects/{id}/twin?purpose=candidate_self_view' \
  -H 'X-Tenant-ID: demo' -H 'X-Account-ID: candidate-001' -H 'X-Roles: candidate'
```

Configure `AZURE_BLOB_CONNECTION_STRING` and `AZURE_BLOB_CONTAINER` to select Azure Blob Storage. `AzureKeyVaultProtector` is injectable at application construction; production should build it with `DefaultAzureCredential` and the vault key ID. The service managed identity alone should receive Blob Data Contributor/Reader and Key Vault crypto permissions. No user receives raw Blob authorization.

## Data behavior

The PostgreSQL reference migrations are `migrations/001_initial.sql` and `migrations/002_subject_restriction.sql`. **For an existing Part 1 database, apply 002 once before starting this version**; SQLAlchemy `create_all` only creates missing tables and cannot add the new column. Fresh local databases created by the app already include it. `(tenant_id, source_system, source_person_ref)` prevents duplicate twins and `(tenant_id, idempotency_key)` serializes mutation retries. Higher same-source versions supersede current claims while retaining all ledger events. Older versions remain historical. Same-version disagreement and different-source disagreement are retained and returned as `contested`; Part 1 intentionally does not resolve them.

Run the fast SQLite acceptance suite with `python -m pytest`. PostgreSQL-only cases skip unless an explicit test database URL is supplied; runtime defaults to PostgreSQL.

### PostgreSQL acceptance

Use a disposable PostgreSQL 16 database. The test role needs permission to create
schemas. Each test creates a uniquely named schema, executes the actual
`001_initial.sql` and `002_subject_restriction.sql` migrations, and drops only
that schema afterwards. Existing application tables are not reset.

```bash
python -m pytest --postgres-url postgresql+psycopg://edt:edt@localhost:5432/edt_test
python -m pytest --postgres-url postgresql+psycopg://edt:edt@localhost:5432/edt_test --postgres-timezone America/New_York
```

These commands run the same 30 Part 1/F01c acceptance cases on PostgreSQL,
including late corrections, retained conflicts/evidence, current restriction
and erasure gates before payload access, and post-erasure restart. Five
PostgreSQL-only cases add:

* Upgrade of populated Part 1 tables with migration 002, preserving encrypted
  claims, ledger hashes, bindings, keys and replay receipts; default false and
  NOT NULL restriction state; denial after restriction and restart.
* Actual `timestamptz` column types, both instants of a DST repeated hour,
  equivalent offsets, and one-microsecond validity/knowledge boundaries.
* Forced concurrent receipt inserts for identical and changed retries:
  one accepted claim, receipt and ledger event; identical responses or 409.
* Forced concurrent source imports: one subject/binding and no orphan subject.

The populated upgrade fixture seeds genuine records via the existing API,
removes the new restriction column to restore the Part 1 table shape, then
applies migration 002 and compares the retained rows before/after.
`.github/workflows/postgres-acceptance.yml` repeats acceptance on PostgreSQL 16
with UTC and America/New_York sessions and runs the SQLite regression suite.

Local validation on 6 October 2026: PostgreSQL 16.15 / Python 3.12, **35 passed**
in each timezone; SQLite **30 passed** (five PostgreSQL-only cases skipped).
No production parity defect was found, so application code and SQL migrations
were left unchanged. Evidence and key protection use the existing local test
adapters; Azure integration was not exercised.

## Bitemporal reconstruction (F01c)

The F01 baseline in `EDT_v3-1_Features.xlsx` (finish: 23 October 2026) requires both validity-time and knowledge-time reconstruction, one late correction, retained conflicting evidence, and current restrictions/deletion applied to historical queries.

`GET /subjects/{subject_id}/twin/history` requires all three query parameters:

* `valid_at`: the instant when the fact applies in the source world.
* `system_at`: the server-ingestion cutoff for what EDT knew.
* `purpose=audit_reconstruction`: requires the existing `auditor` role. Tenant and candidate-account checks still apply.

Both timestamps require a timezone (`Z` or an explicit offset). Example:

```bash
curl -sG 'localhost:8000/subjects/{id}/twin/history' \
  -H 'X-Tenant-ID: demo' -H 'X-Account-ID: auditor-001' -H 'X-Roles: auditor' \
  --data-urlencode 'purpose=audit_reconstruction' \
  --data-urlencode 'valid_at=2026-10-01T00:00:00Z' \
  --data-urlencode 'system_at=2026-10-05T00:00:00Z'
```

Selection is `ingested_at <= system_at` and `valid_from <= valid_at < valid_to`, with a null end meaning no upper bound. `observed_at` is source information, never the knowledge cutoff. Supersession is derived from retained claims at these two instants, ignoring their mutable current `status`: for each predicate and source system, keep the highest version covering the selected valid instant. A correction only overrides that source within its own valid interval. Lower versions remain usable outside that interval and before the correction became known. Source versions are not compared across different source systems. Stored timestamps are normalized to UTC; legacy naive Part 1 timestamps are treated as UTC.

For example, version 1 is ingested on 1 October; version 2 is ingested on 5 October but valid from 15 September. A query valid on 1 October returns version 1 with a 4 October knowledge cutoff and version 2 with a 5 October cutoff. A query valid on 14 September still returns version 1 with the later cutoff.

Each predicate returns `state`, `conflict_state`, and the supporting `claims`. A known result also has `value`. Disagreeing claims at the highest applicable same-source version, or across sources, return `state=unknown`, `reason=contested`, `conflict_state=unresolved`, and all competing values with their evidence. Agreement retains all supporting references. Each claim includes its ID, source/version/authority, validity and ingestion dates, evidence ID/URI/hash, and ledger sequence/hash. Later corrections do not erase earlier disputes. This endpoint does not introduce a manual dispute/resolution workflow or rewrite claims or ledger entries. Successful reconstruction and access denials use the existing audit log and correlation ID.

The existing claim-mutation request/response and `/twin` successful response contracts remain unchanged. The history result is a separate projection and does not inherit today's sticky contested/superseded labels.

### Current rights and crypto-shredding

The minimal rights hook is the current `subject.restricted` flag (default false); there is no new rights-management API. Subject authorization checks it before selecting claims, unwrapping keys, or reading evidence. A restricted subject returns 403. A missing wrapped subject key or key reference returns 410. These gates also protect current-twin, evidence, and mutation/retry paths. There is no historical key lookup, plaintext cache, or fallback to ledger payloads.

Tests set the current flag or clear the wrapped key/key reference directly as controlled fixtures. They verify that an earlier historical timestamp cannot bypass current rights, payload selection/decryption never starts, and a fresh service still denies access with the encrypted claims, evidence and hash-verifiable ledger retained. This is protection against reconstruction from retained ciphertext after key removal; restoring an old backup containing the wrapped key would undo that removal. Recovery must reapply current restrictions and erasure before enabling reads. Backup/key lifecycle and full cross-store deletion remain outside this bounded change.

Acceptance coverage includes late corrections, both timestamp cutoffs, inclusive/exclusive validity boundaries, timezone offsets, older late arrivals, same-version and different-source conflicts, evidence references, access isolation, audit records, current rights and post-erasure restart. Run `pytest` for this coverage and the original Part 1 checks.
