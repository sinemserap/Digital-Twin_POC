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


## F08 controlled source import (US40858 Part 1)

Implements the updated F08 design document (US40858_EDT_F08_Controlled_Source_Import_Part_1)
against the F01 Part 1 contract: one synthetic ATS-like source, JSON Lines schema v1,
file upload only, delta/upsert semantics (absence from a file never changes a fact),
mandatory monotonic `source_version`, atomic multi-claim submission through F01 and no
withdrawal cascade. The PoC decisions D1–D11 of the design are adopted as written.

### File contract (schema v1)

`fixtures/offer-update-v1.schema.json` is generated from `app/import_schema.py` and a
test keeps both in sync. The first JSONL line is the header
(`schema_version`, `source_system_id`, `tenant_id`, `snapshot_id`, `generated_at`,
`record_count`, `content_hash`, optional `signature`); every other line is one record
(`tenant_id`, `source_record_id`, `source_person_ref`, `source_version`,
`source_updated_at`, `event_type`, `role_ref`, `start_date`, `offer_status`,
`effective_from`). `content_hash` is SHA-256 of the exact record lines joined with LF plus
one trailing LF, header excluded. `signature` is HMAC-SHA256 of `content_hash` with the
source's signing secret and is required and verified only when the source registry has
a secret (`IMPORT_SIGNING_SECRET_ATS` or the `source_registry` argument of `create_app`).
CSV is not supported. `event_type` is `offer_accepted` or `offer_updated`.

`app/source_registry.py` is the registry entry: the ATS source may assert
`offer_status`, `offered_role` (from `role_ref`) and `start_date` only. `work_location`,
`manager_ref` or any other field rejects the entire record as `NOT_AUTHORITATIVE`; F08
does not widen ATS authority. Subject binding is deterministic through
`source_person_ref`; schema v1 carries no account field. A subject created by an import
has no candidate account until `/subjects` asserts one for the same
`source_person_ref` (first assertion binds; until then candidate self-view returns 404).

### Processing flow

Upload with `POST /imports/ATS`, `Content-Type: application/x-ndjson` and the mocked
identity headers using `X-Roles: data_administrator` (a candidate role is refused). The
import-context tenant comes from the identity, never from the body. Limits are 256 KiB
and 100 records; the optional malware scanner hook (`malware_scanner` argument of
`create_app`) runs before parsing and the PoC default performs no scan.

1. **File gate**, in design order, each rejecting the whole file with HTTP 422 and an
   `ImportFileRejected` event carrying only the file hash: `FILE_SIZE_INVALID`,
   `FILE_REJECTED_MALWARE`, `FILE_STRUCTURE_INVALID` (malformed UTF-8/JSON, duplicate
   keys, unknown header fields), `SOURCE_NOT_REGISTERED`, `FILE_TENANT_MISMATCH`,
   `SCHEMA_VERSION_UNSUPPORTED`, `FILE_INTEGRITY_FAILED` (record count, content hash,
   configured signature, future `generated_at`). No run, evidence or claim state exists
   after a gate rejection.
2. **Evidence** (§1.8): the accepted original file is stored through F01 as file-level
   evidence encrypted under its own file key, with a manifest of file hash, upload hash and
   per-position record hashes (`import_file_evidence`). Every accepted record becomes one
   canonical per-record snapshot (canonical record, file hash, snapshot id, source record
   id/version, record hash, line position) stored under the subject key; all mapped claims
   of the record reference that snapshot, never the shared raw file.
3. **Per record** (§1.3): the whole record is validated, record identity and idempotency
   keys are computed, the decision table is applied and the mapped claim set is submitted
   to `ClaimService.submit_import_record`, which resolves/creates the binding, writes the
   snapshot and commits all three claims in one transaction. A failure of any mapped claim
   rolls back the subject, binding, snapshot reference, claims, ledger entries and receipts
   of that record; neighbouring records continue.
4. **Outcome persistence** (§1.9): `import_run` (keyed by tenant + source + snapshot +
   content hash with status, attempt count and timestamps), `import_record_outcome` (one
   durable row per position with identity/idempotency keys, outcome, reason code and F01
   references), `import_attempt` (user, correlation id, outcome per upload) and
   `import_event` (`ImportFileRejected`, `ImportRecordHeld`, `BindingIntegrityAlert`).

### Decision table and report

Record outcomes are mutually exclusive: `accepted` (`ACCEPTED`, or `FUTURE_VALID` when
`effective_from` is in the future; such a claim is stored but `/twin` reports
`not_yet_valid` until the valid time), `superseded` (`SUPERSEDED`: higher version
supersedes the current same-source claims), `historical` (`LATE_HISTORICAL`: lower unseen
version stored with its own valid time, current state unchanged), `duplicate`
(`DUPLICATE`: exact idempotency key already processed, original F01 references returned,
no F01 call), `contested` (`VERSION_CONFLICT`: same record identity with different
canonical content; value-conflicting claims are contested in F01 and no conflicting value
is usable as current), `held_for_review` (`UNBOUND_SUBJECT`: `offer_updated` without a
binding; only run metadata, an evidence reference to the file-level evidence and
`retention_rule=import_hold_short_review` are stored, no subject or claim) and `rejected`
(`WRONG_TENANT`, `INVALID_RECORD`, `NOT_AUTHORITATIVE`, `BINDING_INTEGRITY_ERROR` with an
integrity alert when an offer identity would map to a second subject, plus the F01 gates
`RESTRICTED`, `ERASED` and `IDEMPOTENCY_CONFLICT`). Quarantine is not used by F08.

Record identity is `tenant_id + source_system_id + source_record_id + source_version`;
the exact-record idempotency key is SHA-256 of that identity plus the canonical content
hash. `source_version` is the only ordering key; `source_updated_at` maps to
`observed_at`, `effective_from` to `valid_from`, and ingestion time is server generated.

The run report returns run fields (`run_id`, `source_system_id`, `tenant_id`,
`snapshot_id`, `file_hash`, `started_at`, `completed_at`, `status`, `total_records`,
`attempt_count`, `file_evidence_id`), `counts` for the seven outcomes and per-record
outcomes with position, record hash, source record id/version, reason code and F01
references (subject id, claim ids/statuses, ledger sequence/hash, snapshot evidence id).
Reports, events and errors never contain candidate field values.

### Idempotency, resume and concurrency

A completed exact file re-import is logged as another attempt and returns the stored
report with `duplicate_file=true`; no record is resubmitted to F01. An incomplete run
(for example a crash after an F01 commit but before the F08 outcome was written) resumes
the same `import_run`: positions with a durable outcome are skipped and a record whose F01
receipt already exists reuses that result and reports as a clean acceptance. Parallel
imports of the same file are serialized per tenant and source by a PostgreSQL session
advisory lock (SQLite demo mode: one process, thread lock) and converge on one run.

### Erasure and retention

File-level evidence uses `retention_rule=preboarding_source_evidence_file`; subject
snapshots inherit the claim/evidence rule; held records use `import_hold_short_review`.
Part 1 stores the rule only. `ClaimService.crypto_shred_subject` is the erasure hook for
F02: it destroys the subject key and the key of every shared import file containing that
subject, so the raw multi-subject file is no longer recoverable while other subjects keep
their own subject-key snapshots and the manifest remains as accountability metadata.
`destroy_import_file_key` is the retention-end hook for F07. No scheduler is added.

### Canonical events (AC8)

F01 appends the named canonical events to the subject's hash-chained ledger
(`event_ledger.event_type`): `EvidenceAcquired` when an evidence object is stored (once
per per-record snapshot on the import path), then exactly one of `ClaimAccepted`
(current or historical) or `ClaimProposed` (recorded but contested, so not accepted as
current) per claim, followed by `ClaimSuperseded` for every same-source claim the new
version supersedes and `ClaimContested` for every claim involved in a same-version or
cross-source value conflict. Each claim's `event_sequence`/`record_hash` points at its
own ClaimAccepted/ClaimProposed entry; status-change events reference the affected claim
and the claim that caused the change. `verify_ledger` covers all event kinds. F08 emits
`ImportFileRejected`, `ImportRecordHeld` and `BindingIntegrityAlert` in its own
`import_event` table.

**Conflict reading (AC7):** for a same-source, same-version record with different
content, only the predicates whose values differ are contested (both the earlier and the
new claim); identical values in the same record are accepted as historical. The record
outcome is `contested` / `VERSION_CONFLICT` either way. T06 and T20 pin this reading; if
"both records contested" is meant to contest every claim of both records, that is a
one-line change in F01's conflict branch to be agreed with the product owner.

### Write boundary (AC8)

The adapter is constructed with `F01ImportContract`, which exposes only
`store_file_evidence` and `submit_record`, and, when `IMPORT_DATABASE_URL` (or the
`import_database_url` argument of `create_app`) is set, with its own database engine and
login role. `migrations/f08_adapter_role.sql` holds the grants for that role: usage on
the schema and select/insert/update on the four F08 tables only, nothing on subject,
binding, claim, ledger, receipt, audit or file-evidence tables. The PostgreSQL-only test
`test_f08_adapter_role_cannot_write_canonical_state` creates a disposable role, applies
that file, runs a complete import through the app with the adapter on the restricted
role, and asserts that raw SQL on that connection is denied by PostgreSQL for claim,
subject, event_ledger, mutation_receipt, import_file_evidence and audit_log while
import tables remain writable. In-process, the adapter's session factory additionally
refuses to flush any non-F08 table (defence in depth, and the only guard in the SQLite
demo, which shares one file database). Known limitation: without `IMPORT_DATABASE_URL`
the adapter shares the F01 engine and credentials.

### Outside this story: source freshness (early work for US41282)

`GET /imports/ATS/freshness` (data-administrator role) returns `missing`, `fresh` or
`stale` from completed runs with at least one canonical outcome, with a seven-day
threshold and `task_completion=unknown`. Stale/missing-source visibility belongs to
US41282 (design D2), so this endpoint is not evidence for US40858; it is kept as early
US41282 work and is covered by two tests only.

### Migrations and tests

Apply `migrations/003_controlled_import.sql` after 001/002. It replaces the earlier,
never-merged draft of 003: it makes `subject_binding.authenticated_account_id` nullable,
adds the F01 file-evidence tables and the four F08 operational tables. Fresh local
startup creates them; the opt-in PostgreSQL tests apply all three actual migrations.

`tests/test_import.py` implements design scenarios T01–T20 by name (clean import, file
and record duplicates, higher/late/conflicting versions, tenant/source/schema/integrity
gates including a configured signature, unbound hold with `ImportRecordHeld`, mixed
files, non-authoritative fields, atomic record failure, crash/resume, parallel imports,
direct-write denial, file/subject evidence linkage with erasure, and the report over
`fixtures/offer-update-v1-mixed.jsonl`) plus canonical event sequences, future valid
time, binding integrity alerts, account binding after import, restricted/erased subjects
and restart. Run `python -m pytest` for SQLite and add `--postgres-url` for the migrated
PostgreSQL run, which adds the restricted-role boundary test.

Local validation on 7 October 2026: SQLite **78 passed** (six PostgreSQL-only cases
skipped); migrated PostgreSQL 16 **84 passed** in both UTC and America/New_York sessions.
The same PostgreSQL workflow runs on every pull request. Not covered by this slice: Azure
Blob/Key Vault execution, a real malware scanner, F02/F07 orchestration of the retention
and erasure hooks, API/event adapters and offer withdrawal.


## F03 Operational Relationship Graph — Part 1 (US40852)

A deployed graph service that projects accepted F01 canonical claims into typed nodes and
edges with provenance, serves exactly two server-side query templates, and can be dropped and
rebuilt deterministically. It never writes canonical data: the service receives only the
read-only `F01ProjectionContract` (the F03 counterpart of `F01ImportContract`) and, in
deployment, its own database identity (`GRAPH_DATABASE_URL`, grants in
`migrations/f03_graph_role.sql`: read-only on `subject`, `subject_binding`, `event_ledger`;
read-write on the five `graph_*` tables only, no access to `claim`).

**Ontology (`app/graph/ontology.py`) — PROPOSED, pending Design Authority (`docs/F03_decisions.md`, D-01).**
No six-node/seven-relationship ontology exists in EDT v3.1, F01 or F08; the five relationship
names in F01 §1.1 "Needed by" are the only agreed input. The registry is closed (exactly six node
types and seven edge types; anything else is rejected) and the projection, templates and tests
are registry-driven, so an approved change is a change to that file only.

| Node | Key | Source | Edge | From → To | F01 predicate (authority) |
|---|---|---|---|---|---|
| Person | subject_id | F01 subject | OFFERED_ROLE | Person → Role | offered_role (ATS, via F08) |
| Role | role_ref | offered_role | IN_UNIT | Person → OrgUnit | org_unit (HR/directory) |
| OrgUnit | unit_ref | org_unit | ROLE_IN_UNIT | Role → OrgUnit, subject-scoped | org_unit (HR/directory) |
| Contact | contact_ref | manager_or_sponsor | HAS_CONTACT | Person → Contact | manager_or_sponsor (HR/directory) |
| Task | task_ref | preboarding_dependency_status | HAS_DEPENDENCY | Person → Task | preboarding_dependency_status (ITSM) |
| Evidence | subject:evidence_id | claim.evidence_* | BLOCKED_BY | Task → Task (+reason) | preboarding_dependency_status (ITSM) |
| | | | EVIDENCED_BY | Person → Evidence | the contributing claim |

Every edge carries `claim_id`, `event_id`/`event_type`/`event_sequence`/`event_hash` of the
ClaimAccepted ledger entry, `source_system`, `source_record_id`, `source_version`,
`evidence_id`/`evidence_hash`/`evidence_uri`, `valid_from`/`valid_to`, `projection_version` and
`allowed_purposes`, plus the owning `subject_id`. Only `record_kind=canonical_claim`,
`claim_class=authoritative`, `status=current` claims from the predicate's authoritative source,
valid at the projection `as_of` instant and with exactly one current claim per predicate are
projected; everything else is recorded in `graph_rejection` with a reason code and no values.

### API (`/graph/v1`, OpenAPI at `/openapi.json`)

```bash
# full deterministic rebuild for the caller's tenant (role graph_administrator)
curl -s -X POST localhost:8000/graph/v1/projections/rebuild -H 'X-Tenant-ID: demo' -H 'X-Account-ID: admin' -H 'X-Roles: graph_administrator'
# Template A: role context (Person -OFFERED_ROLE-> Role -ROLE_IN_UNIT-> OrgUnit, plus IN_UNIT / HAS_CONTACT context)
curl -s 'localhost:8000/graph/v1/subjects/{id}/role-context?purpose=candidate_self_view' -H 'X-Tenant-ID: demo' -H 'X-Account-ID: candidate-001' -H 'X-Roles: candidate'
# Template B: blocker explanation (Person -HAS_DEPENDENCY-> Task -BLOCKED_BY-> Task + PreboardingDependencyBlocked event)
curl -s 'localhost:8000/graph/v1/subjects/{id}/blocker-explanation?purpose=preboarding_support' -H 'X-Tenant-ID: demo' -H 'X-Account-ID: support-1' -H 'X-Roles: support'
# dry-run re-projection compared with the active projection (AC10 evidence)
curl -s -X POST localhost:8000/graph/v1/projections/verify -H 'X-Tenant-ID: demo' -H 'X-Account-ID: admin' -H 'X-Roles: graph_administrator'
```

Only `purpose` is accepted as a parameter; any other query parameter, any request body and any
unregistered template path is refused (422/404) and audited. Purpose is validated against the
F01 purpose registry and the caller's role (a candidate cannot request `preboarding_support`),
then against the template, then the subject gate (tenant, candidate binding, current
restriction, erasure) runs on read-only canonical tables, and finally every hop re-checks
tenant, subject and purpose on the edge and both nodes. Foreign-tenant, other-candidate and
unknown subjects all return the same `404 {"detail": "subject not found"}`. Responses carry
`stale=true` when the subject's ledger has moved past the projected watermark; incremental
invalidation itself is US41278.

Every request is written to `graph_query_audit` (actor, tenant, subject, purpose, template,
outcome, HTTP status, request hash, response digest, returned edge ids, correlation id); the
F01 projection read is audited in `audit_log` under the `f03-projection` identity.

### Run, test, demonstrate

```bash
docker compose up --build            # postgres (migrations 001-004 + roles) and the api on :8000
BASE_URL=http://localhost:8000 scripts/demo_f03.sh   # F08 import -> F01 claims -> rebuild -> both templates -> denials -> identical rebuild
python -m pytest tests/test_graph.py                  # G01-G34 on SQLite; add --postgres-url for the migrated PostgreSQL run
```

Local validation on 8 October 2026: SQLite **122 passed** (F01 78 + F03 44; 7 PostgreSQL-only
skipped); migrated PostgreSQL 16.15 **129 passed** in both UTC and America/New_York sessions,
including the F03 role-boundary test; `scripts/demo_f03.sh` executed against uvicorn with the
three database identities (`edt`, `edt_f08`, `edt_f03`) — identical graph hash across rebuilds.
Not covered: deployment to the Azure PoC environment (Dockerfile/compose provided; no
credentials here), Apache AGE (DA-10 open), US41278 incremental invalidation.
