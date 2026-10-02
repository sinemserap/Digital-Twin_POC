# Employee Digital Twin — Claim and Evidence Service

Part 1 of the EDT PoC is a deliberately small trusted core. It imports synthetic candidates, accepts only the eleven registered facts, preserves encrypted claim history and evidence, and exposes a purpose-controlled current-twin view. It contains no AI, recommendations, graph, real ATS/HR connector, or candidate UI.

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

The PostgreSQL reference migration is `migrations/001_initial.sql`. `(tenant_id, source_system, source_person_ref)` prevents duplicate twins and `(tenant_id, idempotency_key)` serializes mutation retries. Higher same-source versions supersede current claims while retaining all ledger events. Older versions remain historical. Same-version disagreement and different-source disagreement are retained and returned as `contested`; Part 1 intentionally does not resolve them.

Run all acceptance tests with `pytest`. Tests use SQLite only as a fast isolated SQLAlchemy test backend; runtime defaults to PostgreSQL.
