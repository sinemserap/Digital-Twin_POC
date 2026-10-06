-- F08 controlled source import (US40858 Part 1) and the small F01 extensions it depends on.
-- Apply after 001 and 002. Replaces the earlier draft of this migration, which created a
-- single JSON-report import_run table that was never merged.

-- F01: subjects created by a source import have no account yet; /subjects binds it later.
ALTER TABLE subject_binding ALTER COLUMN authenticated_account_id DROP NOT NULL;

-- F01-owned file-level import evidence: raw file under its own key plus a record-hash manifest.
CREATE TABLE import_file_evidence (
  id varchar(64) PRIMARY KEY, tenant_id varchar(128) NOT NULL, source_system_id varchar(128) NOT NULL,
  snapshot_id varchar(128) NOT NULL, file_hash varchar(64) NOT NULL, wrapped_key bytea,
  key_reference varchar(512), evidence_uri varchar(1024) NOT NULL, manifest jsonb NOT NULL,
  retention_rule varchar(128) NOT NULL, created_at timestamptz NOT NULL,
  key_destroyed_at timestamptz, key_destroyed_reason varchar(40)
);
CREATE INDEX ix_import_file_evidence_tenant_id ON import_file_evidence(tenant_id);
CREATE TABLE import_file_evidence_subject (
  file_evidence_id varchar(64) NOT NULL REFERENCES import_file_evidence(id),
  subject_id varchar(36) NOT NULL REFERENCES subject(id),
  PRIMARY KEY (file_evidence_id, subject_id)
);

-- F08 operational state only; never raw personal record payloads.
CREATE TABLE import_run (
  run_id varchar(64) PRIMARY KEY, tenant_id varchar(128) NOT NULL, source_system_id varchar(128) NOT NULL,
  snapshot_id varchar(128) NOT NULL, content_hash varchar(64) NOT NULL, generated_at timestamptz NOT NULL,
  file_evidence_id varchar(64), started_at timestamptz NOT NULL, completed_at timestamptz,
  status varchar(20) NOT NULL, attempt_count integer NOT NULL, last_attempt_at timestamptz NOT NULL,
  total_records integer NOT NULL
);
CREATE INDEX ix_import_run_tenant_id ON import_run(tenant_id);
CREATE TABLE import_record_outcome (
  run_id varchar(64) NOT NULL REFERENCES import_run(run_id), position integer NOT NULL,
  source_record_id varchar(256), source_version integer, identity_key varchar(64), idempotency_key varchar(64),
  record_hash varchar(64) NOT NULL, outcome varchar(20) NOT NULL, reason_code varchar(40) NOT NULL,
  f01_result jsonb, evidence_ref jsonb, retention_rule varchar(128), created_at timestamptz NOT NULL,
  PRIMARY KEY (run_id, position)
);
CREATE INDEX ix_import_record_outcome_identity_key ON import_record_outcome(identity_key);
CREATE INDEX ix_import_record_outcome_idempotency_key ON import_record_outcome(idempotency_key);
CREATE TABLE import_attempt (
  id varchar(36) PRIMARY KEY, run_id varchar(64) NOT NULL REFERENCES import_run(run_id),
  actor varchar(128) NOT NULL, correlation_id varchar(128) NOT NULL, started_at timestamptz NOT NULL,
  finished_at timestamptz, outcome varchar(20) NOT NULL
);
CREATE INDEX ix_import_attempt_run_id ON import_attempt(run_id);
CREATE TABLE import_event (
  id varchar(36) PRIMARY KEY, tenant_id varchar(128) NOT NULL, source_system_id varchar(128) NOT NULL,
  event_type varchar(40) NOT NULL, run_id varchar(64), reason_code varchar(40) NOT NULL, detail jsonb NOT NULL,
  actor varchar(128) NOT NULL, correlation_id varchar(128) NOT NULL, created_at timestamptz NOT NULL
);
CREATE INDEX ix_import_event_tenant_id ON import_event(tenant_id);

-- Deployment boundary (design §1.11): run the F08 adapter under a database role that holds
-- INSERT/UPDATE/SELECT on import_run, import_record_outcome, import_attempt and import_event only.
-- Only the F01 service role writes subject, subject_binding, claim, event_ledger, mutation_receipt,
-- import_file_evidence and import_file_evidence_subject. In-process, the adapter's session
-- factory enforces the same table set.
