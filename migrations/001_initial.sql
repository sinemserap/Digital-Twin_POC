-- PostgreSQL reference migration. SQLAlchemy metadata creates the same model for local tests.
CREATE TABLE subject (
  id varchar(36) PRIMARY KEY, tenant_id varchar(128) NOT NULL, wrapped_key bytea,
  key_reference varchar(512), created_at timestamptz NOT NULL
);
CREATE TABLE subject_binding (
  id varchar(36) PRIMARY KEY, subject_id varchar(36) NOT NULL REFERENCES subject(id),
  tenant_id varchar(128) NOT NULL, authenticated_account_id varchar(128) NOT NULL,
  source_system varchar(128) NOT NULL, source_person_ref varchar(256) NOT NULL,
  CONSTRAINT uq_subject_source_person UNIQUE (tenant_id, source_system, source_person_ref)
);
CREATE TABLE predicate_registry (predicate varchar(80) PRIMARY KEY, required_claim_class varchar(40) NOT NULL);
CREATE TABLE purpose_registry (purpose varchar(80) PRIMARY KEY, operation varchar(20) NOT NULL, required_role varchar(80) NOT NULL, allowed boolean NOT NULL);
CREATE TABLE claim (
  id varchar(36) PRIMARY KEY, subject_id varchar(36) NOT NULL REFERENCES subject(id), tenant_id varchar(128) NOT NULL,
  predicate varchar(80) NOT NULL, value_ciphertext bytea NOT NULL, claim_class varchar(40) NOT NULL,
  record_kind varchar(40) NOT NULL, status varchar(40) NOT NULL, source_system varchar(128) NOT NULL,
  source_record_id varchar(256) NOT NULL, source_authority varchar(80) NOT NULL, source_version integer NOT NULL,
  evidence_id varchar(36) NOT NULL, evidence_uri varchar(1024) NOT NULL, evidence_hash varchar(64) NOT NULL,
  purpose_ids jsonb NOT NULL, valid_from timestamptz NOT NULL, valid_to timestamptz, observed_at timestamptz NOT NULL,
  ingested_at timestamptz NOT NULL, retention_rule varchar(128) NOT NULL, confidence_band varchar(40) NOT NULL,
  event_sequence integer NOT NULL, record_hash varchar(64) NOT NULL
);
CREATE TABLE event_ledger (
  id varchar(36) PRIMARY KEY, tenant_id varchar(128) NOT NULL, subject_id varchar(36) NOT NULL REFERENCES subject(id),
  claim_id varchar(36) NOT NULL REFERENCES claim(id), sequence integer NOT NULL, event_type varchar(80) NOT NULL,
  ciphertext bytea NOT NULL, metadata_json jsonb NOT NULL, previous_hash varchar(64) NOT NULL,
  record_hash varchar(64) NOT NULL, created_at timestamptz NOT NULL
);
CREATE TABLE mutation_receipt (
  id varchar(36) PRIMARY KEY, tenant_id varchar(128) NOT NULL, idempotency_key varchar(256) NOT NULL,
  request_hash varchar(64) NOT NULL, claim_id varchar(36), response_json jsonb, created_at timestamptz NOT NULL,
  CONSTRAINT uq_tenant_idempotency UNIQUE (tenant_id, idempotency_key)
);
CREATE TABLE audit_log (
  id varchar(36) PRIMARY KEY, actor varchar(128) NOT NULL, tenant_id varchar(128) NOT NULL,
  subject_id varchar(36), purpose varchar(80) NOT NULL, operation varchar(80) NOT NULL,
  outcome varchar(40) NOT NULL, correlation_id varchar(128) NOT NULL, timestamp timestamptz NOT NULL
);

