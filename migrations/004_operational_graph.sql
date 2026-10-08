-- F03 Operational Relationship Graph — Part 1 (US40852). Apply after 001, 002 and 003.
-- Derived projection tables only: dropped and rebuilt from F01; never a source of truth.
-- Technology: plain PostgreSQL property-graph tables (F01 §1.6 "Apache AGE" is [ASSUMPTION — DA-10];
-- DA-10 is open). The storage is behind the GraphStore boundary in app/graph/service.py.

CREATE TABLE graph_projection (
  id varchar(36) PRIMARY KEY, tenant_id varchar(128) NOT NULL, projection_version varchar(160) NOT NULL,
  ontology_version varchar(64) NOT NULL, as_of timestamptz NOT NULL, canonical_fingerprint varchar(64) NOT NULL,
  canonical_event_count integer NOT NULL, graph_hash varchar(64) NOT NULL, node_count integer NOT NULL,
  edge_count integer NOT NULL, rejected_count integer NOT NULL, status varchar(20) NOT NULL,
  actor varchar(128) NOT NULL, correlation_id varchar(128) NOT NULL, built_at timestamptz NOT NULL,
  replaced_at timestamptz
);
CREATE INDEX ix_graph_projection_tenant_id ON graph_projection(tenant_id);
CREATE INDEX ix_graph_projection_status ON graph_projection(status);

CREATE TABLE graph_node (
  projection_id varchar(36) NOT NULL REFERENCES graph_projection(id), node_id varchar(64) NOT NULL,
  tenant_id varchar(128) NOT NULL, node_type varchar(40) NOT NULL, node_key varchar(512) NOT NULL,
  subject_id varchar(36), properties jsonb NOT NULL, allowed_purposes jsonb NOT NULL,
  PRIMARY KEY (projection_id, node_id), CONSTRAINT uq_graph_node UNIQUE (projection_id, node_id)
);
CREATE INDEX ix_graph_node_subject_id ON graph_node(subject_id);
CREATE INDEX ix_graph_node_lookup ON graph_node(projection_id, tenant_id, node_type);

CREATE TABLE graph_edge (
  projection_id varchar(36) NOT NULL REFERENCES graph_projection(id), edge_id varchar(64) NOT NULL,
  tenant_id varchar(128) NOT NULL, edge_type varchar(40) NOT NULL, src_node_id varchar(64) NOT NULL,
  dst_node_id varchar(64) NOT NULL, subject_id varchar(36) NOT NULL, claim_id varchar(36) NOT NULL,
  event_id varchar(36) NOT NULL, event_type varchar(80) NOT NULL, event_sequence integer NOT NULL,
  event_hash varchar(64) NOT NULL, source_system varchar(128) NOT NULL, source_record_id varchar(256) NOT NULL,
  source_version integer NOT NULL, evidence_id varchar(36) NOT NULL, evidence_hash varchar(64) NOT NULL,
  evidence_uri varchar(1024) NOT NULL, valid_from varchar(40) NOT NULL, valid_to varchar(40),
  projection_version varchar(160) NOT NULL, allowed_purposes jsonb NOT NULL, properties jsonb NOT NULL,
  PRIMARY KEY (projection_id, edge_id), CONSTRAINT uq_graph_edge UNIQUE (projection_id, edge_id)
);
CREATE INDEX ix_graph_edge_subject ON graph_edge(projection_id, tenant_id, subject_id);

CREATE TABLE graph_rejection (
  id varchar(36) PRIMARY KEY, projection_id varchar(36) NOT NULL REFERENCES graph_projection(id),
  tenant_id varchar(128) NOT NULL, subject_id varchar(36), predicate varchar(80), claim_id varchar(36),
  reason_code varchar(40) NOT NULL, detail text
);
CREATE INDEX ix_graph_rejection_projection_id ON graph_rejection(projection_id);

CREATE TABLE graph_query_audit (
  id varchar(36) PRIMARY KEY, actor varchar(128) NOT NULL, tenant_id varchar(128) NOT NULL,
  subject_id varchar(36), purpose varchar(80) NOT NULL, template_id varchar(80) NOT NULL,
  template_version varchar(20) NOT NULL, operation varchar(40) NOT NULL, outcome varchar(40) NOT NULL,
  http_status integer NOT NULL, request_hash varchar(64) NOT NULL, response_digest varchar(64),
  projection_id varchar(36), edge_ids jsonb, correlation_id varchar(128) NOT NULL, timestamp timestamptz NOT NULL
);
CREATE INDEX ix_graph_query_audit_tenant_id ON graph_query_audit(tenant_id);
CREATE INDEX ix_graph_query_audit_subject_id ON graph_query_audit(subject_id);

-- Deployment boundary (AC10): run the F03 graph service under the role in f03_graph_role.sql.
