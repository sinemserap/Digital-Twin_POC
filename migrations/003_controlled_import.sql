-- F08 operational metadata only; never store raw personal record payloads here.
CREATE TABLE import_run (
    file_key varchar(64) PRIMARY KEY,
    tenant_id varchar(128) NOT NULL,
    source varchar(128) NOT NULL,
    generated_at timestamptz NOT NULL,
    report json NOT NULL
);
CREATE INDEX ix_import_run_tenant_id ON import_run(tenant_id);
