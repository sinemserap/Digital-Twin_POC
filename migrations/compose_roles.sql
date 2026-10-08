-- docker-compose only: create the two restricted runtime identities with synthetic passwords and
-- apply the role grant files. In the PoC/Azure environment create the roles with real secrets
-- (or Entra-managed identities) and run f08_adapter_role.sql / f03_graph_role.sql as the owner.
CREATE ROLE edt_f08 LOGIN PASSWORD 'edt_f08';
CREATE ROLE edt_f03 LOGIN PASSWORD 'edt_f03';
GRANT USAGE ON SCHEMA public TO edt_f08;
GRANT SELECT, INSERT, UPDATE ON TABLE import_run, import_record_outcome, import_attempt, import_event TO edt_f08;
GRANT USAGE ON SCHEMA public TO edt_f03;
GRANT SELECT ON TABLE subject, subject_binding, event_ledger TO edt_f03;
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE graph_projection, graph_node, graph_edge, graph_rejection, graph_query_audit TO edt_f03;
