-- Database identity for the F03 Operational Relationship Graph service (US40852 AC10).
-- Not a schema migration: run once per environment after 004, as the owner of the tables,
-- replacing edt_f03 with the service's login role and public with the application schema.
-- The service then connects with GRAPH_DATABASE_URL using this role.
--
-- The role may READ the canonical tables it needs for read-time authorization and staleness
-- (subject, subject_binding, event_ledger) and may WRITE only its own derived graph tables.
-- It has no INSERT/UPDATE/DELETE on subject, subject_binding, claim, event_ledger, mutation_receipt,
-- audit_log, import_* or predicate/purpose registries, and no SELECT on claim (values stay
-- encrypted behind the F01 projection contract). tests/test_graph.py executes this file with a
-- disposable role and asserts the denials on PostgreSQL.
GRANT USAGE ON SCHEMA public TO edt_f03;
GRANT SELECT ON TABLE subject, subject_binding, event_ledger TO edt_f03;
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE graph_projection, graph_node, graph_edge, graph_rejection, graph_query_audit TO edt_f03;
