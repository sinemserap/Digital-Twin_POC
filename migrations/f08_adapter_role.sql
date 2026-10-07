-- Database identity for the F08 controlled source import adapter (design §1.11).
-- Not a schema migration: run once per environment after 003, as the owner of the tables,
-- replacing edt_f08 with the adapter's login role and public with the application schema.
-- The adapter then connects with IMPORT_DATABASE_URL using this role. It receives the four
-- F08 operational tables only; subject, subject_binding, claim, event_ledger,
-- mutation_receipt, audit_log, import_file_evidence and import_file_evidence_subject stay
-- with the F01 service role, which alone writes canonical and evidence state.
-- tests/test_postgres.py executes this file with a disposable role and asserts the denials.
GRANT USAGE ON SCHEMA public TO edt_f08;
GRANT SELECT, INSERT, UPDATE ON TABLE import_run, import_record_outcome, import_attempt, import_event TO edt_f08;
