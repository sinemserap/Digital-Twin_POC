"""PostgreSQL-only cases supplementing the shared acceptance suite."""
import uuid
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, event, func, inspect, select, text
from sqlalchemy.engine import make_url

from app.main import create_app
from app.models import Claim, EventLedger, MutationReceipt, Subject, SubjectBinding
from conftest import MIGRATIONS, apply_migration
from test_acceptance import accept, acceptance_clock, headers, history, import_subject, mutation


@pytest.fixture()
def pg_env(postgres_database, tmp_path):
    app = create_app(postgres_database, str(tmp_path / "evidence"))
    with TestClient(app) as client:
        yield client, app


def test_migration_002_preserves_populated_part1_and_enforces_current_rights(
        postgres_schema, tmp_path, acceptance_clock):
    engine = create_engine(postgres_schema)
    apply_migration(engine, "001_initial.sql")
    assert "restricted" not in {c["name"] for c in inspect(engine).get_columns("subject")}
    # Bootstrap the new column solely to seed genuine accepted Part 1 records
    # via the unchanged mutation contract, then restore the Part 1 table shape.
    apply_migration(engine, "002_subject_restriction.sql")
    evidence_dir = str(tmp_path / "evidence")
    seed = create_app(postgres_schema, evidence_dir)
    with TestClient(seed) as client:
        sid = import_subject(client).json()["subject_id"]
        result = accept(client, sid, mutation())
    with engine.begin() as conn:
        conn.execute(text("ALTER TABLE subject DROP COLUMN restricted"))
        before = {
            table: conn.execute(text(f"SELECT * FROM {table} ORDER BY id")).all()
            for table in ("subject", "subject_binding", "claim", "event_ledger", "mutation_receipt")
        }
    assert "restricted" not in {c["name"] for c in inspect(engine).get_columns("subject")}

    apply_migration(engine, "002_subject_restriction.sql")
    with engine.connect() as conn:
        # The sole added column defaults to false on existing records.
        assert conn.execute(text("SELECT restricted FROM subject")).scalar_one() is False
        for table, rows in before.items():
            columns = ", ".join(rows[0]._mapping.keys())
            assert conn.execute(text(f"SELECT {columns} FROM {table} ORDER BY id")).all() == rows
    column = next(c for c in inspect(engine).get_columns("subject") if c["name"] == "restricted")
    assert column["nullable"] is False and column["default"] == "false"
    upgraded = create_app(postgres_schema, evidence_dir)
    with TestClient(upgraded) as client:
        assert import_subject(client).json() == {"subject_id": sid, "created": False}
        assert accept(client, sid, mutation()) == result
        assert history(client, sid).json()["predicates"]["start_date"]["value"] == "2026-11-01"
        with upgraded.state.sessions() as db:
            assert db.scalar(select(func.count()).select_from(EventLedger)) == 2
            assert upgraded.state.service.verify_ledger(db, sid)
            db.get(Subject, sid).restricted = True
            db.commit()
        assert history(client, sid).status_code == 403
        assert client.post(f"/subjects/{sid}/claims", headers=headers(), json=mutation()).status_code == 403
    restarted = create_app(postgres_schema, evidence_dir)
    with TestClient(restarted) as client:
        assert history(client, sid).status_code == 403
    engine.dispose()


def test_timestamptz_dst_fold_and_microsecond_cutoffs(pg_env, acceptance_clock):
    client, app = pg_env
    # The repeated local 01:30 occurs twice on this day, one hour apart.
    acceptance_clock("2026-11-01T01:30:00.123456-04:00")
    sid = import_subject(client).json()["subject_id"]
    body = mutation()
    body.update(valid_from="2026-11-01T01:30:00.123456-04:00",
                valid_to="2026-11-01T01:30:00.123456-05:00")
    accept(client, sid, body)
    with app.state.engine.connect() as conn:
        types = dict(conn.execute(text(
            "SELECT column_name, data_type FROM information_schema.columns "
            "WHERE table_schema=current_schema() AND table_name='claim' "
            "AND column_name IN ('ingested_at', 'valid_from', 'valid_to')"
        )).all())
    assert set(types.values()) == {"timestamp with time zone"} and len(types) == 3
    known = history(client, sid, valid_at=body["valid_from"],
                    system_at=body["valid_from"])
    assert known.status_code == 200
    proof = known.json()["predicates"]["start_date"]["claims"][0]
    assert proof["ingested_at"] == proof["valid_from"] == "2026-11-01T05:30:00.123456+00:00"
    assert proof["valid_to"] == "2026-11-01T06:30:00.123456+00:00"
    equivalent = history(client, sid, valid_at="2026-11-01T05:30:00.123456Z",
                         system_at="2026-11-01T08:30:00.123456+03:00")
    assert equivalent.json() == known.json()
    for valid_at, system_at, state in [
        ("2026-11-01T05:30:00.123455Z", "2026-11-02T00:00:00Z", "unknown"),
        ("2026-11-01T05:30:00.123456Z", "2026-11-01T05:30:00.123455Z", "unknown"),
        ("2026-11-01T06:30:00.123455Z", "2026-11-02T00:00:00Z", "known"),
        (body["valid_to"], "2026-11-02T00:00:00Z", "unknown"),
    ]:
        response = history(client, sid, valid_at=valid_at, system_at=system_at)
        assert response.status_code == 200
        assert response.json()["predicates"]["start_date"]["state"] == state


@pytest.mark.parametrize("changed", [False, True])
def test_concurrent_receipt_unique_constraint(pg_env, changed):
    client, app = pg_env
    sid = import_subject(client).json()["subject_id"]
    bodies = [mutation(idem="pg-race"), mutation(idem="pg-race")]
    if changed:
        bodies[1] = mutation(value="2026-11-08", idem="pg-race")
    barrier = Barrier(2)

    def synchronize_receipt(conn, cursor, statement, parameters, context, executemany):
        if statement.startswith("INSERT INTO mutation_receipt"):
            # Both requests have reached insertion before either can commit.
            barrier.wait(timeout=10)

    event.listen(app.state.engine, "before_cursor_execute", synchronize_receipt)
    try:
        with ThreadPoolExecutor(max_workers=2) as pool:
            responses = list(pool.map(
                lambda body: client.post(f"/subjects/{sid}/claims", headers=headers(), json=body),
                bodies))
    finally:
        event.remove(app.state.engine, "before_cursor_execute", synchronize_receipt)
    assert sorted(r.status_code for r in responses) == ([201, 409] if changed else [201, 201])
    if not changed:
        assert responses[0].json() == responses[1].json()
    with app.state.sessions() as db:
        for model, expected in ((Claim, 1), (EventLedger, 2), (MutationReceipt, 1)):
            assert db.scalar(select(func.count()).select_from(model)) == expected
        assert app.state.service.verify_ledger(db, sid)
        receipt = db.scalar(select(MutationReceipt))
        assert receipt.response_json == next(r.json() for r in responses if r.status_code == 201)


def test_concurrent_subject_import_rolls_back_losing_subject(pg_env):
    client, app = pg_env
    barrier = Barrier(2)

    def synchronize_binding(conn, cursor, statement, parameters, context, executemany):
        if statement.startswith("INSERT INTO subject_binding"):
            barrier.wait(timeout=10)

    event.listen(app.state.engine, "before_cursor_execute", synchronize_binding)
    try:
        with ThreadPoolExecutor(max_workers=2) as pool:
            responses = list(pool.map(lambda _: import_subject(client), range(2)))
    finally:
        event.remove(app.state.engine, "before_cursor_execute", synchronize_binding)
    assert [r.status_code for r in responses] == [201, 201]
    assert responses[0].json()["subject_id"] == responses[1].json()["subject_id"]
    assert sorted(r.json()["created"] for r in responses) == [False, True]
    with app.state.sessions() as db:
        assert db.scalar(select(func.count()).select_from(Subject)) == 1
        assert db.scalar(select(func.count()).select_from(SubjectBinding)) == 1


def test_f08_adapter_role_cannot_write_canonical_state(postgres_database, tmp_path):
    """Design §1.11: the adapter's runtime identity holds no write permission on canonical state."""
    import secrets
    from sqlalchemy.exc import ProgrammingError
    from test_import import counts, file, upload
    url = make_url(postgres_database)
    role, password = "edt_f08_" + uuid.uuid4().hex[:12], secrets.token_urlsafe(16)
    owner = create_engine(postgres_database)
    try:
        with owner.begin() as conn:
            try:
                # DDL takes no bind parameters; token_urlsafe yields only [A-Za-z0-9_-].
                conn.execute(text(f"CREATE ROLE \"{role}\" LOGIN PASSWORD '{password}'"))
            except ProgrammingError as exc:
                if getattr(exc.orig, "sqlstate", None) != "42501":
                    raise
                pytest.skip("test user lacks CREATEROLE")
            schema = conn.execute(text("SELECT current_schema()")).scalar_one()
            grants = (MIGRATIONS / "f08_adapter_role.sql").read_text().replace("edt_f08", role).replace("public", schema)
            conn.exec_driver_sql(grants)
    except Exception:
        owner.dispose(); raise
    restricted_url = url.set(username=role, password=password).render_as_string(hide_password=False)
    try:
        app = create_app(postgres_database, str(tmp_path / "evidence"), import_database_url=restricted_url)
        with TestClient(app) as client:
            assert app.state.import_engine is not app.state.engine
            assert app.state.importer.engine.url.username == role
            # A full import works: the adapter writes its own tables and everything else goes through F01.
            report = upload(client, file()).json()
            assert [o["outcome"] for o in report["outcomes"]] == ["accepted"] and counts(app) == [1, 3, 4]
            assert client.get("/imports/ATS/freshness", headers=headers(roles="data_administrator")).json()["state"] == "fresh"
            sid = report["outcomes"][0]["f01"]["subject_id"]
            # Raw SQL as the adapter identity, bypassing the in-process ORM guard: PostgreSQL denies it.
            denied = [
                f"UPDATE claim SET status = 'superseded' WHERE subject_id = '{sid}'",
                f"UPDATE subject SET restricted = true WHERE id = '{sid}'",
                f"INSERT INTO event_ledger (id, tenant_id, subject_id, claim_id, sequence, event_type, ciphertext, "
                f"metadata_json, previous_hash, record_hash, created_at) SELECT 'x', tenant_id, subject_id, claim_id, 99, "
                f"'ClaimAccepted', ciphertext, metadata_json, previous_hash, record_hash, created_at FROM event_ledger LIMIT 1",
                "DELETE FROM mutation_receipt",
                "UPDATE import_file_evidence SET wrapped_key = NULL",
                "SELECT count(*) FROM claim",
                "SELECT count(*) FROM audit_log",
            ]
            for statement in denied:
                with app.state.import_engine.connect() as conn:
                    with pytest.raises(ProgrammingError, match="permission denied"):
                        conn.execute(text(statement))
            with app.state.import_engine.begin() as conn:
                assert conn.execute(text("SELECT count(*) FROM import_record_outcome")).scalar_one() == 1
            assert counts(app) == [1, 3, 4]
            with app.state.sessions() as db:
                assert app.state.service.verify_ledger(db, sid)
    finally:
        with owner.begin() as conn:
            # Explicit revokes: a CREATEROLE (non-superuser) owner may not DROP OWNED BY on PostgreSQL 16.
            conn.execute(text(f'REVOKE ALL ON ALL TABLES IN SCHEMA "{schema}" FROM "{role}"'))
            conn.execute(text(f'REVOKE ALL ON SCHEMA "{schema}" FROM "{role}"'))
            conn.execute(text(f'DROP ROLE "{role}"'))
        owner.dispose()
