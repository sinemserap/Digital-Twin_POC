"""PostgreSQL-only cases supplementing the shared acceptance suite."""
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, event, func, inspect, select, text

from app.main import create_app
from app.models import Claim, EventLedger, MutationReceipt, Subject, SubjectBinding
from conftest import apply_migration
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
            assert db.scalar(select(func.count()).select_from(EventLedger)) == 1
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
        for model in (Claim, EventLedger, MutationReceipt):
            assert db.scalar(select(func.count()).select_from(model)) == 1
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
