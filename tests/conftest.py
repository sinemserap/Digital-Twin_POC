"""Opt-in PostgreSQL acceptance runner; never touches existing application tables."""
from pathlib import Path
import uuid

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.engine import make_url


MIGRATIONS = Path(__file__).resolve().parents[1] / "migrations"


def pytest_addoption(parser):
    parser.addoption("--postgres-url", help="Disposable PostgreSQL test database URL")
    parser.addoption("--postgres-timezone", default="UTC",
                     help="PostgreSQL session timezone (default UTC)")


@pytest.fixture()
def postgres_schema(request):
    raw_url = request.config.getoption("--postgres-url")
    if not raw_url:
        pytest.skip("requires --postgres-url")
    base_url = make_url(raw_url)
    if base_url.drivername != "postgresql+psycopg":
        raise pytest.UsageError("--postgres-url must use postgresql+psycopg")
    # Generated identifier, not user input. Each test gets its own schema.
    schema = "edt_test_" + uuid.uuid4().hex
    options = base_url.query.get("options", "")
    timezone = request.config.getoption("--postgres-timezone")
    # libpq options split on spaces; restrict to IANA names / UTC.
    if not timezone or any(c not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789/_+-" for c in timezone):
        raise pytest.UsageError("invalid --postgres-timezone")
    admin = create_engine(base_url)
    with admin.begin() as conn:
        conn.execute(text(f'CREATE SCHEMA "{schema}"'))
    url = base_url.update_query_dict({
        "options": f"{options} -csearch_path={schema} -ctimezone={timezone}".strip()
    }).render_as_string(hide_password=False)
    try:
        probe = create_engine(url)
        try:
            with probe.connect() as conn:
                assert conn.execute(text("SELECT current_schema()")).scalar_one() == schema
                assert conn.execute(text("SHOW TimeZone")).scalar_one() == timezone
        finally:
            probe.dispose()
        yield url
    finally:
        with admin.begin() as conn:
            conn.execute(text(f'DROP SCHEMA "{schema}" CASCADE'))
        admin.dispose()


def apply_migration(engine, name):
    with engine.begin() as conn:
        # Execute the actual SQL file, not SQLAlchemy create_all.
        conn.exec_driver_sql((MIGRATIONS / name).read_text())


@pytest.fixture()
def postgres_database(postgres_schema):
    engine = create_engine(postgres_schema)
    try:
        apply_migration(engine, "001_initial.sql")
        apply_migration(engine, "002_subject_restriction.sql")
        apply_migration(engine, "003_controlled_import.sql")
        apply_migration(engine, "004_operational_graph.sql")
    finally:
        engine.dispose()
    return postgres_schema

