from dataclasses import dataclass
import os


@dataclass(frozen=True)
class Settings:
    database_url: str = os.getenv("DATABASE_URL", "postgresql+psycopg://edt:edt@localhost:5432/edt")
    evidence_dir: str = os.getenv("EVIDENCE_DIR", ".evidence")
    # Separate database identity for the F08 adapter (grants in migrations/f08_adapter_role.sql).
    import_database_url: str | None = os.getenv("IMPORT_DATABASE_URL")
    # Separate database identity for the F03 graph service (grants in migrations/f03_graph_role.sql).
    graph_database_url: str | None = os.getenv("GRAPH_DATABASE_URL")
    azure_blob_connection_string: str | None = os.getenv("AZURE_BLOB_CONNECTION_STRING")
    azure_blob_container: str = os.getenv("AZURE_BLOB_CONTAINER", "edt-evidence")
    azure_key_vault_url: str | None = os.getenv("AZURE_KEY_VAULT_URL")

