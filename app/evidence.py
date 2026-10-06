from pathlib import Path
from urllib.parse import urlparse
from .security import decrypt, encrypt, sha256


class LocalEvidenceStore:
    """Blob-compatible local adapter for tests; objects are ciphertext only."""
    def __init__(self, root: str):
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)

    def put(self, tenant: str, subject: str, evidence_id: str, content: bytes, key: bytes) -> str:
        path = self.root / tenant / subject / evidence_id
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(encrypt(key, content, evidence_id.encode()))
        return f"localblob://{tenant}/{subject}/{evidence_id}"

    def read_verified(self, uri: str, evidence_id: str, expected_hash: str, key: bytes) -> bytes:
        parsed = urlparse(uri)
        path = self.root / parsed.netloc / parsed.path.lstrip("/")
        content = decrypt(key, path.read_bytes(), evidence_id.encode())
        if sha256(content) != expected_hash.lower():
            raise ValueError("evidence hash mismatch")
        return content


class AzureBlobEvidenceStore:
    """Encrypted object adapter. The service's managed identity owns blob access."""
    def __init__(self, connection_string: str, container: str):
        from azure.storage.blob import BlobServiceClient
        self.container = BlobServiceClient.from_connection_string(connection_string).get_container_client(container)
        try:
            self.container.create_container()
        except Exception:  # container commonly already exists
            pass

    def put(self, tenant: str, subject: str, evidence_id: str, content: bytes, key: bytes) -> str:
        name = f"{tenant}/{subject}/{evidence_id}"
        blob = self.container.get_blob_client(name)
        blob.upload_blob(encrypt(key, content, evidence_id.encode()), overwrite=False)
        return blob.url

    def read_verified(self, uri: str, evidence_id: str, expected_hash: str, key: bytes) -> bytes:
        name = "/".join(uri.split("/")[-3:])
        content = decrypt(key, self.container.download_blob(name).readall(), evidence_id.encode())
        if sha256(content) != expected_hash.lower():
            raise ValueError("evidence hash mismatch")
        return content

