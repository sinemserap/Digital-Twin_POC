import base64
import hashlib
import os
from dataclasses import dataclass
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def encrypt(key: bytes, plaintext: bytes, aad: bytes = b"") -> bytes:
    nonce = os.urandom(12)
    return nonce + AESGCM(key).encrypt(nonce, plaintext, aad)


def decrypt(key: bytes, ciphertext: bytes, aad: bytes = b"") -> bytes:
    return AESGCM(key).decrypt(ciphertext[:12], ciphertext[12:], aad)


class LocalKeyProtector:
    """Development envelope-key adapter; production uses AzureKeyVaultProtector."""
    def __init__(self, master_key: bytes | None = None):
        self.master_key = master_key or hashlib.sha256(b"synthetic-dev-only-master-key").digest()

    def wrap(self, subject_id: str, key: bytes) -> tuple[bytes, str]:
        return encrypt(self.master_key, key, subject_id.encode()), f"local://keys/{subject_id}"

    def unwrap(self, subject_id: str, wrapped: bytes, _: str | None) -> bytes:
        return decrypt(self.master_key, wrapped, subject_id.encode())


class AzureKeyVaultProtector:
    """Envelope-key adapter backed by an Azure Key Vault RSA key."""
    def __init__(self, key_id: str, credential):
        from azure.keyvault.keys.crypto import CryptographyClient, KeyWrapAlgorithm
        self.client = CryptographyClient(key_id, credential)
        self.algorithm = KeyWrapAlgorithm.rsa_oaep_256
        self.key_id = key_id

    def wrap(self, subject_id: str, key: bytes) -> tuple[bytes, str]:
        return self.client.wrap_key(self.algorithm, key).encrypted_key, self.key_id

    def unwrap(self, subject_id: str, wrapped: bytes, _: str | None) -> bytes:
        return self.client.unwrap_key(self.algorithm, wrapped).key


@dataclass(frozen=True)
class Identity:
    tenant_id: str
    account_id: str
    roles: frozenset[str]


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

