"""
AES-256-GCM file encryption with PBKDF2-SHA256 key derivation.

Security design:
- Each file gets its own password — encryption key derived from that password's hash
- Each file gets its own random 16-byte salt → unique key per file even if password is reused
- Each file gets its own random 12-byte nonce → unique cipher stream per file
- AES-GCM authentication tag (16 bytes, appended to ciphertext) detects any tampering
- SHA-256 plaintext checksum stored at upload; verified before serving the download
- PBKDF2-HMAC-SHA256 with 600_000 iterations (NIST 2023 recommendation)
"""

import os
import hmac
import hashlib

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidTag

PBKDF2_ITERATIONS = 600_000
KEY_LENGTH = 32   # 256 bits for AES-256
SALT_LENGTH = 16  # 128-bit salt
NONCE_LENGTH = 12  # 96-bit nonce (GCM standard)
VAULT_SALT_LENGTH = 32  # salt for vault password verification hash


class TamperingDetected(Exception):
    """Raised when GCM authentication fails — ciphertext or metadata was altered."""


class ChecksumMismatch(Exception):
    """Raised when the SHA-256 checksum of decrypted content does not match the stored value."""


def _derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_LENGTH,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
    )
    return kdf.derive(password.encode("utf-8"))


def encrypt_file(password: str, plaintext: bytes) -> tuple[bytes, bytes, bytes]:
    """
    Encrypt plaintext with AES-256-GCM using a per-file password.

    Returns (ciphertext_with_tag, salt, nonce).
    """
    salt = os.urandom(SALT_LENGTH)
    nonce = os.urandom(NONCE_LENGTH)
    key = _derive_key(password, salt)
    aesgcm = AESGCM(key)
    ciphertext_with_tag = aesgcm.encrypt(nonce, plaintext, None)
    return ciphertext_with_tag, salt, nonce


def decrypt_file(password: str, ciphertext_with_tag: bytes, salt: bytes, nonce: bytes) -> bytes:
    """
    Decrypt ciphertext produced by encrypt_file.

    Raises TamperingDetected if the GCM tag verification fails (wrong password or tampered data).
    """
    key = _derive_key(password, salt)
    aesgcm = AESGCM(key)
    try:
        return aesgcm.decrypt(nonce, ciphertext_with_tag, None)
    except InvalidTag:
        raise TamperingDetected(
            "Authentication tag mismatch — the encrypted file has been tampered with "
            "or the password is incorrect."
        )


def compute_plaintext_checksum(data: bytes) -> bytes:
    """Return the SHA-256 digest of plaintext — stored at upload time."""
    return hashlib.sha256(data).digest()


def verify_plaintext_checksum(data: bytes, stored_checksum: bytes) -> bool:
    """Compare the SHA-256 of decrypted data against the stored checksum (constant-time)."""
    return hmac.compare_digest(hashlib.sha256(data).digest(), stored_checksum)


def hash_vault_password(password: str) -> tuple[bytes, bytes]:
    """
    Hash the vault password for storage (used only for vault unlock verification,
    NOT for file encryption).

    Returns (hashed_password, salt).
    """
    salt = os.urandom(VAULT_SALT_LENGTH)
    digest = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        PBKDF2_ITERATIONS,
    )
    return digest, salt


def verify_vault_password(password: str, stored_hash: bytes, stored_salt: bytes) -> bool:
    """Verify a vault password against the stored PBKDF2 hash using constant-time comparison."""
    candidate = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        stored_salt,
        PBKDF2_ITERATIONS,
    )
    return hmac.compare_digest(candidate, stored_hash)


def hash_file_password(password: str) -> tuple[bytes, bytes]:
    """
    Hash a per-file password for storage/verification (not used for key derivation).

    Returns (hashed_password, salt).
    """
    salt = os.urandom(VAULT_SALT_LENGTH)
    digest = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        PBKDF2_ITERATIONS,
    )
    return digest, salt


def verify_file_password(password: str, stored_hash: bytes, stored_salt: bytes) -> bool:
    """Verify a per-file password against its stored PBKDF2 hash (constant-time)."""
    candidate = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        stored_salt,
        PBKDF2_ITERATIONS,
    )
    return hmac.compare_digest(candidate, stored_hash)
