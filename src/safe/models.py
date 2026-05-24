from django.db import models
from django.conf import settings


class VaultConfig(models.Model):
    """
    One row per user — stores the vault password hash and its derivation salt.
    The hash is used only for password verification; encryption keys are derived
    independently per file (see SafeFile.salt).
    """
    user = models.OneToOneField(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="vault_config",
    )
    password_hash = models.BinaryField()
    password_salt = models.BinaryField()
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"VaultConfig({self.user})"


class SafeFile(models.Model):
    """
    An encrypted file stored in the safe.

    Security invariants:
    - encrypted_data holds AES-256-GCM ciphertext || 16-byte auth tag
    - salt is the per-file PBKDF2 salt (unique, random, 16 bytes)
    - nonce is the per-file AES-GCM nonce (unique, random, 12 bytes)
    - salt and nonce live in the database; tampering with encrypted_data
      without also forging the auth tag is computationally infeasible
    """
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="safe_files",
    )
    original_name = models.CharField(max_length=255)
    encrypted_data = models.BinaryField()
    salt = models.BinaryField(max_length=16)
    nonce = models.BinaryField(max_length=12)
    file_size = models.PositiveIntegerField(help_text="Original file size in bytes")
    uploaded_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-uploaded_at"]

    def __str__(self):
        return f"SafeFile({self.original_name}, user={self.user})"
