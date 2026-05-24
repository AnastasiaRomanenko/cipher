from django.test import TestCase

from .crypto import (
    TamperingDetected,
    decrypt_file,
    encrypt_file,
    hash_vault_password,
    verify_vault_password,
)


class CryptoUnitTests(TestCase):

    def test_encrypt_decrypt_roundtrip(self):
        password = "TestPassword!2024"
        plaintext = b"Hello, this is a secret file content."
        ciphertext, salt, nonce = encrypt_file(password, plaintext)
        recovered = decrypt_file(password, ciphertext, salt, nonce)
        self.assertEqual(recovered, plaintext)

    def test_unique_salt_per_encryption(self):
        password = "SamePassword"
        data = b"Same content"
        _, salt1, nonce1 = encrypt_file(password, data)
        _, salt2, nonce2 = encrypt_file(password, data)
        self.assertNotEqual(salt1, salt2, "Salt must be unique per file")
        self.assertNotEqual(nonce1, nonce2, "Nonce must be unique per file")

    def test_unique_ciphertext_for_same_plaintext(self):
        password = "SamePassword"
        data = b"Same content"
        ct1, _, _ = encrypt_file(password, data)
        ct2, _, _ = encrypt_file(password, data)
        self.assertNotEqual(ct1, ct2, "Same plaintext must produce different ciphertext")

    def test_wrong_password_raises(self):
        ciphertext, salt, nonce = encrypt_file("correct-password", b"Secret")
        with self.assertRaises(TamperingDetected):
            decrypt_file("wrong-password", ciphertext, salt, nonce)

    def test_tampered_ciphertext_detected(self):
        ciphertext, salt, nonce = encrypt_file("password", b"Sensitive data")
        tampered = bytearray(ciphertext)
        tampered[0] ^= 0xFF
        with self.assertRaises(TamperingDetected):
            decrypt_file("password", bytes(tampered), salt, nonce)

    def test_tampered_nonce_detected(self):
        ciphertext, salt, nonce = encrypt_file("password", b"Sensitive data")
        bad_nonce = bytes([n ^ 0x01 for n in nonce])
        with self.assertRaises(TamperingDetected):
            decrypt_file("password", ciphertext, salt, bad_nonce)

    def test_vault_password_hash_verify(self):
        pw = "VaultPass!99"
        hashed, salt = hash_vault_password(pw)
        self.assertTrue(verify_vault_password(pw, hashed, salt))
        self.assertFalse(verify_vault_password("wrong", hashed, salt))

    def test_binary_file_encryption(self):
        import os
        password = "BinaryTest"
        binary_data = os.urandom(4096)
        ciphertext, salt, nonce = encrypt_file(password, binary_data)
        recovered = decrypt_file(password, ciphertext, salt, nonce)
        self.assertEqual(recovered, binary_data)

    def test_ciphertext_longer_than_plaintext(self):
        plaintext = b"Short text"
        ciphertext, salt, nonce = encrypt_file("pass", plaintext)
        # GCM appends 16-byte auth tag
        self.assertEqual(len(ciphertext), len(plaintext) + 16)

    def test_salt_and_nonce_lengths(self):
        _, salt, nonce = encrypt_file("pass", b"data")
        self.assertEqual(len(salt), 16)
        self.assertEqual(len(nonce), 12)
