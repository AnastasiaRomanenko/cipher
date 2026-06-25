from django.test import TestCase

from .crypto import (
    ChecksumMismatch,
    TamperingDetected,
    compute_plaintext_checksum,
    decrypt_file,
    encrypt_file,
    hash_file_password,
    hash_vault_password,
    verify_file_password,
    verify_plaintext_checksum,
    verify_vault_password,
)


class CryptoUnitTests(TestCase):

    def test_encrypt_decrypt_roundtrip(self):
        password = "FilePassword!2024"
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

    def test_file_password_hash_verify(self):
        pw = "FilePass!42"
        hashed, salt = hash_file_password(pw)
        self.assertTrue(verify_file_password(pw, hashed, salt))
        self.assertFalse(verify_file_password("wrong", hashed, salt))

    def test_file_password_independent_from_vault_password(self):
        vault_pw = "VaultMaster!1"
        file_pw = "FileSecret!2"
        v_hash, v_salt = hash_vault_password(vault_pw)
        f_hash, f_salt = hash_file_password(file_pw)
        self.assertFalse(verify_file_password(vault_pw, f_hash, f_salt))
        self.assertFalse(verify_vault_password(file_pw, v_hash, v_salt))

    def test_checksum_match(self):
        data = b"Original plaintext content"
        checksum = compute_plaintext_checksum(data)
        self.assertTrue(verify_plaintext_checksum(data, checksum))

    def test_checksum_mismatch_on_tampered_data(self):
        data = b"Original plaintext content"
        checksum = compute_plaintext_checksum(data)
        tampered = b"Tampered plaintext content"
        self.assertFalse(verify_plaintext_checksum(tampered, checksum))

    def test_checksum_is_32_bytes(self):
        checksum = compute_plaintext_checksum(b"any data")
        self.assertEqual(len(checksum), 32)

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
        self.assertEqual(len(ciphertext), len(plaintext) + 16)

    def test_salt_and_nonce_lengths(self):
        _, salt, nonce = encrypt_file("pass", b"data")
        self.assertEqual(len(salt), 16)
        self.assertEqual(len(nonce), 12)
