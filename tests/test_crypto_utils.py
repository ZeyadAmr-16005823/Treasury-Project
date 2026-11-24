import tempfile
import unittest
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from treasury.crypto_utils import (
    generate_p256_keypair,
    load_private_key,
    load_public_key,
    public_key_pem,
    save_private_key,
    sign_raw,
    verify_raw,
)


class CryptoUtilsTests(unittest.TestCase):
    def setUp(self):
        self.private_key, self.pem = generate_p256_keypair()
        self.public_key = load_public_key(self.pem)

    def test_keypair_is_p256_and_signature_is_128_hex_chars(self):
        self.assertIsInstance(self.private_key, ec.EllipticCurvePrivateKey)
        self.assertIsInstance(self.private_key.curve, ec.SECP256R1)
        signature = sign_raw(self.private_key, b"message")
        self.assertEqual(len(signature), 128)
        self.assertTrue(all(c in "0123456789abcdef" for c in signature))

    def test_sign_verify_round_trip_and_tampering(self):
        signature = sign_raw(self.private_key, b"message")
        self.assertTrue(verify_raw(self.public_key, b"message", signature))
        self.assertFalse(verify_raw(self.public_key, b"messagf", signature))
        other_key, _ = generate_p256_keypair()
        self.assertFalse(verify_raw(other_key.public_key(), b"message", signature))

    def test_malformed_signatures_are_rejected(self):
        signature = sign_raw(self.private_key, b"message")
        for bad in ("", signature[:-1], signature + "0", "z" * 128,
                    signature.upper(), None):
            self.assertFalse(verify_raw(self.public_key, b"message", bad))

    def test_unsupported_or_malformed_public_keys_are_rejected(self):
        rsa_pem = rsa.generate_private_key(public_exponent=65537, key_size=2048).public_key()
        other_curve = ec.generate_private_key(ec.SECP384R1()).public_key()
        candidates = [
            rsa_pem.public_bytes(serialization.Encoding.PEM,
                                 serialization.PublicFormat.SubjectPublicKeyInfo),
            other_curve.public_bytes(serialization.Encoding.PEM,
                                     serialization.PublicFormat.SubjectPublicKeyInfo),
            b"not a PEM key",
            b"",
        ]
        for candidate in candidates:
            with self.subTest(candidate=candidate[:32]):
                with self.assertRaises(ValueError):
                    load_public_key(candidate)

    def test_non_p256_private_key_is_rejected(self):
        other_key = ec.generate_private_key(ec.SECP384R1())
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "other.pem"
            path.write_bytes(other_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            ))
            with self.assertRaises(ValueError):
                load_private_key(path)

    def test_private_and_public_key_io(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "nested" / "private.pem"
            save_private_key(path, self.private_key)
            loaded = load_private_key(path)
            self.assertTrue(verify_raw(
                loaded.public_key(), b"message", sign_raw(self.private_key, b"message")
            ))
            self.assertEqual(public_key_pem(loaded), self.pem)


if __name__ == "__main__":
    unittest.main()
