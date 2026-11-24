import unittest

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from treasury.certificates import create_certificate, verify_certificate
from treasury.config import CERT_EXPIRY, GROUP
from treasury.crypto_utils import generate_p256_keypair, load_public_key, public_key_pem


class CertificateTests(unittest.TestCase):
    def setUp(self):
        self.founder_private, founder_pem = generate_p256_keypair()
        self.founder_public = load_public_key(founder_pem)
        _, self.member_pem = generate_p256_keypair()
        self.certificate = create_certificate(
            self.founder_private, "M1", self.member_pem, CERT_EXPIRY
        ).to_dict()

    def test_valid_certificate(self):
        self.assertTrue(verify_certificate(self.certificate, self.founder_public, "M1"))
        self.assertEqual(len(self.certificate["sig"]), 128)

    def test_wrong_group_name_or_expiry(self):
        wrong_group = dict(self.certificate, group="other-group")
        self.assertFalse(verify_certificate(wrong_group, self.founder_public, "M1"))
        self.assertFalse(verify_certificate(self.certificate, self.founder_public, "M2"))
        expired = dict(self.certificate, expires="2020-01-01")
        self.assertFalse(verify_certificate(expired, self.founder_public, "M1"))

    def test_tampered_fields_and_malformed_structure(self):
        tampered = dict(self.certificate, name="M2")
        self.assertFalse(verify_certificate(tampered, self.founder_public, "M2"))
        missing_sig = {k: v for k, v in self.certificate.items() if k != "sig"}
        self.assertFalse(verify_certificate(missing_sig, self.founder_public, "M1"))
        extra = dict(self.certificate, unexpected="value")
        self.assertFalse(verify_certificate(extra, self.founder_public, "M1"))
        bad_pem = dict(self.certificate, public_key="not a PEM key")
        self.assertFalse(verify_certificate(bad_pem, self.founder_public, "M1"))

    def test_unsupported_public_key_in_certificate_is_rejected(self):
        rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        rsa_pem = rsa_key.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode("ascii")
        forged = dict(self.certificate, public_key=rsa_pem)
        self.assertFalse(verify_certificate(forged, self.founder_public, "M1"))

    def test_self_signed_certificate_is_rejected(self):
        impostor_private, _ = generate_p256_keypair()
        forged = create_certificate(impostor_private, "M1", self.member_pem, CERT_EXPIRY).to_dict()
        self.assertFalse(verify_certificate(forged, self.founder_public, "M1"))


if __name__ == "__main__":
    unittest.main()
