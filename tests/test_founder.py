import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from treasury import founder
from treasury.certificates import verify_certificate
from treasury.config import CERT_EXPIRY, GROUP, PROGRAM_NAMES
from treasury.crypto_utils import (
    generate_p256_keypair,
    load_private_key,
    load_public_key,
    public_key_pem,
)


class FounderSetupTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        patches = [
            patch.object(founder, "FOUNDER_DIR", root / "founder"),
            patch.object(founder, "FOUNDER_PRIVATE", root / "founder" / "founder_private.pem"),
            patch.object(founder, "FOUNDER_PUBLIC", root / "founder.pub"),
            patch.object(founder, "REQUESTS_DIR", root / "requests"),
            patch.object(founder, "CERTS_DIR", root / "certs"),
        ]
        for item in patches:
            item.start()
            self.addCleanup(item.stop)
        self.log = Mock()

    def write_request(self, name):
        founder.REQUESTS_DIR.mkdir(parents=True, exist_ok=True)
        _, pem = generate_p256_keypair()
        (founder.REQUESTS_DIR / f"{name}.json").write_text(
            json.dumps({"name": name, "public_key": pem}), encoding="utf-8"
        )
        return pem

    def test_full_setup_issues_verifiable_certificates(self):
        for name in PROGRAM_NAMES:
            self.write_request(name)
        founder.setup_ca(self.log)
        founder.sign_certificates(self.log)

        founder_public = load_public_key(founder.FOUNDER_PUBLIC.read_text(encoding="ascii"))
        self.assertTrue(founder.FOUNDER_PRIVATE.exists())
        for name in PROGRAM_NAMES:
            path = founder.CERTS_DIR / f"{name}.json"
            self.assertTrue(path.exists())
            cert = json.loads(path.read_text(encoding="utf-8"))
            self.assertTrue(verify_certificate(cert, founder_public, name))
            self.assertEqual(cert["group"], GROUP)
            self.assertEqual(cert["expires"], CERT_EXPIRY)

    def test_missing_requests_are_skipped(self):
        self.write_request("M1")
        founder.setup_ca(self.log)
        founder.sign_certificates(self.log)
        self.assertEqual(sorted(p.stem for p in founder.CERTS_DIR.glob("*.json")), ["M1"])

    def test_init_repairs_stale_public_key_without_replacing_private_key(self):
        founder.setup_ca(self.log)
        private_bytes = founder.FOUNDER_PRIVATE.read_bytes()
        _, stale_pem = generate_p256_keypair()
        founder.FOUNDER_PUBLIC.write_text(stale_pem, encoding="ascii")

        founder.setup_ca(self.log)

        self.assertEqual(founder.FOUNDER_PRIVATE.read_bytes(), private_bytes)
        expected = public_key_pem(load_private_key(founder.FOUNDER_PRIVATE))
        self.assertEqual(founder.FOUNDER_PUBLIC.read_text(encoding="ascii"), expected)

    def test_invalid_public_key_request_fails_cleanly(self):
        founder.setup_ca(self.log)
        self.write_request("M1")
        path = founder.REQUESTS_DIR / "M1.json"
        request = json.loads(path.read_text(encoding="utf-8"))
        request["public_key"] = "not a PEM key"
        path.write_text(json.dumps(request), encoding="utf-8")
        with self.assertRaises(ValueError):
            founder.sign_certificates(self.log)

    def test_signing_requires_ca_key(self):
        with self.assertRaises(RuntimeError):
            founder.sign_certificates(self.log)


if __name__ == "__main__":
    unittest.main()
