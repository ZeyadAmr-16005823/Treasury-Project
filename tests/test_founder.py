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

    def test_full_setup_leaves_no_staging_or_backup_directories(self):
        for name in PROGRAM_NAMES:
            self.write_request(name)
        founder.setup_ca(self.log)
        founder.sign_certificates(self.log)
        parent = founder.CERTS_DIR.parent
        self.assertFalse((parent / "certs.staging").exists())
        self.assertFalse((parent / "certs.backup").exists())

    def test_missing_requests_fail_closed(self):
        self.write_request("M1")
        founder.setup_ca(self.log)
        founder.CERTS_DIR.mkdir(parents=True, exist_ok=True)
        stale = founder.CERTS_DIR / "M4.json"
        stale.write_text("stale certificate", encoding="utf-8")

        with self.assertRaises(ValueError) as error:
            founder.sign_certificates(self.log)

        for name in PROGRAM_NAMES:
            if name != "M1":
                self.assertIn(name, str(error.exception))
        # Nothing was activated: the stale certificate is untouched and no new
        # certificate set was mistaken for a successful issuance.
        self.assertEqual(stale.read_text(encoding="utf-8"), "stale certificate")
        self.assertEqual(sorted(p.stem for p in founder.CERTS_DIR.glob("*.json")), ["M4"])

    def test_allow_partial_replaces_stale_certificates(self):
        founder.setup_ca(self.log)
        self.write_request("M1")
        founder.CERTS_DIR.mkdir(parents=True, exist_ok=True)
        (founder.CERTS_DIR / "M4.json").write_text("stale certificate", encoding="utf-8")

        founder.sign_certificates(self.log, allow_partial=True)

        self.assertEqual(sorted(p.stem for p in founder.CERTS_DIR.glob("*.json")), ["M1"])
        self.assertFalse((founder.CERTS_DIR.parent / "certs.staging").exists())
        self.assertFalse((founder.CERTS_DIR.parent / "certs.backup").exists())

    def test_malformed_request_aborts_before_writing_any_certificate(self):
        founder.setup_ca(self.log)
        for name in PROGRAM_NAMES:
            self.write_request(name)
        founder.CERTS_DIR.mkdir(parents=True, exist_ok=True)
        stale = founder.CERTS_DIR / "M5.json"
        stale.write_text("stale certificate", encoding="utf-8")
        bad_request = founder.REQUESTS_DIR / "M2.json"
        request = json.loads(bad_request.read_text(encoding="utf-8"))
        request["public_key"] = "not a PEM key"
        bad_request.write_text(json.dumps(request), encoding="utf-8")

        with self.assertRaises(ValueError) as error:
            founder.sign_certificates(self.log)

        self.assertIn("M2.json", str(error.exception))
        self.assertEqual(stale.read_text(encoding="utf-8"), "stale certificate")
        self.assertEqual(sorted(p.stem for p in founder.CERTS_DIR.glob("*.json")), ["M5"])

    def test_init_repairs_stale_public_key_without_replacing_private_key(self):
        founder.setup_ca(self.log)
        private_bytes = founder.FOUNDER_PRIVATE.read_bytes()
        _, stale_pem = generate_p256_keypair()
        founder.FOUNDER_PUBLIC.write_text(stale_pem, encoding="ascii")

        founder.setup_ca(self.log)

        self.assertEqual(founder.FOUNDER_PRIVATE.read_bytes(), private_bytes)
        expected = public_key_pem(load_private_key(founder.FOUNDER_PRIVATE))
        self.assertEqual(founder.FOUNDER_PUBLIC.read_text(encoding="ascii"), expected)

    def test_signing_requires_ca_key(self):
        with self.assertRaises(RuntimeError):
            founder.sign_certificates(self.log)


if __name__ == "__main__":
    unittest.main()
