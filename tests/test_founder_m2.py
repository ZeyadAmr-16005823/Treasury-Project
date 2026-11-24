import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from treasury import founder
from treasury.config import GROUP
from treasury.crypto_utils import load_public_key, verify_raw
from treasury.encoding import canonical_json, sha256
from treasury.group import G, P, Q
from treasury.sharing import lagrange_coefficient, verify_share, vault_aad, vault_key


class FounderVaultTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        patches = [
            patch.object(founder, "DATA_DIR", root),
            patch.object(founder, "FOUNDER_DIR", root / "founder"),
            patch.object(founder, "FOUNDER_PRIVATE", root / "founder" / "founder_private.pem"),
            patch.object(founder, "FOUNDER_PUBLIC", root / "founder.pub"),
            patch.object(founder, "M2_DIR", root / "m2"),
            patch.object(founder, "GENERATIONS_DIR", root / "m2" / "generations"),
            patch.object(founder, "CURRENT_FILE", root / "m2" / "current.json"),
        ]
        for item in patches:
            item.start()
            self.addCleanup(item.stop)
        self.log = Mock()
        founder.setup_ca(self.log)
        self.founder_public = load_public_key(founder.FOUNDER_PUBLIC.read_text(encoding="ascii"))

    def current_generation(self):
        current = json.loads(founder.CURRENT_FILE.read_text(encoding="utf-8"))
        return current, founder.GENERATIONS_DIR / current["generation"]

    def test_full_setup_publishes_verifiable_artifacts(self):
        founder.setup_vault(self.log)
        current, generation = self.current_generation()
        self.assertEqual((current["t"], current["n"], current["group"]), (3, 5, GROUP))
        self.assertTrue((generation / "manifest.json").exists())
        self.assertFalse(list(generation.rglob("share.json")))  # no central private copy

        commitments = json.loads((generation / "public" / "commitments.json").read_text())
        commitments_bytes = canonical_json(
            ["commitments", GROUP, 3, 5, commitments["commitments"]]
        )
        self.assertEqual(commitments["digest"], sha256(commitments_bytes).hex())
        self.assertTrue(verify_raw(self.founder_public, commitments_bytes, commitments["sig"]))

        C = [int(value, 16) for value in commitments["commitments"]]
        shares = []
        for index in range(1, 6):
            record = json.loads(founder.member_share_path(f"M{index}").read_text())
            self.assertEqual((record["index"], record["generation"]), (index, current["generation"]))
            share = int(record["s_i"], 16)
            self.assertTrue(verify_share(share, index, C, P, Q, G))
            shares.append(share)

        vault = json.loads((generation / "public" / "vault.json").read_text())
        self.assertEqual(vault["commitments_digest"], commitments["digest"])
        vault_bytes = canonical_json({k: v for k, v in vault.items() if k != "sig"})
        self.assertTrue(verify_raw(self.founder_public, vault_bytes, vault["sig"]))

        selected = [1, 2, 3]
        D = 1
        for index in selected:
            d_i = pow(int(vault["c1"], 16), shares[index - 1], P)
            D = D * pow(d_i, lagrange_coefficient(index, selected, Q), P) % P
        m = int(vault["c2"], 16) * pow(D, -1, P) % P
        frame = (generation / "public" / "vault.enc").read_bytes()
        key = vault_key(m, vault["c1"], vault["c2"], vault["commitments_digest"])
        aad = vault_aad(vault["c1"], vault["c2"], vault["commitments_digest"])
        plaintext = AESGCM(key).decrypt(frame[:12], frame[12:], aad)
        self.assertEqual(plaintext, founder.VAULT_PLAINTEXT)

    def test_changing_c1_or_c2_changes_derived_key(self):
        founder.setup_vault(self.log)
        _, generation = self.current_generation()
        vault = json.loads((generation / "public" / "vault.json").read_text())
        digest = vault["commitments_digest"]
        original = vault_key(2, vault["c1"], vault["c2"], digest)
        changed_c1 = vault["c1"][:-1] + ("0" if vault["c1"][-1] != "0" else "1")
        changed_c2 = vault["c2"][:-1] + ("0" if vault["c2"][-1] != "0" else "1")
        self.assertNotEqual(original, vault_key(2, changed_c1, vault["c2"], digest))
        self.assertNotEqual(original, vault_key(2, vault["c1"], changed_c2, digest))

    def test_regeneration_is_refused_unless_forced(self):
        founder.setup_vault(self.log)
        with self.assertRaises(ValueError):
            founder.setup_vault(self.log)
        founder.setup_vault(self.log, force=True)
        current, generation = self.current_generation()
        self.assertEqual(current["generation"], "generation-002")
        self.assertTrue(generation.exists())

    def test_forced_regeneration_preserves_previous_generation(self):
        founder.setup_vault(self.log)
        first_current, _ = self.current_generation()
        first_manifest = (founder.GENERATIONS_DIR / "generation-001" / "manifest.json").read_text()
        founder.setup_vault(self.log, force=True)
        second_current, second = self.current_generation()
        self.assertEqual(first_current["generation"], "generation-001")
        self.assertEqual(second_current["generation"], "generation-002")
        self.assertTrue(second.exists())
        self.assertEqual(
            (founder.GENERATIONS_DIR / "generation-001" / "manifest.json").read_text(),
            first_manifest,
        )

    def test_interrupted_forced_regeneration_keeps_old_pointer(self):
        founder.setup_vault(self.log)
        before, _ = self.current_generation()
        with patch.object(founder, "verify_share", return_value=False):
            with self.assertRaises(RuntimeError):
                founder.setup_vault(self.log, force=True)
        after, _ = self.current_generation()
        self.assertEqual(after, before)
        self.assertFalse((founder.GENERATIONS_DIR / "generation-002").exists())
        self.assertFalse((founder.GENERATIONS_DIR / "generation-002.tmp").exists())

    def test_share_files_have_restrictive_permissions(self):
        if os.name == "nt":
            self.skipTest("POSIX permission bits are not meaningful on Windows")
        founder.setup_vault(self.log)
        for index in range(1, 6):
            mode = os.stat(founder.member_share_path(f"M{index}")).st_mode & 0o777
            self.assertEqual(mode, 0o600)

    def test_failed_validation_publishes_nothing(self):
        with patch.object(founder, "verify_share", return_value=False):
            with self.assertRaises(RuntimeError):
                founder.setup_vault(self.log)
        self.assertFalse(founder.CURRENT_FILE.exists())
        self.assertFalse(founder.GENERATIONS_DIR.exists())

    def test_generic_two_of_four_setup(self):
        founder.setup_vault(self.log, t=2, n=4)
        _, generation = self.current_generation()
        for index in range(1, 5):
            self.assertTrue(founder.member_share_path(f"M{index}").exists())
        self.assertFalse(founder.member_share_path("M5").exists())
        commitments = json.loads((generation / "public" / "commitments.json").read_text())
        self.assertEqual(len(commitments["commitments"]), 2)

    def test_no_secret_bearing_fields_are_persisted(self):
        # Known founder scalar values let the test check for their persisted forms.
        known_s, known_u, known_r = 12345, 23456, 34567
        with patch.object(founder, "random_nonzero_scalar",
                          side_effect=[known_s, known_u, known_r]):
            founder.setup_vault(self.log)
        _, generation = self.current_generation()
        vault = json.loads((generation / "public" / "vault.json").read_text())
        m = pow(G, known_u, P)
        key = vault_key(m, vault["c1"], vault["c2"], vault["commitments_digest"])
        secret_forms = [
            format(known_s, "x"), format(known_u, "x"), format(known_r, "x"),
            format(m, "0512x"), key.hex(),
        ]
        forbidden = {"s", "u", "r", "m", "key", "a0", "a1", "a2"}
        paths = list(generation.rglob("*.json")) + [
            founder.member_share_path(f"M{i}") for i in range(1, 6)
        ]
        for path in paths:
            text = path.read_text(encoding="utf-8")
            for form in secret_forms:
                self.assertNotIn(form, text, f"{form[:8]}... appeared in {path.name}")
            data = json.loads(text)
            if path.name == "share.json":
                self.assertEqual(set(data), {"index", "generation", "s_i"})
            else:
                self.assertFalse(forbidden.intersection(data))
        frame = (generation / "public" / "vault.enc").read_bytes()
        self.assertNotIn(founder.VAULT_PLAINTEXT, frame)


if __name__ == "__main__":
    unittest.main()
