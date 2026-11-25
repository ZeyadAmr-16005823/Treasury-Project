import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from treasury import founder, member
from treasury.config import GROUP
from treasury.crypto_utils import load_public_key, verify_raw
from treasury.encoding import canonical_json, sha256
from treasury.group import G, P, Q, is_valid_element
from treasury.sharing import evaluate_polynomial, hex_element, lagrange_coefficient, verify_share, vault_aad, vault_key


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
            patch.object(founder, "VAULT_DIR", root / "vault"),
            patch.object(founder, "GENERATIONS_DIR", root / "vault" / "generations"),
            patch.object(founder, "CURRENT_FILE", root / "vault" / "current.json"),
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
        self.assertFalse(list(founder.VAULT_DIR.rglob("share.json")))  # no share in public tree

        manifest = json.loads((generation / "manifest.json").read_text())
        self.assertEqual(manifest["generation"], current["generation"])
        self.assertEqual(manifest["commitments_digest"], current["commitments_digest"])
        self.assertIn("public/vault.json", manifest["artifacts"])
        self.assertFalse(any("\\" in key for key in manifest["artifacts"]))
        self.assertFalse(any(Path(key).is_absolute() for key in manifest["artifacts"]))
        for key, expected in manifest["artifacts"].items():
            self.assertEqual(expected, sha256((generation / key).read_bytes()).hex())

        commitments = json.loads((generation / "public" / "commitments.json").read_text())
        commitments_bytes = canonical_json(
            ["commitments", GROUP, 3, 5, commitments["commitments"]]
        )
        self.assertEqual(commitments["digest"], sha256(commitments_bytes).hex())
        self.assertTrue(verify_raw(self.founder_public, commitments_bytes, commitments["sig"]))
        self.assertTrue(all(is_valid_element(int(c, 16)) for c in commitments["commitments"]))

        C = [int(value, 16) for value in commitments["commitments"]]
        shares = []
        for index in range(1, 6):
            record = json.loads(founder.member_share_path(
                f"M{index}", current["generation"]).read_text())
            self.assertEqual((record["index"], record["generation"]), (index, current["generation"]))
            share = int(record["s_i"], 16)
            self.assertTrue(verify_share(share, index, C, P, Q, G))
            shares.append(share)

        vault = json.loads((generation / "public" / "vault.json").read_text())
        self.assertEqual(vault["commitments_digest"], commitments["digest"])
        self.assertTrue(is_valid_element(int(vault["c1"], 16)))
        self.assertTrue(is_valid_element(int(vault["c2"], 16)))
        vault_bytes = canonical_json({k: v for k, v in vault.items() if k != "sig"})
        self.assertTrue(verify_raw(self.founder_public, vault_bytes, vault["sig"]))

        selected = [1, 2, 3]
        D = 1
        for index in selected:
            d_i = pow(int(vault["c1"], 16), shares[index - 1], P)
            D = D * pow(d_i, lagrange_coefficient(index, selected, Q), P) % P
        m = int(vault["c2"], 16) * pow(D, -1, P) % P
        self.assertTrue(is_valid_element(m))
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
        m = pow(G, 2, P)
        original = vault_key(m, vault["c1"], vault["c2"], digest)
        # Use other strict subgroup elements: a single hex-digit mutation of a
        # random group element may leave the subgroup and be (correctly) rejected.
        changed_c1 = hex_element(pow(int(vault["c1"], 16), 2, P))
        changed_c2 = hex_element(pow(int(vault["c2"], 16), 2, P))
        self.assertNotEqual(original, vault_key(m, changed_c1, vault["c2"], digest))
        self.assertNotEqual(original, vault_key(m, vault["c1"], changed_c2, digest))

    def test_vault_dir_is_distinct_from_member2_dir(self):
        member2_dir = founder.DATA_DIR / "M2"
        member2_dir.mkdir(parents=True, exist_ok=True)
        founder.VAULT_DIR.mkdir(parents=True, exist_ok=True)
        self.assertFalse(os.path.samefile(member2_dir, founder.VAULT_DIR))
        self.assertNotEqual(member2_dir.name.lower(), founder.VAULT_DIR.name.lower())

    def test_member2_private_files_are_not_created_inside_vault_dir(self):
        founder.setup_vault(self.log)
        with patch.object(member, "DATA_DIR", founder.DATA_DIR):
            member.init_identity("M2", self.log)
            key_path = member.private_key_path("M2")
            secret_path = member.login_secret_path("M2")
        self.assertTrue(key_path.exists())
        self.assertTrue(secret_path.exists())
        self.assertFalse((founder.VAULT_DIR / "private.pem").exists())
        self.assertFalse((founder.VAULT_DIR / "login_secret.json").exists())
        self.assertFalse(list(founder.VAULT_DIR.rglob("private.pem")))
        current, _ = self.current_generation()
        self.assertTrue(founder.member_share_path("M2", current["generation"]).exists())

    def test_candidate_validation_rules(self):
        coefficients = [1, 2, 3]
        commitments = [pow(G, a, P) for a in coefficients]
        shares = [evaluate_polynomial(coefficients, i, Q) for i in range(1, 4)]
        m, c1, c2 = pow(G, 2, P), pow(G, 3, P), pow(G, 5, P)
        c1_hex, c2_hex, digest = hex_element(c1), hex_element(c2), "0" * 64

        self.assertTrue(founder._candidate_is_valid(
            commitments, shares, m, c1, c2, c1_hex, c2_hex, digest, 3, 3))
        self.assertFalse(founder._candidate_is_valid(  # c2 = 1
            commitments, shares, m, c1, 1, c1_hex, hex_element(1), digest, 3, 3))
        self.assertFalse(founder._candidate_is_valid(  # m = 1
            commitments, shares, 1, c1, c2, c1_hex, c2_hex, digest, 3, 3))
        self.assertFalse(founder._candidate_is_valid(  # zero share -> h_i = 1
            commitments, [0] + shares[1:], m, c1, c2, c1_hex, c2_hex, digest, 3, 3))
        self.assertFalse(founder._candidate_is_valid(  # identity commitment
            [commitments[0], 1, commitments[2]], shares, m, c1, c2,
            c1_hex, c2_hex, digest, 3, 3))
        self.assertFalse(founder._candidate_is_valid(  # caller-side length checks
            commitments[:2], shares, m, c1, c2, c1_hex, c2_hex, digest, 3, 3))
        self.assertFalse(founder._candidate_is_valid(
            commitments, shares[:2], m, c1, c2, c1_hex, c2_hex, digest, 3, 3))

    def test_degenerate_candidate_is_regenerated_before_publication(self):
        real_make_shares = founder.make_shares
        calls = []

        def flaky(secret, t, n, q):
            calls.append(secret)
            if len(calls) == 1:
                # zero higher coefficients (identity C1/C2) and zero shares
                return [secret, 0, 0], [secret] * n
            return real_make_shares(secret, t, n, q)

        with patch.object(founder, "make_shares", side_effect=flaky):
            founder.setup_vault(self.log)
        self.assertEqual(len(calls), 2)
        current, generation = self.current_generation()
        self.assertEqual(current["generation"], "generation-001")
        commitments = json.loads((generation / "public" / "commitments.json").read_text())
        self.assertTrue(all(is_valid_element(int(c, 16)) for c in commitments["commitments"]))

    def test_commitment_count_mismatch_publishes_nothing(self):
        with patch.object(founder, "make_commitments", return_value=[pow(G, 1, P)]):
            with self.assertRaises(RuntimeError):
                founder.setup_vault(self.log)
        self.assertFalse(founder.CURRENT_FILE.exists())
        self.assertFalse(founder.GENERATIONS_DIR.exists())

    def test_share_count_mismatch_publishes_nothing(self):
        with patch.object(founder, "make_shares", return_value=([1, 2, 3], [1, 2, 3])):
            with self.assertRaises(RuntimeError):
                founder.setup_vault(self.log)
        self.assertFalse(founder.CURRENT_FILE.exists())
        self.assertFalse(founder.GENERATIONS_DIR.exists())

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
        old_shares = {
            i: founder.member_share_path(f"M{i}", "generation-001").read_text()
            for i in range(1, 6)
        }
        founder.setup_vault(self.log, force=True)
        second_current, second = self.current_generation()
        self.assertEqual(first_current["generation"], "generation-001")
        self.assertEqual(second_current["generation"], "generation-002")
        self.assertTrue(second.exists())
        self.assertEqual(
            (founder.GENERATIONS_DIR / "generation-001" / "manifest.json").read_text(),
            first_manifest,
        )
        for i in range(1, 6):
            self.assertEqual(founder.member_share_path(f"M{i}", "generation-001").read_text(),
                             old_shares[i])
            self.assertTrue(founder.member_share_path(f"M{i}", "generation-002").exists())

    def test_interrupted_forced_regeneration_keeps_old_shares_usable(self):
        founder.setup_vault(self.log)
        before, _ = self.current_generation()
        old_shares = {
            i: founder.member_share_path(f"M{i}", "generation-001").read_text()
            for i in range(1, 6)
        }

        def partial_activation(generation, n):
            # Simulate a crash after M1's new share has been activated.
            staging_dir = founder.member_share_staging_path("M1", generation)
            final_dir = founder.member_share_path("M1", generation).parent
            os.replace(staging_dir, final_dir)
            raise RuntimeError("simulated interruption after one share")

        with patch.object(founder, "_activate_shares", side_effect=partial_activation):
            with self.assertRaises(RuntimeError):
                founder.setup_vault(self.log, force=True)

        after, _ = self.current_generation()
        self.assertEqual(after, before)
        for i in range(1, 6):
            path = founder.member_share_path(f"M{i}", "generation-001")
            self.assertEqual(path.read_text(), old_shares[i])

    def test_share_files_have_restrictive_permissions(self):
        if os.name == "nt":
            self.skipTest("POSIX permission bits are not meaningful on Windows")
        founder.setup_vault(self.log)
        current, _ = self.current_generation()
        for index in range(1, 6):
            path = founder.member_share_path(f"M{index}", current["generation"])
            mode = os.stat(path).st_mode & 0o777
            self.assertEqual(mode, 0o600)

    def test_failed_validation_publishes_nothing(self):
        with patch.object(founder, "verify_share", return_value=False):
            with self.assertRaises(RuntimeError):
                founder.setup_vault(self.log)
        self.assertFalse(founder.CURRENT_FILE.exists())
        self.assertFalse(founder.GENERATIONS_DIR.exists())

    def test_generic_two_of_four_setup(self):
        founder.setup_vault(self.log, t=2, n=4)
        current, generation = self.current_generation()
        for index in range(1, 5):
            self.assertTrue(founder.member_share_path(f"M{index}", current["generation"]).exists())
        self.assertFalse(founder.member_share_path("M5", current["generation"]).exists())
        commitments = json.loads((generation / "public" / "commitments.json").read_text())
        self.assertEqual(len(commitments["commitments"]), 2)

    def test_no_secret_bearing_fields_are_persisted(self):
        # Known founder scalar values let the test check for their persisted forms.
        known_s, known_u, known_r = 12345, 23456, 34567
        real_scalar = founder.random_nonzero_scalar
        known_values = iter([known_s, known_u, known_r])

        def scalars(q):
            try:
                return next(known_values)
            except StopIteration:
                return real_scalar(q)

        with patch.object(founder, "random_nonzero_scalar", side_effect=scalars):
            founder.setup_vault(self.log)
        current, generation = self.current_generation()
        vault = json.loads((generation / "public" / "vault.json").read_text())
        m = pow(G, known_u, P)
        key = vault_key(m, vault["c1"], vault["c2"], vault["commitments_digest"])
        secret_forms = [
            format(known_s, "x"), format(known_u, "x"), format(known_r, "x"),
            format(m, "0512x"), key.hex(),
        ]
        forbidden = {"s", "u", "r", "m", "key", "a0", "a1", "a2"}
        paths = list(generation.rglob("*.json")) + [
            founder.member_share_path(f"M{i}", current["generation"]) for i in range(1, 6)
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
