import itertools
import json
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import Mock, patch

from treasury import founder
from treasury.crypto_utils import load_public_key
from treasury.group import G, P, Q, is_valid_element, random_exponent
from treasury.opening import (DecryptionProof, DecryptionShare, OpeningError,
                              combine_decryption_shares, decrypt_vault, load_member_share,
                              load_public_vault, make_decryption_share, member_share_path,
                              public_share_key, recover_message, threshold_decrypt,
                              verify_decryption_share)
from treasury.sharing import make_commitments, make_shares, random_nonzero_scalar


def fresh_sharing(t=3, n=5):
    """A valid Shamir sharing (no zero coefficients/shares) and an ElGamal ciphertext to h."""
    while True:
        secret = random_nonzero_scalar(Q)
        coefficients, shares = make_shares(secret, t, n, Q)
        commitments = make_commitments(coefficients, P, Q, G)
        if all(is_valid_element(c) for c in commitments) and all(shares):
            break
    m = pow(G, random_exponent(Q), P)
    r = random_exponent(Q)
    c1, c2 = pow(G, r, P), m * pow(commitments[0], r, P) % P
    return shares, commitments, m, c1, c2


class ProofTests(unittest.TestCase):
    def setUp(self):
        self.shares, self.commitments, self.m, self.c1, self.c2 = fresh_sharing()
        self.h3 = public_share_key(3, self.commitments)
        self.share3 = make_decryption_share(self.shares[2], 3, self.c1, self.h3)

    def test_public_share_key_is_g_to_the_share(self):
        for i, s_i in enumerate(self.shares, start=1):
            self.assertEqual(public_share_key(i, self.commitments), pow(G, s_i, P))

    def test_honest_share_and_proof_verify(self):
        self.assertEqual(self.share3.d, pow(self.c1, self.shares[2], P))
        self.assertTrue(verify_decryption_share(self.share3, self.c1, self.h3))

    def test_tampered_values_are_rejected(self):
        proof = self.share3.proof
        bad_shares = [
            replace(self.share3, d=self.share3.d * G % P),            # A5's corrupted d_3 * g
            replace(self.share3, index=2),                            # claims another member
            replace(self.share3, proof=replace(proof, z=(proof.z + 1) % Q)),
            replace(self.share3, proof=replace(proof, e=(proof.e + 1) % Q)),
            replace(self.share3, proof=replace(proof, T1=proof.T1 * G % P)),
            replace(self.share3, proof=replace(proof, T2=proof.T2 * G % P)),
            replace(self.share3, proof=None),                         # missing proof
        ]
        for bad in bad_shares:
            self.assertFalse(verify_decryption_share(bad, self.c1, self.h3), bad)

    def test_proof_is_bound_to_c1_and_h_i(self):
        other_c1 = pow(G, random_exponent(Q), P)
        self.assertFalse(verify_decryption_share(self.share3, other_c1, self.h3))
        self.assertFalse(verify_decryption_share(self.share3, self.c1, public_share_key(2, self.commitments)))

    def test_identity_and_out_of_group_values_are_rejected(self):
        self.assertFalse(verify_decryption_share(replace(self.share3, d=1), self.c1, self.h3))
        self.assertFalse(verify_decryption_share(replace(self.share3, d=P - 1), self.c1, self.h3))
        self.assertFalse(verify_decryption_share(self.share3, 1, self.h3))

    def test_fresh_w_every_time(self):
        again = make_decryption_share(self.shares[2], 3, self.c1, self.h3)
        self.assertEqual(again.d, self.share3.d)
        self.assertNotEqual(again.proof.T1, self.share3.proof.T1)

    def test_member_refuses_share_that_does_not_match_commitments(self):
        with self.assertRaises(OpeningError):
            make_decryption_share(self.shares[1], 3, self.c1, self.h3)
        with self.assertRaises(OpeningError):
            make_decryption_share(0, 3, self.c1)
        with self.assertRaises(OpeningError):
            make_decryption_share(self.shares[2], 3, 1)

    def test_wire_round_trip_and_malformed_input(self):
        wire = json.loads(json.dumps(self.share3.to_dict()))
        self.assertEqual(len(wire["d"]), 512)
        self.assertEqual(DecryptionShare.from_dict(wire), self.share3)
        for bad in ({"index": 3}, {"index": "3", "d": wire["d"], "proof": wire["proof"]},
                    {**wire, "d": wire["d"].upper()}, {**wire, "proof": {"T1": wire["proof"]["T1"]}},
                    {**wire, "extra": 1}):
            with self.assertRaises(OpeningError):
                DecryptionShare.from_dict(bad)


class CombineTests(unittest.TestCase):
    def setUp(self):
        self.shares, self.commitments, self.m, self.c1, self.c2 = fresh_sharing()
        self.dec = [make_decryption_share(s, i, self.c1, public_share_key(i, self.commitments))
                    for i, s in enumerate(self.shares, start=1)]

    def test_every_3_of_5_subset_recovers_m(self):
        for subset in itertools.combinations(self.dec, 3):
            D = combine_decryption_shares(subset)
            self.assertEqual(recover_message(self.c2, D), self.m)
            result = threshold_decrypt(self.c1, self.c2, self.commitments, subset, 3, 5)
            self.assertEqual(result.m, self.m)

    def test_two_shares_are_not_enough(self):
        for pair in itertools.combinations(self.dec, 2):
            self.assertNotEqual(recover_message(self.c2, combine_decryption_shares(pair)), self.m)
            with self.assertRaises(OpeningError):
                threshold_decrypt(self.c1, self.c2, self.commitments, pair, 3, 5)

    def test_extra_shares_use_first_t_valid(self):
        result = threshold_decrypt(self.c1, self.c2, self.commitments, reversed(self.dec), 3, 5)
        self.assertEqual((result.m, result.used, result.rejected), (self.m, [1, 2, 3], {}))

    def test_a5_secure_rejects_cheater_and_continues(self):
        cheat = DecryptionShare(3, self.dec[2].d * G % P, None)          # d_3 * g, no proof
        result = threshold_decrypt(self.c1, self.c2, self.commitments,
                                   [self.dec[0], self.dec[1], cheat, self.dec[3]], 3, 5)
        self.assertEqual(result.m, self.m)
        self.assertEqual(result.used, [1, 2, 4])
        self.assertIn(3, result.rejected)

    def test_a5_secure_fails_closed_when_too_few_honest(self):
        cheat = DecryptionShare(3, self.dec[2].d * G % P, None)
        with self.assertRaises(OpeningError):
            threshold_decrypt(self.c1, self.c2, self.commitments, [self.dec[0], self.dec[1], cheat], 3, 5)

    def test_a5_weak_no_proof_gives_wrong_m(self):
        cheat = DecryptionShare(3, self.dec[2].d * G % P, None)
        result = threshold_decrypt(self.c1, self.c2, self.commitments,
                                   [self.dec[0], self.dec[1], cheat], 3, 5, verify_proofs=False)
        self.assertNotEqual(result.m, self.m)

    def test_caller_checks(self):
        with self.assertRaises(OpeningError):
            threshold_decrypt(self.c1, self.c2, self.commitments[:2], self.dec, 3, 5)  # len != t
        outsider = replace(self.dec[0], index=6)
        result = threshold_decrypt(self.c1, self.c2, self.commitments,
                                   [outsider] + self.dec[1:4], 3, 5)
        self.assertEqual(result.rejected[6], "member index out of range")
        result = threshold_decrypt(self.c1, self.c2, self.commitments,
                                   [self.dec[0], self.dec[0], self.dec[1], self.dec[2]], 3, 5)
        self.assertEqual(result.rejected[1], "duplicate share")
        with self.assertRaises(OpeningError):
            combine_decryption_shares([self.dec[0], self.dec[0]])

    def test_works_for_any_ciphertext_like_m3_tally(self):
        """M3 reuse: threshold-decrypt an arbitrary ElGamal ciphertext of g^T."""
        h = self.commitments[0]
        T = 4
        r = random_exponent(Q)
        c1, c2 = pow(G, r, P), pow(G, T, P) * pow(h, r, P) % P
        dec = [make_decryption_share(s, i, c1, public_share_key(i, self.commitments))
               for i, s in enumerate(self.shares, start=1)]
        result = threshold_decrypt(c1, c2, self.commitments, dec[2:], 3, 5)
        self.assertEqual(result.m, pow(G, T, P))


class VaultFileTests(unittest.TestCase):
    """End to end with Member 1's real founder setup: 3 members open the vault, 2 cannot."""

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = root = Path(tmp.name)
        for name, value in (("DATA_DIR", root), ("FOUNDER_DIR", root / "founder"),
                            ("FOUNDER_PRIVATE", root / "founder" / "founder_private.pem"),
                            ("FOUNDER_PUBLIC", root / "founder.pub"), ("VAULT_DIR", root / "vault"),
                            ("GENERATIONS_DIR", root / "vault" / "generations"),
                            ("CURRENT_FILE", root / "vault" / "current.json")):
            p = patch.object(founder, name, value)
            p.start()
            self.addCleanup(p.stop)
        founder.setup_ca(Mock())
        founder.setup_vault(Mock())
        self.founder_pub = load_public_key(founder.FOUNDER_PUBLIC.read_text())
        self.vault = load_public_vault(self.founder_pub, root)

    def member_share(self, name):
        s_i = load_member_share(name, self.vault, self.root)
        i = int(name[1:])
        return make_decryption_share(s_i, i, self.vault.c1, public_share_key(i, self.vault.commitments))

    def test_three_members_open_the_vault_two_cannot(self):
        shares = [self.member_share(n) for n in ("M1", "M3", "M5")]
        result = threshold_decrypt(self.vault.c1, self.vault.c2, self.vault.commitments,
                                   shares, self.vault.t, self.vault.n)
        self.assertEqual(decrypt_vault(result.m, self.vault), founder.VAULT_PLAINTEXT)
        wrong_m = recover_message(self.vault.c2, combine_decryption_shares(shares[:2]))
        with self.assertRaises(OpeningError):
            decrypt_vault(wrong_m, self.vault)

    def test_a5_weak_combination_cannot_open_vault(self):
        good = [self.member_share(n) for n in ("M1", "M2")]
        cheat = DecryptionShare(3, self.member_share("M3").d * G % P, None)
        result = threshold_decrypt(self.vault.c1, self.vault.c2, self.vault.commitments,
                                   good + [cheat], 3, 5, verify_proofs=False)
        with self.assertRaises(OpeningError):
            decrypt_vault(result.m, self.vault)

    def _rewrite(self, rel, mutate):
        path = self.root / "vault" / "generations" / self.vault.generation / rel
        data = json.loads(path.read_text())
        mutate(data)
        path.write_text(json.dumps(data))

    def test_modified_public_data_is_rejected(self):
        self._rewrite("public/vault.json", lambda d: d.update(c1=d["c2"]))
        with self.assertRaises(OpeningError):
            load_public_vault(self.founder_pub, self.root)

    def test_wrong_founder_key_is_rejected(self):
        from treasury.crypto_utils import generate_p256_keypair
        _, pem = generate_p256_keypair()
        with self.assertRaises(OpeningError):
            load_public_vault(load_public_key(pem), self.root)

    def test_member_share_checks(self):
        path = member_share_path("M2", self.vault.generation, self.root)
        record = json.loads(path.read_text())
        good = dict(record)
        for bad in ({**good, "index": 3}, {**good, "generation": "generation-999"},
                    {**good, "s_i": format((int(good["s_i"], 16) + 1) % Q, "0512x")}):
            path.write_text(json.dumps(bad))
            with self.assertRaises(OpeningError):
                load_member_share("M2", self.vault, self.root)
        path.write_text(json.dumps(good))
        self.assertTrue(load_member_share("M2", self.vault, self.root))
        with self.assertRaises(OpeningError):
            load_member_share("M6", self.vault, self.root)


if __name__ == "__main__":
    unittest.main()
