import itertools
import unittest

from treasury.group import G, P, Q, is_valid_element
from treasury.sharing import (
    evaluate_polynomial,
    hex_element,
    lagrange_coefficient,
    make_commitments,
    make_shares,
    verify_share,
    vault_key,
)


class SharingTests(unittest.TestCase):
    def test_polynomial_evaluation_and_shares(self):
        coefficients = [5, 2, 3]
        self.assertEqual(evaluate_polynomial(coefficients, 0, 97), 5)
        self.assertEqual(evaluate_polynomial(coefficients, 1, 97), 10)
        self.assertEqual(evaluate_polynomial(coefficients, 2, 97), 21)
        secret = 12345
        coefficients, shares = make_shares(secret, 3, 5, Q)
        self.assertEqual(len(coefficients), 3)
        self.assertEqual(coefficients[0], secret)
        self.assertEqual(len(shares), 5)
        self.assertEqual(shares, [evaluate_polynomial(coefficients, i, Q)
                                  for i in range(1, 6)])

    def test_all_ten_three_of_five_subsets_reconstruct(self):
        secret = 987654321
        coefficients, shares = make_shares(secret, 3, 5, Q)
        subsets = list(itertools.combinations(range(1, 6), 3))
        self.assertEqual(len(subsets), 10)
        for subset in subsets:
            with self.subTest(subset=subset):
                recovered = sum(
                    shares[i - 1] * lagrange_coefficient(i, list(subset), Q)
                    for i in subset
                ) % Q
                self.assertEqual(recovered, secret)

    def test_generic_two_of_four_parameters(self):
        secret = 424242
        _, shares = make_shares(secret, 2, 4, Q)
        self.assertEqual(len(shares), 4)
        for subset in itertools.combinations(range(1, 5), 2):
            recovered = sum(shares[i - 1] * lagrange_coefficient(i, list(subset), Q)
                            for i in subset) % Q
            self.assertEqual(recovered, secret)

    def test_fewer_than_threshold_shares_allow_many_secrets(self):
        coefficients = [11, 7, 13]
        known = (1, 2)
        shares = [evaluate_polynomial(coefficients, i, Q) for i in known]
        constants = set()
        for c in (11, 12, 999):
            # g(x) = f(x) + c*(x-1)*(x-2) agrees at the known shares but
            # has a different constant term, hence a different secret.
            alternate = [
                (coefficients[0] + 2 * c) % Q,
                (coefficients[1] - 3 * c) % Q,
                (coefficients[2] + c) % Q,
            ]
            self.assertEqual([evaluate_polynomial(alternate, i, Q) for i in known], shares)
            constants.add(evaluate_polynomial(alternate, 0, Q))
        self.assertEqual(len(constants), 3)

    def test_zero_coefficients_are_rejected_by_strict_verification(self):
        # make_shares still draws coefficients from all of Z_q; verification
        # and the founder's candidate check reject the identity commitments.
        secret = 555
        coefficients = [secret, 0, 0]
        commitments = make_commitments(coefficients, P, Q, G)
        self.assertEqual(commitments[1], 1)
        self.assertEqual(commitments[2], 1)
        self.assertFalse(verify_share(secret, 3, commitments, P, Q, G))
        self.assertEqual(secret * lagrange_coefficient(1, [1], Q) % Q, secret)

        # A zero share makes h_i = 1; strict validation rejects it.
        a2 = 1
        a1 = (-secret - a2) % Q
        zero_share_poly = [secret, a1, a2]
        self.assertEqual(evaluate_polynomial(zero_share_poly, 1, Q), 0)
        zero_commitments = make_commitments(zero_share_poly, P, Q, G)
        self.assertTrue(all(is_valid_element(c) for c in zero_commitments))
        self.assertFalse(verify_share(0, 1, zero_commitments, P, Q, G))

    def test_zero_highest_coefficient_candidate_is_not_publishable(self):
        secret = 321
        coefficients = [secret, 999, 0]
        self.assertNotEqual(coefficients[1], 0)
        commitments = make_commitments(coefficients, P, Q, G)
        self.assertEqual(commitments[-1], 1)  # C_2 = g^0 = 1 is public evidence
        shares = [evaluate_polynomial(coefficients, i, Q) for i in range(1, 6)]
        for index, share in enumerate(shares, start=1):
            self.assertFalse(verify_share(share, index, commitments, P, Q, G))
        # The helper still reconstructs with two shares; the founder rejects
        # this candidate before publication (see test_founder_m2.py).
        subset = [1, 2]
        recovered = sum(shares[i - 1] * lagrange_coefficient(i, subset, Q) for i in subset) % Q
        self.assertEqual(recovered, secret)

    def test_verify_share_rejects_invalid_inputs(self):
        coefficients, shares = make_shares(777, 3, 5, Q)
        commitments = make_commitments(coefficients, P, Q, G)
        self.assertTrue(verify_share(shares[0], 1, commitments, P, Q, G))
        self.assertFalse(verify_share(shares[0] + 1, 1, commitments, P, Q, G))
        self.assertFalse(verify_share(0, 1, commitments, P, Q, G))
        self.assertFalse(verify_share(shares[0], 0, commitments, P, Q, G))
        self.assertFalse(verify_share(shares[0], 6, commitments, P, Q, G))
        self.assertFalse(verify_share(shares[0], True, commitments, P, Q, G))
        self.assertFalse(verify_share(shares[0], 1, [1] + commitments[1:], P, Q, G))
        self.assertFalse(verify_share(shares[0], 1, [P - 4] + commitments[1:], P, Q, G))
        self.assertFalse(verify_share(shares[0], 1, commitments[:-1], P, Q, G))

    def test_verify_share_cannot_enforce_n_or_t(self):
        # The starter signature has no n/t: valid points outside 1..n and a
        # longer commitment list are accepted when the Feldman equation holds.
        coefficients = [111, 222, 333]
        commitments = make_commitments(coefficients, P, Q, G)
        for index in (6, 99):
            share = evaluate_polynomial(coefficients, index, Q)
            self.assertTrue(verify_share(share, index, commitments, P, Q, G))

        longer_commitments = commitments + [pow(G, 7, P)]
        degree_three_share = (evaluate_polynomial(coefficients, 1, Q) + 7) % Q
        self.assertTrue(verify_share(degree_three_share, 1, longer_commitments, P, Q, G))
        # Caller-side checks are therefore mandatory; see docs/M2_INTERFACES.md §3.

    def test_strict_group_validation_and_lagrange_validation(self):
        self.assertFalse(is_valid_element(1))
        self.assertTrue(is_valid_element(G))
        self.assertFalse(is_valid_element(P - 4))
        self.assertFalse(is_valid_element(P - 1))
        self.assertFalse(is_valid_element(True))
        with self.assertRaises(ValueError):
            lagrange_coefficient(1, [1, 1, 2], Q)
        with self.assertRaises(ValueError):
            lagrange_coefficient(4, [1, 2, 3], Q)
        self.assertEqual(lagrange_coefficient(1, [1, 2, 3], Q), 3 % Q)

    def test_vault_key_requires_strict_group_elements(self):
        m, c1, c2 = pow(G, 2, P), pow(G, 3, P), pow(G, 5, P)
        c1_hex, c2_hex, digest = hex_element(c1), hex_element(c2), "0" * 64
        self.assertEqual(len(vault_key(m, c1_hex, c2_hex, digest)), 32)

        for bad_m in (0, 1, -1, P - 1, P - 4):
            with self.subTest(m=bad_m):
                with self.assertRaises(ValueError):
                    vault_key(bad_m, c1_hex, c2_hex, digest)
        uppercase_hex = c1_hex[:10] + "A" + c1_hex[11:]
        for bad_hex in (hex_element(1), hex_element(P - 4), uppercase_hex, c1_hex[1:]):
            with self.subTest(c1_hex=bad_hex[:12]):
                with self.assertRaises(ValueError):
                    vault_key(m, bad_hex, c2_hex, digest)
        with self.assertRaises(ValueError):
            vault_key(m, c1_hex, hex_element(1), digest)

    def test_hex_element_is_fixed_width(self):
        value = hex_element(15)
        self.assertEqual(len(value), 512)
        self.assertTrue(value.endswith("0f"))
        self.assertTrue(all(c in "0123456789abcdef" for c in value))


if __name__ == "__main__":
    unittest.main()
