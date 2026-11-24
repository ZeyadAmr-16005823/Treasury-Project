import itertools
import unittest

from treasury.group import G, P, Q
from treasury.sharing import (
    evaluate_polynomial,
    hex_element,
    is_subgroup_element,
    lagrange_coefficient,
    make_commitments,
    make_shares,
    verify_share,
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

    def test_zero_coefficients_and_identity_commitments(self):
        secret = 555
        coefficients = [secret, 0, 0]
        commitments = make_commitments(coefficients, P, Q, G)
        self.assertEqual(commitments[1], 1)
        self.assertEqual(commitments[2], 1)
        self.assertTrue(verify_share(secret, 3, commitments, P, Q, G))
        self.assertFalse(verify_share(secret + 1, 3, commitments, P, Q, G))

        # A polynomial with f(1)=0 produces a zero share and h_i=1.
        a2 = 1
        a1 = (-secret - a2) % Q
        zero_share_poly = [secret, a1, a2]
        self.assertEqual(evaluate_polynomial(zero_share_poly, 1, Q), 0)
        zero_commitments = make_commitments(zero_share_poly, P, Q, G)
        self.assertTrue(verify_share(0, 1, zero_commitments, P, Q, G))

    def test_zero_highest_coefficient_is_a_documented_exception(self):
        secret = 321
        coefficients = [secret, 999, 0]
        self.assertNotEqual(coefficients[1], 0)  # nonzero a1: two shares determine s
        commitments = make_commitments(coefficients, P, Q, G)
        self.assertEqual(commitments[-1], 1)  # C_2 = g^0 = 1 is public evidence
        shares = [evaluate_polynomial(coefficients, i, Q) for i in range(1, 6)]
        for index, share in enumerate(shares, start=1):
            self.assertTrue(verify_share(share, index, commitments, P, Q, G))
        # With a linear polynomial, two shares already determine the secret.
        subset = [1, 2]
        recovered = sum(shares[i - 1] * lagrange_coefficient(i, subset, Q) for i in subset) % Q
        self.assertEqual(recovered, secret)

    def test_verify_share_rejects_invalid_inputs(self):
        coefficients, shares = make_shares(777, 3, 5, Q)
        commitments = make_commitments(coefficients, P, Q, G)
        self.assertTrue(verify_share(shares[0], 1, commitments, P, Q, G))
        self.assertFalse(verify_share(shares[0] + 1, 1, commitments, P, Q, G))
        self.assertFalse(verify_share(shares[0], 0, commitments, P, Q, G))
        self.assertFalse(verify_share(shares[0], 6, commitments, P, Q, G))
        self.assertFalse(verify_share(shares[0], True, commitments, P, Q, G))
        self.assertFalse(verify_share(shares[0], 1, [1] + commitments[1:], P, Q, G))
        self.assertFalse(verify_share(shares[0], 1, [P - 4] + commitments[1:], P, Q, G))
        self.assertFalse(verify_share(shares[0], 1, commitments[:-1], P, Q, G))

    def test_subgroup_validation_and_lagrange_validation(self):
        self.assertTrue(is_subgroup_element(1, P, Q, allow_identity=True))
        self.assertFalse(is_subgroup_element(1, P, Q))
        self.assertTrue(is_subgroup_element(G, P, Q))
        self.assertFalse(is_subgroup_element(P - 4, P, Q, allow_identity=True))
        with self.assertRaises(ValueError):
            lagrange_coefficient(1, [1, 1, 2], Q)
        with self.assertRaises(ValueError):
            lagrange_coefficient(4, [1, 2, 3], Q)
        self.assertEqual(lagrange_coefficient(1, [1, 2, 3], Q), 3 % Q)

    def test_hex_element_is_fixed_width(self):
        value = hex_element(15)
        self.assertEqual(len(value), 512)
        self.assertTrue(value.endswith("0f"))
        self.assertTrue(all(c in "0123456789abcdef" for c in value))


if __name__ == "__main__":
    unittest.main()
