import unittest

from treasury.group import G, P, Q, is_valid_element, random_exponent


def _arctan_inverse(x: int, scale: int) -> int:
    """Fixed-point arctan(1/x) scaled by ``scale`` (truncated per term)."""
    total = 0
    power = x
    denominator = 1
    sign = 1
    while True:
        term = scale // (denominator * power)
        if term == 0:
            return total
        total += sign * term
        sign = -sign
        power *= x * x
        denominator += 2


def _is_probable_prime(n: int, bases: tuple[int, ...]) -> bool:
    if n < 2:
        return False
    for small in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
        if n % small == 0:
            return n == small
    d, s = n - 1, 0
    while d % 2 == 0:
        d //= 2
        s += 1
    for base in bases:
        x = pow(base, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


class GroupTests(unittest.TestCase):
    def test_prime_matches_rfc3526_integer_formula(self):
        guard_bits = 256
        precision = 1918 + guard_bits
        scale = 1 << precision
        pi_fixed = 4 * (4 * _arctan_inverse(5, scale)
                        - _arctan_inverse(239, scale))
        floor_pi = pi_fixed >> (precision - 1918)
        expected = (2 ** 2048 - 2 ** 1984 - 1
                    + 2 ** 64 * (floor_pi + 124476))
        self.assertEqual(P, expected)

    def test_prime_shape_and_rfc_hex_endpoints(self):
        self.assertEqual(P.bit_length(), 2048)
        self.assertEqual(len(f"{P:x}"), 512)
        self.assertTrue(f"{P:X}".startswith("FFFFFFFFFFFFFFFFC90FDAA2"))
        self.assertTrue(f"{P:X}".endswith("FFFFFFFFFFFFFFFF"))

    def test_safe_prime_relation_and_primality(self):
        self.assertEqual(Q, (P - 1) // 2)
        self.assertTrue(_is_probable_prime(P, (2, 3, 5, 7, 11)))
        self.assertTrue(_is_probable_prime(Q, (2, 3, 5, 7, 11)))

    def test_generator_has_order_q(self):
        self.assertEqual(G, 4)
        self.assertNotEqual(G, 1)
        self.assertEqual(pow(G, Q, P), 1)
        self.assertTrue(is_valid_element(G))

    def test_accepts_subgroup_elements(self):
        for exponent in (1, 2, 3, 12345, Q - 1):
            with self.subTest(exponent=exponent):
                self.assertTrue(is_valid_element(pow(G, exponent, P)))

    def test_rejects_identity_out_of_range_and_non_integers(self):
        for value in (0, 1, P - 1, P, P + 1, -1, -P, True, False, 3.0, "4", None):
            with self.subTest(value=value):
                self.assertFalse(is_valid_element(value))

    def test_rejects_quadratic_non_residues(self):
        for value in (P - 4, P - 9):
            with self.subTest(value=f"P-{P - value}"):
                self.assertNotEqual(pow(value, Q, P), 1)
                self.assertFalse(is_valid_element(value))

    def test_random_exponent_is_in_range(self):
        values = [random_exponent() for _ in range(100)]
        self.assertTrue(all(1 <= value < Q for value in values))
        self.assertTrue(1 <= random_exponent(17) < 17)

    def test_random_exponent_rejects_invalid_modulus(self):
        for q in (2, 0, -5, True, 3.0):
            with self.subTest(q=q):
                with self.assertRaises(ValueError):
                    random_exponent(q)


if __name__ == "__main__":
    unittest.main()
