import unittest

from treasury.encoding import H
from treasury.group import G, P, Q, is_valid_element, random_exponent
from treasury.login import (SECURE_CHALLENGE_BITS, WEAK_CHALLENGE_BITS,
                            generate_challenge, make_interactive_response,
                            make_noninteractive_response, register_login_secret,
                            verify_interactive_login,
                            verify_noninteractive_login)


class LoginTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.x, cls.X = register_login_secret("M1", P, Q, G)

    def test_registration_produces_subgroup_element_and_fresh_secrets(self):
        self.assertTrue(1 <= self.x < Q)
        self.assertEqual(self.X, pow(G, self.x, P))
        self.assertTrue(is_valid_element(self.X))

        other_x, other_X = register_login_secret("M1", P, Q, G)
        self.assertNotEqual(other_x, self.x)
        self.assertNotEqual(other_X, self.X)

    def test_registration_rejects_invalid_name_and_parameters(self):
        for name in ("", "   ", None, 17, b"M1"):
            with self.subTest(name=name):
                with self.assertRaises(ValueError):
                    register_login_secret(name, P, Q, G)
        with self.assertRaises(ValueError):
            register_login_secret("M1", P, Q, 1)

    def test_honest_interactive_login_verifies(self):
        challenge = generate_challenge()
        R, z = make_interactive_response(self.x, challenge, Q)
        self.assertTrue(verify_interactive_login(R, z, challenge, self.X, P, Q, G))

    def test_deterministic_challenge_source_gives_reproducible_challenge(self):
        challenge = generate_challenge(source=lambda: 0x5A)
        self.assertEqual(challenge, 0x5A)
        R1, z1 = make_interactive_response(self.x, challenge, Q)
        R2, z2 = make_interactive_response(self.x, challenge, Q)
        self.assertNotEqual(R1, R2)
        self.assertTrue(verify_interactive_login(R1, z1, challenge, self.X, P, Q, G))
        self.assertTrue(verify_interactive_login(R2, z2, challenge, self.X, P, Q, G))

    def test_interactive_rejects_wrong_response_values(self):
        challenge = 12345
        R, z = make_interactive_response(self.x, challenge, Q)
        _, other_X = register_login_secret("M2", P, Q, G)

        self.assertFalse(verify_interactive_login(R, (z + 1) % Q, challenge,
                                                  self.X, P, Q, G))
        self.assertFalse(verify_interactive_login(R, z, (challenge + 1) % Q,
                                                  self.X, P, Q, G))
        self.assertFalse(verify_interactive_login(R, z, challenge, other_X, P, Q, G))
        self.assertFalse(verify_interactive_login(pow(R, 2, P), z, challenge,
                                                  self.X, P, Q, G))

    def test_interactive_rejects_invalid_group_elements_and_ranges(self):
        challenge = 12345
        R, z = make_interactive_response(self.x, challenge, Q)

        self.assertFalse(verify_interactive_login(1, z, challenge, self.X, P, Q, G))
        self.assertFalse(verify_interactive_login(R, Q, challenge, self.X, P, Q, G))
        self.assertFalse(verify_interactive_login(R, -1, challenge, self.X, P, Q, G))
        self.assertFalse(verify_interactive_login(R, z, challenge, P - 4, P, Q, G))
        self.assertFalse(verify_interactive_login("R", z, challenge, self.X, P, Q, G))
        self.assertFalse(verify_interactive_login(R, True, challenge, self.X, P, Q, G))

    def test_challenge_ranges_and_injection(self):
        secure = generate_challenge()
        self.assertTrue(0 <= secure < 1 << SECURE_CHALLENGE_BITS)
        weak = generate_challenge(weak=True)
        self.assertTrue(0 <= weak < 1 << WEAK_CHALLENGE_BITS)

        self.assertEqual(generate_challenge(bits=8, source=lambda: 255), 255)
        self.assertEqual(generate_challenge(weak=True, source=lambda: 15), 15)
        with self.assertRaises(ValueError):
            generate_challenge(weak=True, source=lambda: 16)
        with self.assertRaises(ValueError):
            generate_challenge(bits=0)
        with self.assertRaises(ValueError):
            generate_challenge(source=lambda: -1)

    def test_noninteractive_login_verifies_and_is_identity_bound(self):
        nonce = "server-nonce-1"
        R, z = make_noninteractive_response(self.x, "M1", nonce)
        self.assertTrue(verify_noninteractive_login("M1", R, z, nonce, self.X))
        self.assertFalse(verify_noninteractive_login("M2", R, z, nonce, self.X))

    def test_noninteractive_login_is_nonce_bound(self):
        R, z = make_noninteractive_response(self.x, "M1", "nonce-a")
        self.assertFalse(verify_noninteractive_login("M1", R, z, "nonce-b", self.X))
        self.assertTrue(verify_noninteractive_login("M1", R, z, "nonce-a", self.X))

    def test_noninteractive_rejects_tampered_proof_and_identity(self):
        nonce = "server-nonce-2"
        R, z = make_noninteractive_response(self.x, "M1", nonce)
        _, other_X = register_login_secret("M2", P, Q, G)

        self.assertFalse(verify_noninteractive_login("M1", pow(R, 2, P), z,
                                                     nonce, self.X))
        self.assertFalse(verify_noninteractive_login("M1", R, (z + 1) % Q,
                                                     nonce, self.X))
        self.assertFalse(verify_noninteractive_login("M1", R, z, nonce, other_X))
        self.assertFalse(verify_noninteractive_login("M1", 1, z, nonce, self.X))
        self.assertFalse(verify_noninteractive_login("M1", R, Q, nonce, self.X))

    def test_noninteractive_rejects_missing_name_or_nonce(self):
        nonce = "server-nonce-3"
        with self.assertRaises(ValueError):
            make_noninteractive_response(self.x, "", nonce)
        with self.assertRaises(ValueError):
            make_noninteractive_response(self.x, "M1", "")
        R, z = make_noninteractive_response(self.x, "M1", nonce)
        self.assertFalse(verify_noninteractive_login("", R, z, nonce, self.X))
        self.assertFalse(verify_noninteractive_login("M1", R, z, "", self.X))
        self.assertFalse(verify_noninteractive_login("M1", R, z, None, self.X))


    def test_noninteractive_uses_exact_login_label(self):
        nonce = "00000000000000000000000000000001"
        R, z = make_noninteractive_response(self.x, "M1", nonce)
        challenge = H("login", "M1", self.X, R, nonce, q=Q)
        self.assertTrue(verify_noninteractive_login("M1", R, z, nonce, self.X))
        self.assertNotEqual(challenge, H("login-ni", "M1", self.X, R, nonce, q=Q))

    def test_noninteractive_rejects_proof_created_with_wrong_label(self):
        """A valid proof for the old label must be rejected by the verifier."""
        name, nonce = "M1", "00000000000000000000000000000002"
        k = random_exponent(Q)
        R = pow(G, k, P)
        wrong_challenge = H("login-ni", name, self.X, R, nonce, q=Q)
        z = (k + wrong_challenge * self.x) % Q
        self.assertTrue(pow(G, z, P) == (R * pow(self.X, wrong_challenge, P)) % P)
        self.assertFalse(verify_noninteractive_login(name, R, z, nonce, self.X))

    def test_same_nonce_string_gives_identical_challenge(self):
        nonce = "00000000000000000000000000000003"
        R, X_M, name = pow(G, 54321, P), self.X, "M1"
        self.assertEqual(H("login", name, X_M, R, nonce, q=Q),
                         H("login", name, X_M, R, nonce, q=Q))
        first = make_noninteractive_response(self.x, name, nonce)
        second = make_noninteractive_response(self.x, name, nonce)
        self.assertTrue(verify_noninteractive_login(name, *first, nonce, X_M))
        self.assertTrue(verify_noninteractive_login(name, *second, nonce, X_M))

    def test_different_nonce_changes_challenge_for_fixed_inputs(self):
        nonce_a = "00000000000000000000000000000001"
        nonce_b = "00000000000000000000000000000002"
        R, X_M, name = pow(G, 12345, P), self.X, "M1"
        challenge_a = H("login", name, X_M, R, nonce_a, q=Q)
        challenge_b = H("login", name, X_M, R, nonce_b, q=Q)
        self.assertNotEqual(challenge_a, challenge_b)

    def test_leading_zero_nonce_is_preserved_verbatim(self):
        nonce = "0000000000000000000000000000000f"  # 32 lowercase hex characters
        self.assertEqual(len(nonce), 32)
        R, z = make_noninteractive_response(self.x, "M1", nonce)
        self.assertTrue(verify_noninteractive_login("M1", R, z, nonce, self.X))
        exact = H("login", "M1", self.X, R, nonce, q=Q)
        normalized = H("login", "M1", self.X, R, nonce.lstrip("0"), q=Q)
        self.assertNotEqual(exact, normalized)

    def test_integer_nonce_is_not_equivalent_to_hex_string(self):
        nonce = "0000000000000000000000000000000f"
        R, z = make_noninteractive_response(self.x, "M1", nonce)
        self.assertFalse(verify_noninteractive_login("M1", R, z, int(nonce, 16), self.X))
        as_string = H("login", "M1", self.X, R, nonce, q=Q)
        as_integer = H("login", "M1", self.X, R, int(nonce, 16), q=Q)
        self.assertNotEqual(as_string, as_integer)


if __name__ == "__main__":
    unittest.main()
