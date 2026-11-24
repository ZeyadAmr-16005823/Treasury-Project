import itertools
import unittest

from attacks.a3_short_challenge import forge_response, measure_success
from treasury.group import G, P, Q, is_valid_element
from treasury.login import register_login_secret, verify_interactive_login


class ShortChallengeAttackTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        _, cls.X = register_login_secret("A3-victim", P, Q, G)

    def test_forged_proof_is_accepted_only_for_guessed_challenge(self):
        guess, z = 9, 123456
        R, z = forge_response(self.X, guess, z)
        self.assertTrue(is_valid_element(R))
        self.assertTrue(verify_interactive_login(R, z, guess, self.X, P, Q, G))
        self.assertFalse(verify_interactive_login(R, z, guess + 1, self.X, P, Q, G))

    def test_weak_success_rate_is_one_in_sixteen_deterministically(self):
        guesses = itertools.cycle(range(16))
        trials = 64
        successes, total = measure_success(
            trials, self.X, weak=True,
            guess_source=lambda: next(guesses),
            challenge_source=lambda: 0,
        )
        self.assertEqual(total, trials)
        self.assertEqual(successes, trials // 16)

    def test_secure_challenge_is_not_guessable(self):
        successes, total = measure_success(
            16, self.X, weak=False,
            guess_source=lambda: 0x123456789ABCDEF,
            challenge_source=lambda: 0x123456789ABCDF0,
        )
        self.assertEqual(total, 16)
        self.assertEqual(successes, 0)

    def test_trials_must_be_positive(self):
        for trials in (0, -1, True, 2.5):
            with self.subTest(trials=trials):
                with self.assertRaises(ValueError):
                    measure_success(trials, self.X)


if __name__ == "__main__":
    unittest.main()
