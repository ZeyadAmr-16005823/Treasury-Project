import unittest

from treasury.config import GROUP
from treasury.crypto_utils import generate_p256_keypair, load_public_key
from treasury.requests import request_transcript, sign_request, verify_request


class SignedRequestTests(unittest.TestCase):
    def setUp(self):
        private_key, pem = generate_p256_keypair()
        self.public_key = load_public_key(pem)
        self.private_key = private_key
        self.request = sign_request(private_key, GROUP, "M1", 1, "spend",
                                    {"amount": 50, "reason": "pizza"})

    def test_transcript_and_valid_request(self):
        self.assertEqual(
            request_transcript(GROUP, "M1", 1, "spend", {"amount": 50, "reason": "pizza"}),
            ["request", GROUP, "M1", 1, "spend", {"amount": 50, "reason": "pizza"}],
        )
        self.assertTrue(verify_request(self.public_key, self.request, 0))

    def test_replay_is_rejected(self):
        self.assertFalse(verify_request(self.public_key, self.request, 1))
        self.assertFalse(verify_request(self.public_key, self.request, 2))

    def test_tampered_request_is_rejected(self):
        for field, value in (("op", "refund"), ("seq", 2), ("name", "M2"),
                             ("body", {"amount": 500, "reason": "pizza"})):
            tampered = dict(self.request, **{field: value})
            self.assertFalse(verify_request(self.public_key, tampered, 0))

    def test_malformed_request_is_rejected(self):
        self.assertFalse(verify_request(self.public_key, dict(self.request, sig="0" * 64), 0))
        self.assertFalse(verify_request(self.public_key, dict(self.request, seq=True), 0))
        self.assertFalse(verify_request(self.public_key, dict(self.request, body="pizza"), 0))
        self.assertFalse(verify_request(self.public_key, {"op": "spend"}, 0))


if __name__ == "__main__":
    unittest.main()
