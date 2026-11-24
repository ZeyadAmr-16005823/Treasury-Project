"""A1 unsigned-handshake MITM (Member 2): Mallory proxy against the real server and member."""
import logging
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from attacks.a1_unsigned_handshake import build_world, run_scenario
from treasury import member
from treasury.mallory import describe, main as mallory_main, tamper_request


def quiet(name):
    log = logging.getLogger(f"test-a1-{name}")
    log.handlers[:] = [logging.NullHandler()]
    log.propagate = False
    return log


class A1AttackTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        patcher = mock.patch.object(member, "DATA_DIR", Path(self.tmp.name))
        patcher.start()
        self.addCleanup(patcher.stop)
        self.world = build_world(Path(self.tmp.name))
        self.logs = (quiet("server"), quiet("mallory"), quiet("member"))

    def scenario(self, **options):
        return run_scenario(self.world, logs=self.logs, **options)

    def test_weak_handshake_lets_mallory_read_everything(self):
        outcome = self.scenario(weak=True)
        self.assertTrue(outcome.member_ok, outcome.member_error)
        types = [m.get("type") for m in outcome.interception.seen]
        for expected in ("register", "login", "challenge", "login-response", "request", "bye"):
            self.assertIn(expected, types)
        request = next(m for m in outcome.interception.seen if m["type"] == "request")
        self.assertEqual(request["request"]["body"], {"amount": 50, "reason": "team pizza"})
        self.assertTrue(outcome.interception.request_results[0]["ok"])

    def test_noninteractive_login_is_also_readable(self):
        outcome = self.scenario(weak=True, login_mode="noninteractive")
        self.assertTrue(outcome.member_ok, outcome.member_error)
        self.assertIn("login-nonce", [m.get("type") for m in outcome.interception.seen])

    def test_modified_signed_request_is_rejected(self):
        self.scenario(weak=True)  # register first
        outcome = self.scenario(weak=True, tamper="modify")
        self.assertFalse(outcome.member_ok)
        result = outcome.interception.request_results[-1]
        self.assertFalse(result["ok"])
        self.assertIn("signature", result["error"])

    def test_replayed_signed_request_is_rejected(self):
        self.scenario(weak=True)
        outcome = self.scenario(weak=True, tamper="replay")
        original, replay = outcome.interception.request_results
        self.assertTrue(original["ok"])
        self.assertTrue(replay["replay"])
        self.assertFalse(replay["ok"])

    def test_signed_handshake_defeats_mallory(self):
        outcome = self.scenario(weak=False)
        self.assertFalse(outcome.member_ok)
        self.assertIn("invalid server handshake signature", outcome.member_error)
        self.assertEqual(outcome.interception.seen, [])
        self.assertIsNotNone(outcome.interception.handshake_failed)

    def test_helpers(self):
        message = {"type": "request", "request": {"name": "M1", "seq": 1, "op": "spend",
                                                  "body": {"amount": 50}, "sig": "ab" * 64}}
        forged = tamper_request(message)
        self.assertEqual(forged["request"]["body"]["amount"], 5000)
        self.assertEqual(forged["request"]["sig"], message["request"]["sig"])
        self.assertEqual(message["request"]["body"], {"amount": 50})  # original untouched
        self.assertIn("SIGNED REQUEST", describe(message))

    def test_cli_requires_matching_weakness(self):
        with self.assertRaises(SystemExit):
            mallory_main(["--attack", "A1", "--weak", "no-proof"])


if __name__ == "__main__":
    unittest.main()
