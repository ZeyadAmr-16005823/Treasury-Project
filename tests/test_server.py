"""Treasury server (Member 2): registration, login, signed requests, persistence."""
import json
import logging
import socket
import tempfile
import threading
import unittest
from contextlib import closing
from pathlib import Path
from unittest import mock

from attacks.a1_unsigned_handshake import build_world
from treasury import member
from treasury.channel import SecureChannel, recv_frame, recv_secure, send_frame, send_secure
from treasury.config import GROUP
from treasury.crypto_utils import generate_p256_keypair, sign_raw
from treasury.encoding import canonical_json
from treasury.group import G, P, Q
from treasury.handshake import client_handshake
from treasury.login import make_interactive_response, make_noninteractive_response
from treasury.requests import sign_request
from treasury.server import (RegistrationStore, SequenceStore, ServerPaths, TreasuryServer,
                             init_identity, load_identity, parse_hex_int)


def quiet_logger(name):
    log = logging.getLogger(f"test-{name}")
    log.handlers[:] = [logging.NullHandler()]
    log.propagate = False
    return log


class RawClient:
    """A member that speaks the wire protocol by hand, to send malicious messages."""

    def __init__(self, port, identity, weak=()):
        self.identity = identity
        self.sock = socket.create_connection(("127.0.0.1", port), timeout=5)
        self.session = client_handshake(self.sock, identity.certificate, identity.private_key,
                                        identity.founder_public_key, identity.name, set(weak))
        self.channel = SecureChannel.from_session(self.session, "member")

    def send(self, message):
        send_secure(self.sock, self.channel, message)

    def recv(self):
        return recv_secure(self.sock, self.channel)

    def ask(self, message):
        self.send(message)
        return self.recv()

    def register(self, X_M=None, sig=None):
        X_hex = format(X_M or self.identity.X_M, "x")
        sig = sig or sign_raw(self.identity.private_key,
                              canonical_json(["register", GROUP, self.identity.name, X_hex]))
        return self.ask({"type": "register", "X_M": X_hex, "sig": sig})

    def login(self):
        reply = self.ask({"type": "login", "mode": "noninteractive"})
        R, z = make_noninteractive_response(self.identity.x_M, self.identity.name, reply["nonce"])
        return self.ask({"type": "login-proof", "R": format(R, "x"), "z": format(z, "x")})

    def close(self):
        self.sock.close()


class ServerTestCase(unittest.TestCase):
    weak: set = set()

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        patcher = mock.patch.object(member, "DATA_DIR", Path(self.tmp.name))
        patcher.start()
        self.addCleanup(patcher.stop)
        self.world = build_world(Path(self.tmp.name), member_names=("M1", "M2"))
        self.server = TreasuryServer(load_identity(self.world.paths), self.world.paths,
                                     quiet_logger("server"), weak=self.weak, port=0)
        self.server.start_background()
        self.addCleanup(self.server.stop)
        self.log = quiet_logger("member")

    def run_member(self, name="M1", login_mode="interactive", requests=(("spend", {"amount": 1}),)):
        identity = member.load_identity(name)
        with closing(socket.create_connection(("127.0.0.1", self.server.port), timeout=5)) as sock:
            return member.run_session(sock, identity, self.log, handshake=client_handshake,
                                      login_mode=login_mode, requests=list(requests))

    def raw(self, name="M1", register=True, login=True):
        client = RawClient(self.server.port, member.load_identity(name))
        self.addCleanup(client.close)
        if register:
            self.assertTrue(client.register()["ok"])
        if login:
            self.assertTrue(client.login()["ok"])
        return client

    def registrations(self):
        return json.loads(self.world.paths.registrations.read_text())


class EndToEndTests(ServerTestCase):
    def test_interactive_and_noninteractive_sessions_with_real_member(self):
        first = self.run_member(login_mode="interactive", requests=[("spend", {"amount": 5})] * 2)
        self.assertEqual([r["seq"] for r in first], [1, 2])
        second = self.run_member(login_mode="noninteractive")
        self.assertEqual([r["seq"] for r in second], [3])
        identity = member.load_identity("M1")
        self.assertEqual(self.registrations(), {"M1": format(identity.X_M, "x")})
        self.assertEqual(json.loads(self.world.paths.sequences.read_text()), {"M1": 3})

    def test_sequence_state_survives_server_restart(self):
        self.run_member(requests=[("spend", {"amount": 1})])
        self.server.stop()
        restarted = TreasuryServer(load_identity(self.world.paths), self.world.paths,
                                   quiet_logger("server2"), port=0)
        restarted.start_background()
        self.addCleanup(restarted.stop)
        self.assertEqual(restarted.sequences.last("M1"), 1)
        self.assertEqual(restarted.registrations.login_key("M1"), member.load_identity("M1").X_M)

    def test_two_members_are_independent(self):
        self.run_member("M1")
        self.run_member("M2")
        self.assertEqual(set(self.registrations()), {"M1", "M2"})


class RegistrationTests(ServerTestCase):
    def test_reregistering_same_key_is_idempotent(self):
        client = self.raw(login=False)
        self.assertEqual(client.register()["status"], "already-registered")

    def test_first_X_M_is_kept_and_a_different_one_rejected(self):
        self.raw(login=False).close()
        other_X = pow(G, 12345, P)
        reply = self.raw(register=False, login=False).register(X_M=other_X)
        self.assertFalse(reply["ok"])
        self.assertIn("already registered", reply["error"])
        self.assertEqual(self.registrations()["M1"], format(member.load_identity("M1").X_M, "x"))

    def test_bad_signature_and_invalid_element_rejected(self):
        bad_sig = self.raw(register=False, login=False).register(sig="00" * 64)
        self.assertFalse(bad_sig["ok"])
        self.assertIn("signature", bad_sig["error"])
        not_in_subgroup = self.raw(register=False, login=False).register(X_M=P - 1)
        self.assertFalse(not_in_subgroup["ok"])
        self.assertFalse(self.world.paths.registrations.exists())

    def test_registration_signed_for_another_name_is_rejected(self):
        client = self.raw(register=False, login=False)
        X_hex = format(client.identity.X_M, "x")
        sig = sign_raw(client.identity.private_key, canonical_json(["register", GROUP, "M2", X_hex]))
        self.assertFalse(client.ask({"type": "register", "X_M": X_hex, "sig": sig})["ok"])


class LoginTests(ServerTestCase):
    def test_login_before_registration_rejected(self):
        client = self.raw(register=False, login=False)
        reply = client.ask({"type": "login", "mode": "noninteractive"})
        self.assertEqual(reply, {"type": "login-result", "ok": False, "error": "member is not registered"})

    def test_wrong_interactive_response_rejected(self):
        client = self.raw(login=False)
        R, z = make_interactive_response(client.identity.x_M, 0, Q)
        challenge = client.ask({"type": "login", "mode": "interactive", "R": format(R, "x")})
        self.assertEqual(challenge["type"], "challenge")
        # z computed for e=0 instead of the real challenge -> must fail
        reply = client.ask({"type": "login-response", "z": format(z, "x")})
        self.assertFalse(reply["ok"])
        self.assertIsNone(client.recv())  # server closed the connection

    def test_proof_for_another_nonce_rejected(self):
        client = self.raw(login=False)
        client.ask({"type": "login", "mode": "noninteractive"})
        R, z = make_noninteractive_response(client.identity.x_M, "M1", "00" * 16)
        reply = client.ask({"type": "login-proof", "R": format(R, "x"), "z": format(z, "x")})
        self.assertFalse(reply["ok"])

    def test_proof_without_issued_nonce_rejected(self):
        client = self.raw(login=False)
        R, z = make_noninteractive_response(client.identity.x_M, "M1", "ab" * 16)
        reply = client.ask({"type": "login-proof", "R": format(R, "x"), "z": format(z, "x")})
        self.assertEqual(reply["error"], "no outstanding login nonce for this session")

    def test_another_members_secret_cannot_log_in(self):
        self.raw("M2", login=False).close()
        client = self.raw("M1", login=False)
        m2 = member.load_identity("M2")
        nonce = client.ask({"type": "login", "mode": "noninteractive"})["nonce"]
        R, z = make_noninteractive_response(m2.x_M, "M1", nonce)
        self.assertFalse(client.ask({"type": "login-proof", "R": format(R, "x"),
                                     "z": format(z, "x")})["ok"])

    def test_malformed_hex_rejected(self):
        client = self.raw(login=False)
        reply = client.ask({"type": "login", "mode": "interactive", "R": "0x10"})
        self.assertFalse(reply["ok"])


class RequestTests(ServerTestCase):
    def signed(self, client, seq, body=None, name=None):
        return sign_request(client.identity.private_key, GROUP, name or client.identity.name, seq,
                            "spend", body or {"amount": 10})

    def test_request_before_login_rejected(self):
        client = self.raw(login=False)
        reply = client.ask({"type": "request", "request": self.signed(client, 1)})
        self.assertEqual(reply["error"], "login required before requests")

    def test_replay_and_old_sequence_rejected_across_sessions(self):
        client = self.raw()
        request = self.signed(client, 1)
        self.assertTrue(client.ask({"type": "request", "request": request})["ok"])
        client.close()
        again = self.raw(register=False)
        reply = again.ask({"type": "request", "request": request})
        self.assertFalse(reply["ok"])
        self.assertEqual(reply["seq"], 1)

    def test_sequence_gaps_allowed_but_must_increase(self):
        client = self.raw()
        self.assertTrue(client.ask({"type": "request", "request": self.signed(client, 5)})["ok"])
        self.assertFalse(client.ask({"type": "request", "request": self.signed(client, 4)})["ok"])

    def test_modified_body_rejected(self):
        client = self.raw()
        request = self.signed(client, 1)
        request["body"] = {"amount": 10_000}
        self.assertFalse(client.ask({"type": "request", "request": request})["ok"])
        self.assertEqual(self.server.sequences.last("M1"), 0)

    def test_request_for_another_identity_rejected(self):
        client = self.raw()
        reply = client.ask({"type": "request", "request": self.signed(client, 1, name="M2")})
        self.assertIn("certified session", reply["error"])

    def test_concurrent_sessions_cannot_both_use_a_sequence_number(self):
        a, b = self.raw(), self.raw(register=False)
        request = self.signed(a, 1)
        results = []
        threads = [threading.Thread(target=lambda c=c: results.append(
            c.ask({"type": "request", "request": request})["ok"])) for c in (a, b)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(5)
        self.assertEqual(sorted(results), [False, True])

    def test_tampered_frame_closes_the_connection(self):
        client = self.raw()
        frame = bytearray(client.channel.encrypt(b'{"type":"bye"}'))
        frame[-1] ^= 1
        send_frame(client.sock, bytes(frame))
        self.assertIsNone(recv_frame(client.sock))

    def test_replayed_frame_closes_the_connection(self):
        client = self.raw()
        request = self.signed(client, 1)
        frame = client.channel.encrypt(json.dumps({"type": "request", "request": request}).encode())
        send_frame(client.sock, frame)
        self.assertTrue(client.recv()["ok"])
        send_frame(client.sock, frame)  # same counter again
        self.assertIsNone(recv_frame(client.sock))

    def test_unknown_message_type_rejected(self):
        client = self.raw()
        self.assertFalse(client.ask({"type": "withdraw-everything"})["ok"])


class ShortChallengeServerTests(ServerTestCase):
    weak = {"short-challenge"}

    def test_weak_server_sends_four_bit_challenges(self):
        client = self.raw(login=False)
        R, _ = make_interactive_response(client.identity.x_M, 0, Q)
        reply = client.ask({"type": "login", "mode": "interactive", "R": format(R, "x")})
        self.assertLess(int(reply["e"], 16), 16)


class NoEncryptionServerTests(ServerTestCase):
    weak = {"no-encryption"}

    def test_plain_mode_for_the_capture_still_runs_the_protocol(self):
        identity = member.load_identity("M1")
        with closing(socket.create_connection(("127.0.0.1", self.server.port), timeout=5)) as sock:
            replies = member.run_session(sock, identity, self.log, handshake=client_handshake,
                                         requests=[("spend", {"amount": 1})], weak={"no-encryption"})
        self.assertTrue(replies[0]["ok"])


class StoreAndIdentityTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir = Path(self.tmp.name)

    def test_concurrent_first_registration_has_one_winner(self):
        store = RegistrationStore(self.dir / "server" / "registrations.json")
        outcomes = []

        def attempt(value):
            try:
                outcomes.append(store.register_first("M1", value))
            except ValueError:
                outcomes.append("rejected")
        threads = [threading.Thread(target=attempt, args=(format(i + 2, "x"),)) for i in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(outcomes.count("registered"), 1)
        self.assertEqual(outcomes.count("rejected"), 7)
        data = json.loads(store.path.read_text())
        self.assertEqual(list(data), ["M1"])
        self.assertEqual(list(store.path.parent.glob("*.tmp")), [])

    def test_sequence_store_check_and_set(self):
        store = SequenceStore(self.dir / "seq.json")
        self.assertTrue(store.accept("M1", lambda last: last == 0, 3))
        self.assertFalse(store.accept("M1", lambda last: last == 0, 4))
        self.assertEqual(store.last("M1"), 3)

    def test_init_identity_writes_public_request_only(self):
        paths = ServerPaths(self.dir)
        init_identity(paths, quiet_logger("init"))
        request = json.loads(paths.request.read_text())
        self.assertEqual(set(request), {"name", "public_key"})
        self.assertEqual(request["name"], "server")
        self.assertNotIn("PRIVATE", paths.request.read_text())
        self.assertTrue(paths.private_key.exists())
        key_before = paths.private_key.read_bytes()
        init_identity(paths, quiet_logger("init"))  # reuses, does not overwrite
        self.assertEqual(paths.private_key.read_bytes(), key_before)

    def test_load_identity_rejects_certificate_for_other_key(self):
        with mock.patch.object(member, "DATA_DIR", self.dir):
            world = build_world(self.dir, member_names=())
        other, _ = generate_p256_keypair()
        from treasury.crypto_utils import save_private_key
        save_private_key(world.paths.private_key, other)
        with self.assertRaises(RuntimeError):
            load_identity(world.paths)

    def test_parse_hex_int_is_strict(self):
        self.assertEqual(parse_hex_int("ff"), 255)
        for bad in ("", "FF", "0x1", "0ff", "-1", 15, None, "g", "f" * 5000):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    parse_hex_int(bad)


if __name__ == "__main__":
    unittest.main()
