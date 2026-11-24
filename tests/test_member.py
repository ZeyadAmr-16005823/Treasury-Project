"""Member client flow against an in-test stand-in server.

The stand-in handshake only hands both sides the same session secret; the real
signed handshake is Member 2's handshake.py and is tested there.
"""
import json
import logging
import secrets
import socket
import tempfile
import threading
import unittest
from dataclasses import dataclass
from pathlib import Path
from unittest import mock

from treasury import member
from treasury.channel import ChannelError, SecureChannel, recv_secure, send_secure
from treasury.config import GROUP
from treasury.crypto_utils import load_public_key, verify_raw
from treasury.encoding import canonical_json
from treasury.group import G, P, Q
from treasury.login import verify_interactive_login, verify_noninteractive_login
from treasury.requests import verify_request

X_HEX = "04" + "aa" * 64
Y_HEX = "04" + "bb" * 64


@dataclass
class FakeSession:
    shared_secret: bytes
    member_name: str
    X_hex: str
    Y_hex: str


class StandInServer:
    """Minimal server side of the agreed wire messages, using the shared verifiers."""

    def __init__(self, sock, secret, name, public_key, encrypted=True):
        self.sock, self.name, self.public_key = sock, name, public_key
        self.channel = (SecureChannel.for_server(secret, name, X_HEX, Y_HEX) if encrypted else None)
        self.registered, self.ledger, self.last_seq = {}, [], 0
        self.logins, self.error = [], None

    def send(self, message):
        send_secure(self.sock, self.channel, message)

    def recv(self):
        return recv_secure(self.sock, self.channel)

    def run(self):
        try:
            while True:
                msg = self.recv()
                if msg is None or msg["type"] == "bye":
                    return
                getattr(self, "on_" + msg["type"].replace("-", "_"))(msg)
        except Exception as exc:  # recorded for the test to inspect
            self.error = exc

    def on_register(self, msg):
        ok = verify_raw(self.public_key, canonical_json(["register", GROUP, self.name, msg["X_M"]]), msg["sig"])
        if ok:
            self.registered.setdefault(self.name, int(msg["X_M"], 16))
        self.send({"type": "register-result", "ok": ok, "status": "registered"})

    def on_login(self, msg):
        X_M = self.registered[self.name]
        if msg["mode"] == "interactive":
            R = int(msg["R"], 16)
            e = secrets.randbits(128)
            self.send({"type": "challenge", "e": format(e, "x")})
            z = int(member._expect(self.recv(), "login-response")["z"], 16)
            ok = verify_interactive_login(R, z, e, X_M, P, Q, G)
        else:
            nonce = secrets.token_bytes(16).hex()
            self.send({"type": "login-nonce", "nonce": nonce})
            proof = member._expect(self.recv(), "login-proof")
            ok = verify_noninteractive_login(self.name, int(proof["R"], 16), int(proof["z"], 16), nonce, X_M)
        self.logins.append((msg["mode"], ok))
        self.send({"type": "login-result", "ok": ok, "last_seq": self.last_seq})

    def on_request(self, msg):
        request = msg["request"]
        ok = request["name"] == self.name and verify_request(self.public_key, request, self.last_seq)
        if ok:
            self.last_seq = request["seq"]
            self.ledger.append(request)
        self.send({"type": "request-result", "ok": ok, "seq": request["seq"]})


class MemberFlowTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        patcher = mock.patch.object(member, "DATA_DIR", Path(self.tmp.name))
        patcher.start()
        self.addCleanup(patcher.stop)
        self.addCleanup(self.tmp.cleanup)
        self.log = logging.getLogger("test-member")
        self.log.addHandler(logging.NullHandler())
        self.log.propagate = False
        member.init_identity("M1", self.log)
        # Certificate and founder key are Member 1's job; stand-ins are enough here.
        (Path(self.tmp.name) / "certs").mkdir()
        (Path(self.tmp.name) / "certs" / "M1.json").write_text("{}")
        pem = json.loads(member.request_path("M1").read_text())["public_key"]
        (Path(self.tmp.name) / "founder.pub").write_text(pem)
        self.public_key = load_public_key(pem)

    def run_pair(self, login_mode, requests, weak=frozenset(), identity=None):
        secret = secrets.token_bytes(32)
        left, right = socket.socketpair()
        server = StandInServer(right, secret, "M1", self.public_key, encrypted="no-encryption" not in weak)
        thread = threading.Thread(target=server.run)
        thread.start()
        identity = identity or member.load_identity("M1")
        calls = []

        def fake_handshake(sock, cert, private_key, founder_pub, name, weak_set):
            calls.append((name, weak_set))
            return FakeSession(secret, name, X_HEX, Y_HEX)

        try:
            replies = member.run_session(left, identity, self.log, handshake=fake_handshake,
                                         login_mode=login_mode, requests=requests, weak=weak)
        finally:
            thread.join(timeout=5)
            left.close()
            right.close()
        self.assertIsNone(server.error)
        return server, replies, calls

    def test_init_writes_public_request_only(self):
        request = json.loads(member.request_path("M1").read_text())
        self.assertEqual(set(request), {"name", "public_key"})
        self.assertEqual(request["name"], "M1")
        self.assertNotIn("PRIVATE", request["public_key"])
        self.assertTrue(member.private_key_path("M1").exists())
        secret = json.loads(member.login_secret_path("M1").read_text())
        self.assertEqual(pow(G, int(secret["x_M"], 16), P), int(secret["X_M"], 16))

    def test_init_does_not_overwrite_existing_key(self):
        before = member.private_key_path("M1").read_bytes()
        member.init_identity("M1", self.log)
        self.assertEqual(member.private_key_path("M1").read_bytes(), before)

    def test_interactive_login_and_signed_request(self):
        server, replies, calls = self.run_pair("interactive", [("spend", {"amount": 50, "reason": "pizza"})])
        self.assertEqual(calls, [("M1", set())])
        self.assertEqual(server.logins, [("interactive", True)])
        self.assertEqual([r["seq"] for r in server.ledger], [1])
        self.assertTrue(replies[0]["ok"])
        self.assertEqual(member.load_last_seq("M1"), 1)

    def test_noninteractive_login_registration_persists_and_seq_grows(self):
        self.run_pair("interactive", [("spend", {"amount": 1, "reason": "a"})])
        self.assertTrue(member.load_identity("M1").registered)
        # Second session: stand-in server starts empty, so force registration again.
        identity = member.load_identity("M1")
        identity.registered = False
        server, _, _ = self.run_pair("noninteractive", [("spend", {"amount": 2, "reason": "b"})] * 2,
                                     identity=identity)
        self.assertEqual(server.logins, [("noninteractive", True)])
        self.assertEqual([r["seq"] for r in server.ledger], [2, 3])

    def test_weak_options_reach_handshake_and_no_encryption_works(self):
        server, _, calls = self.run_pair("interactive", [("spend", {"amount": 5, "reason": "x"})],
                                         weak={"no-encryption"})
        self.assertEqual(calls, [("M1", {"no-encryption"})])
        self.assertEqual(len(server.ledger), 1)

    def test_tampered_server_frame_closes_member(self):
        secret = secrets.token_bytes(32)
        left, right = socket.socketpair()
        server_channel = SecureChannel.for_server(secret, "M1", X_HEX, Y_HEX)

        def evil_server():
            recv_secure(right, server_channel)                # register
            frame = bytearray(server_channel.encrypt(b'{"type":"register-result","ok":true}'))
            frame[-1] ^= 1
            from treasury.channel import send_frame
            send_frame(right, bytes(frame))

        thread = threading.Thread(target=evil_server)
        thread.start()
        identity = member.load_identity("M1")
        try:
            with self.assertRaises(ChannelError):
                member.run_session(left, identity, self.log,
                                   handshake=lambda *a: FakeSession(secret, "M1", X_HEX, Y_HEX))
        finally:
            thread.join(timeout=5)
            left.close()
            right.close()

    def test_refused_login_raises(self):
        identity = member.load_identity("M1")
        identity.x_M = (identity.x_M + 1) % Q  # wrong secret
        secret = secrets.token_bytes(32)
        left, right = socket.socketpair()
        server = StandInServer(right, secret, "M1", self.public_key)
        server.registered["M1"] = member.load_identity("M1").X_M
        identity.registered = True
        thread = threading.Thread(target=server.run)
        thread.start()
        try:
            with self.assertRaises(member.MemberError):
                member.run_session(left, identity, self.log,
                                   handshake=lambda *a: FakeSession(secret, "M1", X_HEX, Y_HEX))
        finally:
            left.close()
            thread.join(timeout=5)
            right.close()
        self.assertEqual(server.logins, [("interactive", False)])


if __name__ == "__main__":
    unittest.main()
