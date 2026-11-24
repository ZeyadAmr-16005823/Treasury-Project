"""Signed ephemeral ECDH handshake (Member 2)."""
import json
import socket
import threading
import unittest
from datetime import date, timedelta

from treasury.certificates import create_certificate
from treasury.channel import SecureChannel, build_handshake_transcript
from treasury.config import CERT_EXPIRY, GROUP
from treasury.crypto_utils import generate_p256_keypair, public_key_pem, sign_raw
from treasury.encoding import canonical_json
from treasury.framing import recv_json, send_json
from treasury.handshake import (HandshakeError, client_handshake, decode_point,
                                generate_ephemeral, hs_member_transcript,
                                hs_server_transcript, server_handshake)


def make_identity(founder_key, name, expires=CERT_EXPIRY):
    key, pem = generate_p256_keypair()
    return key, create_certificate(founder_key, name, pem, expires).to_dict()


def run_both(client_fn, server_fn):
    """Run two handshake halves on a socketpair; return (client_result, server_result)."""
    left, right = socket.socketpair()
    left.settimeout(5)
    right.settimeout(5)
    results = {}

    def server_side():
        try:
            results["server"] = server_fn(right)
        except Exception as exc:
            results["server"] = exc
        finally:
            right.close()

    thread = threading.Thread(target=server_side)
    thread.start()
    try:
        results["client"] = client_fn(left)
    except Exception as exc:
        results["client"] = exc
    finally:
        left.close()
    thread.join(5)
    return results["client"], results["server"]


class HandshakeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.founder_key, founder_pem = generate_p256_keypair()
        cls.founder_pub = cls.founder_key.public_key()
        cls.server_key, cls.server_cert = make_identity(cls.founder_key, "server")
        cls.member_key, cls.member_cert = make_identity(cls.founder_key, "M1")

    def client(self, weak=(), cert=None, key=None, founder=None):
        return lambda sock: client_handshake(sock, cert or self.member_cert, key or self.member_key,
                                             founder or self.founder_pub, "M1", set(weak))

    def server(self, weak=(), cert=None, key=None):
        return lambda sock: server_handshake(sock, cert or self.server_cert, key or self.server_key,
                                             self.founder_pub, "server", set(weak))

    def test_transcripts_match_the_contract(self):
        self.assertEqual(hs_server_transcript("M1", "x", "y"), ["hs-server", GROUP, "M1", "x", "y"])
        self.assertEqual(hs_member_transcript("M1", "x", "y"), ["hs-member", GROUP, "M1", "x", "y"])
        self.assertEqual(build_handshake_transcript("M1", "x", "y"), ["hs", GROUP, "M1", "x", "y"])

    def test_signed_handshake_agrees_on_secret_and_channel(self):
        client, server = run_both(self.client(), self.server())
        self.assertNotIsInstance(client, Exception, client)
        self.assertNotIsInstance(server, Exception, server)
        self.assertEqual(client.shared_secret, server.shared_secret)
        self.assertEqual(len(client.shared_secret), 32)
        self.assertEqual((client.member_name, client.X_hex, client.Y_hex),
                         (server.member_name, server.X_hex, server.Y_hex))
        self.assertEqual(server.member_name, "M1")
        self.assertTrue(client.signed and server.signed)
        self.assertEqual(server.peer_certificate, self.member_cert)
        member_ch = SecureChannel.from_session(client, "member")
        server_ch = SecureChannel.from_session(server, "server")
        self.assertEqual(server_ch.decrypt(member_ch.encrypt(b"hi")), b"hi")
        self.assertNotIn(client.shared_secret.hex(), repr(client))

    def test_each_handshake_uses_fresh_ephemeral_keys(self):
        first, _ = run_both(self.client(), self.server())
        second, _ = run_both(self.client(), self.server())
        self.assertNotEqual(first.X_hex, second.X_hex)
        self.assertNotEqual(first.Y_hex, second.Y_hex)
        self.assertNotEqual(first.shared_secret, second.shared_secret)

    def test_unsigned_weak_mode_works_without_signatures(self):
        client, server = run_both(self.client({"unsigned-handshake"}),
                                  self.server({"unsigned-handshake"}))
        self.assertEqual(client.shared_secret, server.shared_secret)
        self.assertFalse(client.signed or server.signed)

    def test_secure_server_rejects_unsigned_member(self):
        client, server = run_both(self.client({"unsigned-handshake"}), self.server())
        self.assertIsInstance(server, HandshakeError)
        self.assertIsInstance(client, HandshakeError)

    def test_secure_member_rejects_unsigned_server(self):
        client, server = run_both(self.client(), self.server({"unsigned-handshake"}))
        self.assertIsInstance(client, HandshakeError)
        self.assertIn("missing", str(client))

    def test_weak_mode_still_checks_certificates(self):
        rogue_founder, _ = generate_p256_keypair()
        _, rogue_cert = make_identity(rogue_founder, "M1")
        client, server = run_both(self.client({"unsigned-handshake"}, cert=rogue_cert),
                                  self.server({"unsigned-handshake"}))
        self.assertIsInstance(server, HandshakeError)
        self.assertIn("certificate", str(server))

    def test_server_rejects_bad_member_certificates(self):
        yesterday = (date.today() - timedelta(days=1)).isoformat()
        _, expired = make_identity(self.founder_key, "M1", expires=yesterday)
        _, server_named = make_identity(self.founder_key, "server")
        _, outsider = make_identity(self.founder_key, "M9")
        tampered = dict(self.member_cert, name="M2")
        for cert in (expired, server_named, outsider, tampered):
            with self.subTest(cert=cert["name"]):
                def client_fn(sock, cert=cert):
                    x, X_hex = generate_ephemeral()
                    send_json(sock, {"type": "hs-hello", "cert": cert, "X": X_hex})
                    return recv_json(sock)
                reply, server = run_both(client_fn, self.server())
                self.assertIsInstance(server, HandshakeError)
                self.assertEqual(reply["type"], "hs-error")

    def test_member_rejects_wrong_server_certificate(self):
        # A member certificate presented as the server's is rejected (expected name "server").
        client, _ = run_both(self.client(), self.server(cert=self.member_cert, key=self.member_key))
        self.assertIsInstance(client, HandshakeError)
        self.assertIn("server certificate", str(client))

    def test_member_rejects_signature_from_wrong_key(self):
        impostor_key, _ = generate_p256_keypair()
        client, _ = run_both(self.client(), self.server(key=impostor_key))
        self.assertIsInstance(client, HandshakeError)
        self.assertIn("signature", str(client))

    def test_server_rejects_member_signature_over_other_transcript(self):
        def client_fn(sock):
            x, X_hex = generate_ephemeral()
            send_json(sock, {"type": "hs-hello", "cert": self.member_cert, "X": X_hex})
            reply = recv_json(sock)
            # Sign the *server* label instead of hs-member: must not be accepted.
            sig = sign_raw(self.member_key, canonical_json(hs_server_transcript("M1", X_hex, reply["Y"])))
            send_json(sock, {"type": "hs-member", "sig": sig})
            return recv_json(sock)
        reply, server = run_both(client_fn, self.server())
        self.assertIsInstance(server, HandshakeError)
        self.assertEqual(reply, {"type": "hs-error", "error": "invalid member handshake signature"})

    def test_invalid_ephemeral_points_are_rejected(self):
        _, good = generate_ephemeral()
        bad_points = [
            "", "04" + "00" * 64, good.upper(), "02" + good[2:66], good[:-2],
            "04" + "ff" * 64, 12345,
        ]
        for point in bad_points:
            with self.subTest(point=str(point)[:12]):
                with self.assertRaises(HandshakeError):
                    decode_point(point)
        self.assertEqual(len(good), 130)
        decode_point(good)

    def test_server_rejects_off_curve_X(self):
        def client_fn(sock):
            send_json(sock, {"type": "hs-hello", "cert": self.member_cert, "X": "04" + "11" * 64})
            return recv_json(sock)
        reply, server = run_both(client_fn, self.server())
        self.assertIsInstance(server, HandshakeError)
        self.assertEqual(reply["type"], "hs-error")

    def test_own_certificate_must_match_name(self):
        with self.assertRaises(HandshakeError):
            client_handshake(None, dict(self.member_cert, name="M2"), self.member_key,
                             self.founder_pub, "M1", set())


if __name__ == "__main__":
    unittest.main()
