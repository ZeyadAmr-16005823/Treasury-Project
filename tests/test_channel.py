import secrets
import socket
import threading
import unittest

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from treasury.channel import (ChannelError, SecureChannel, build_handshake_transcript,
                              derive_directional_keys, recv_frame, recv_secure,
                              send_frame, send_secure)
from treasury.config import GROUP
from treasury.encoding import canonical_json, sha256
from treasury.framing import recv_json

X_HEX = "04" + "11" * 64
Y_HEX = "04" + "22" * 64


def make_pair(secret: bytes = None):
    secret = secret or secrets.token_bytes(32)
    member = SecureChannel.for_member(secret, "M1", X_HEX, Y_HEX)
    server = SecureChannel.for_server(secret, "M1", X_HEX, Y_HEX)
    return member, server


class KeyDerivationTests(unittest.TestCase):
    def test_transcript_wrapper_is_kept(self):
        self.assertEqual(build_handshake_transcript("M1", X_HEX, Y_HEX),
                         ["hs", GROUP, "M1", X_HEX, Y_HEX])

    def test_matches_specification(self):
        secret = secrets.token_bytes(32)
        info = (b"ICS505|" + GROUP.encode() + b"|channel|"
                + sha256(canonical_json(["hs", GROUP, "M1", X_HEX, Y_HEX])))
        okm = HKDF(algorithm=hashes.SHA256(), length=64, salt=None, info=info).derive(secret)
        self.assertEqual(derive_directional_keys(secret, "M1", X_HEX, Y_HEX), (okm[:32], okm[32:]))

    def test_keys_are_directional_and_bound_to_transcript(self):
        secret = secrets.token_bytes(32)
        m2s, s2m = derive_directional_keys(secret, "M1", X_HEX, Y_HEX)
        self.assertEqual((len(m2s), len(s2m)), (32, 32))
        self.assertNotEqual(m2s, s2m)
        for changed in (("M2", X_HEX, Y_HEX), ("M1", Y_HEX, X_HEX), ("M1", X_HEX, "04" + "33" * 64)):
            self.assertNotEqual(derive_directional_keys(secret, *changed), (m2s, s2m))

    def test_invalid_inputs(self):
        with self.assertRaises(ValueError):
            derive_directional_keys(b"", "M1", X_HEX, Y_HEX)
        with self.assertRaises(ValueError):
            derive_directional_keys(b"s", "", X_HEX, Y_HEX)
        with self.assertRaises(ValueError):
            SecureChannel(b"short", b"\x00" * 32)


class SecureChannelTests(unittest.TestCase):
    def test_round_trip_both_directions(self):
        member, server = make_pair()
        for i in range(3):
            self.assertEqual(server.decrypt(member.encrypt(b"m2s %d" % i)), b"m2s %d" % i)
            self.assertEqual(member.decrypt(server.encrypt(b"s2m %d" % i)), b"s2m %d" % i)

    def test_nonce_is_big_endian_counter_from_zero(self):
        member, _ = make_pair()
        for expected in range(3):
            frame = member.encrypt(b"hello")
            self.assertEqual(frame[:12], expected.to_bytes(12, "big"))
            self.assertEqual(len(frame), 12 + len(b"hello") + 16)

    def test_directions_use_different_keys(self):
        member, server = make_pair()
        frame = member.encrypt(b"x")
        with self.assertRaises(ChannelError):
            member.decrypt(frame)  # member cannot read its own direction

    def test_modified_frame_is_rejected_and_channel_closes(self):
        for position in (12, -1):  # first ciphertext byte, last tag byte
            member, server = make_pair()
            frame = bytearray(member.encrypt(b"spend 50"))
            frame[position] ^= 0x01
            with self.assertRaises(ChannelError):
                server.decrypt(bytes(frame))
            self.assertTrue(server.closed)
            with self.assertRaises(ChannelError):
                server.decrypt(member.encrypt(b"next"))

    def test_replayed_frame_is_rejected(self):
        member, server = make_pair()
        frame = member.encrypt(b"spend 50")
        server.decrypt(frame)
        with self.assertRaises(ChannelError):
            server.decrypt(frame)

    def test_skipped_and_reordered_frames_are_rejected(self):
        member, server = make_pair()
        first, second = member.encrypt(b"1"), member.encrypt(b"2")
        with self.assertRaises(ChannelError):
            server.decrypt(second)
        member, server = make_pair()
        member.encrypt(b"0")
        with self.assertRaises(ChannelError):
            server.decrypt(member.encrypt(b"1"))

    def test_changed_nonce_is_rejected(self):
        member, server = make_pair()
        server.decrypt(member.encrypt(b"0"))
        frame = member.encrypt(b"1")
        forged = (0).to_bytes(12, "big") + frame[12:]
        with self.assertRaises(ChannelError):
            server.decrypt(forged)

    def test_truncated_and_wrong_key_frames_are_rejected(self):
        member, server = make_pair()
        with self.assertRaises(ChannelError):
            server.decrypt(b"\x00" * 20)
        other_member, _ = make_pair()
        _, server = make_pair()
        with self.assertRaises(ChannelError):
            server.decrypt(other_member.encrypt(b"hi"))

    def test_close_forgets_keys(self):
        member, _ = make_pair()
        member.close()
        self.assertEqual(member.send_key, b"")
        with self.assertRaises(ChannelError):
            member.encrypt(b"x")


class WireTests(unittest.TestCase):
    def setUp(self):
        self.left, self.right = socket.socketpair()

    def tearDown(self):
        self.left.close()
        self.right.close()

    def test_encrypted_json_over_socket(self):
        member, server = make_pair()
        message = {"type": "request", "request": {"op": "spend", "seq": 1}}
        thread = threading.Thread(target=send_secure, args=(self.left, member, message))
        thread.start()
        raw = recv_frame(self.right)
        thread.join()
        self.assertEqual(raw[:12], bytes(12))
        self.assertNotIn(b"spend", raw)
        self.assertEqual(recv_secure_from(raw, server), message)

    def test_recv_secure_and_clean_close(self):
        member, server = make_pair()
        send_secure(self.left, member, {"type": "bye"})
        self.assertEqual(recv_secure(self.right, server), {"type": "bye"})
        self.left.close()
        self.assertIsNone(recv_secure(self.right, server))

    def test_replayed_frame_over_socket_raises(self):
        member, server = make_pair()
        frame = member.encrypt(b'{"type":"bye"}')
        send_frame(self.left, frame)
        send_frame(self.left, frame)
        self.assertEqual(recv_secure(self.right, server), {"type": "bye"})
        with self.assertRaises(ChannelError):
            recv_secure(self.right, server)

    def test_no_encryption_mode_is_plain_json(self):
        send_secure(self.left, None, {"type": "login", "R": "ab"})
        self.assertEqual(recv_json(self.right), {"type": "login", "R": "ab"})


def recv_secure_from(raw: bytes, channel):
    import json
    return json.loads(channel.decrypt(raw))


if __name__ == "__main__":
    unittest.main()
