"""Milestone 1 secure channel (Member 3).

After the signed ECDH handshake (``handshake.py``, Member 2) both sides hold the
same shared secret. This module turns it into two directional AES-256-GCM keys
and protects every later frame:

    keys  = HKDF-SHA256(shared_secret, salt=None, length=64,
                        info = b"ICS505|" + GROUP + b"|channel|"
                               + SHA-256(canonical_json(["hs", GROUP, name, X, Y])))
    k_m2s = keys[:32]      member -> server
    k_s2m = keys[32:]      server -> member

    frame = nonce (12-byte big-endian counter) || AES-256-GCM ciphertext+tag

Each direction has its own counter starting at 0. The receiver accepts a frame
only if its nonce is exactly the next expected counter *and* GCM decryption
succeeds; anything else (tampered, replayed, reordered, skipped or truncated
frame) raises ``ChannelError`` and the caller must close the connection.

On the wire an encrypted frame is sent as a 4-byte big-endian length followed
by the raw frame bytes, so Wireshark shows the counter 0, 1, 2, ... right after
the length prefix. The baseline TCP layer stays in framing.py/network.py.
"""
import json
import socket
import struct
from typing import Any

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .config import GROUP, MAX_FRAME_BYTES
from .encoding import canonical_json, sha256
from .framing import ProtocolError, recv_exact, recv_json, send_json

KEY_BYTES = 32
NONCE_BYTES = 12
TAG_BYTES = 16
MAX_COUNTER = (1 << (8 * NONCE_BYTES)) - 1


class ChannelError(ProtocolError):
    """A frame failed authentication or arrived out of order: close the connection."""


def generate_p256_keypair():
    """Return a fresh ECDSA/ECDH-capable P-256 (private_key, public_key) pair.

    Kept for starter compatibility; identity keys are produced by
    ``crypto_utils.generate_p256_keypair`` (which returns the public key as PEM).
    """
    private_key = ec.generate_private_key(ec.SECP256R1())
    return private_key, private_key.public_key()


def build_handshake_transcript(member_name: str, X_hex: str, Y_hex: str) -> list:
    """Return ["hs", GROUP, member name, X, Y] exactly as specified in the handout.

    Backward-compatible wrapper: the handshake itself lives in handshake.py, but
    this function stays importable from channel.py.
    """
    return ["hs", GROUP, member_name, X_hex, Y_hex]


def channel_info(member_name: str, X_hex: str, Y_hex: str) -> bytes:
    """HKDF info string: "ICS505|" + GROUP + "|channel|" + SHA-256(handshake transcript)."""
    transcript_hash = sha256(canonical_json(build_handshake_transcript(member_name, X_hex, Y_hex)))
    return b"ICS505|" + GROUP.encode("utf-8") + b"|channel|" + transcript_hash


def derive_directional_keys(shared_secret: bytes, member_name: str,
                            X_hex: str, Y_hex: str) -> tuple[bytes, bytes]:
    """HKDF-SHA256 (no salt) -> (member->server key, server->member key), 32 bytes each."""
    if not isinstance(shared_secret, (bytes, bytearray)) or not shared_secret:
        raise ValueError("shared_secret must be non-empty bytes")
    for label, value in (("member_name", member_name), ("X_hex", X_hex), ("Y_hex", Y_hex)):
        if not isinstance(value, str) or not value:
            raise ValueError(f"{label} must be a non-empty string")
    okm = HKDF(
        algorithm=hashes.SHA256(),
        length=2 * KEY_BYTES,
        salt=None,
        info=channel_info(member_name, X_hex, Y_hex),
    ).derive(bytes(shared_secret))
    return okm[:KEY_BYTES], okm[KEY_BYTES:]


class SecureChannel:
    """AES-256-GCM frames with strict per-direction counters.

    Required frame: 12-byte nonce || ciphertext+tag. The nonce is a 96-bit
    big-endian counter starting at zero. Skipped, replayed, reordered or
    modified frames raise ``ChannelError``; after the first failure the channel
    refuses all further use, so the caller has to close the connection.
    """

    def __init__(self, send_key: bytes, receive_key: bytes):
        for label, key in (("send_key", send_key), ("receive_key", receive_key)):
            if not isinstance(key, (bytes, bytearray)) or len(key) != KEY_BYTES:
                raise ValueError(f"{label} must be exactly {KEY_BYTES} bytes")
        self.send_key = bytes(send_key)
        self.receive_key = bytes(receive_key)
        self._send_aead = AESGCM(self.send_key)
        self._receive_aead = AESGCM(self.receive_key)
        self.send_counter = 0
        self.receive_counter = 0
        self.closed = False

    # -- construction helpers for the two roles ---------------------------------
    @classmethod
    def for_member(cls, shared_secret: bytes, member_name: str,
                   X_hex: str, Y_hex: str) -> "SecureChannel":
        """Member side: send with member->server key, receive with server->member key."""
        k_m2s, k_s2m = derive_directional_keys(shared_secret, member_name, X_hex, Y_hex)
        return cls(send_key=k_m2s, receive_key=k_s2m)

    @classmethod
    def for_server(cls, shared_secret: bytes, member_name: str,
                   X_hex: str, Y_hex: str) -> "SecureChannel":
        """Server side: send with server->member key, receive with member->server key."""
        k_m2s, k_s2m = derive_directional_keys(shared_secret, member_name, X_hex, Y_hex)
        return cls(send_key=k_s2m, receive_key=k_m2s)

    @classmethod
    def from_session(cls, session, role: str) -> "SecureChannel":
        """Build from handshake.SessionContext (shared_secret, member_name, X_hex, Y_hex)."""
        args = (session.shared_secret, session.member_name, session.X_hex, session.Y_hex)
        if role == "member":
            return cls.for_member(*args)
        if role == "server":
            return cls.for_server(*args)
        raise ValueError("role must be 'member' or 'server'")

    # -- AEAD ------------------------------------------------------------------
    def _fail(self, reason: str) -> None:
        self.close()
        raise ChannelError(reason)

    def encrypt(self, plaintext: bytes) -> bytes:
        if self.closed:
            raise ChannelError("channel is closed")
        if not isinstance(plaintext, (bytes, bytearray)):
            raise TypeError("plaintext must be bytes")
        if self.send_counter > MAX_COUNTER:
            self._fail("send counter exhausted")
        nonce = self.send_counter.to_bytes(NONCE_BYTES, "big")
        frame = nonce + self._send_aead.encrypt(nonce, bytes(plaintext), None)
        self.send_counter += 1
        return frame

    def decrypt(self, frame: bytes) -> bytes:
        if self.closed:
            raise ChannelError("channel is closed")
        if not isinstance(frame, (bytes, bytearray)) or len(frame) < NONCE_BYTES + TAG_BYTES:
            self._fail("frame too short")
        frame = bytes(frame)
        nonce = frame[:NONCE_BYTES]
        counter = int.from_bytes(nonce, "big")
        if counter != self.receive_counter:
            self._fail(f"unexpected nonce counter {counter}, expected {self.receive_counter}")
        try:
            plaintext = self._receive_aead.decrypt(nonce, frame[NONCE_BYTES:], None)
        except InvalidTag:
            self._fail(f"authentication failed for frame {counter}")
        self.receive_counter += 1
        return plaintext

    def close(self) -> None:
        """Forget the session keys; any later encrypt/decrypt raises ChannelError."""
        self.closed = True
        self._send_aead = self._receive_aead = None
        self.send_key = self.receive_key = b""


# -- wire helpers: 4-byte big-endian length || raw frame -------------------------
def send_frame(sock: socket.socket, frame: bytes) -> None:
    if len(frame) > MAX_FRAME_BYTES:
        raise ProtocolError(f"Frame too large: {len(frame)} bytes")
    sock.sendall(struct.pack(">I", len(frame)) + frame)


def recv_frame(sock: socket.socket) -> bytes | None:
    """Return one raw frame, or None if the peer closed cleanly between frames."""
    header = recv_exact(sock, 4)
    if not header:
        return None
    (length,) = struct.unpack(">I", header)
    if length == 0 or length > MAX_FRAME_BYTES:
        raise ProtocolError(f"Invalid frame length: {length}")
    payload = recv_exact(sock, length)
    if not payload:
        raise ProtocolError("Connection closed before frame payload")
    return payload


def send_secure(sock: socket.socket, channel: SecureChannel | None, message: Any) -> None:
    """Send one JSON message encrypted under ``channel``.

    ``channel=None`` is the deliberate ``--weak no-encryption`` mode used only for
    the 1_plain.pcapng capture: the message is sent as a plain framing.py frame.
    """
    if channel is None:
        send_json(sock, message)
        return
    plaintext = json.dumps(message, separators=(",", ":")).encode("utf-8")
    send_frame(sock, channel.encrypt(plaintext))


def recv_secure(sock: socket.socket, channel: SecureChannel | None) -> Any:
    """Receive and decrypt one JSON message; None if the peer closed cleanly.

    Raises ``ChannelError`` for tampered/replayed/out-of-order frames.
    """
    if channel is None:
        return recv_json(sock)
    frame = recv_frame(sock)
    if frame is None:
        return None
    plaintext = channel.decrypt(frame)
    try:
        return json.loads(plaintext.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        channel.close()
        raise ChannelError("decrypted frame is not valid UTF-8 JSON") from exc
