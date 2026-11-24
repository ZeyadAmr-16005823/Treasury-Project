"""Milestone 1 signed ephemeral ECDH handshake (Member 2).

Extracted from the starter's channel.py TODOs. ``channel.py`` (Member 3) turns
the resulting :class:`SessionContext` into directional AES-256-GCM keys.

Wire messages (plain ``framing`` JSON frames, before the encrypted channel):

    member -> server   {"type": "hs-hello",  "cert": member_cert, "X": X_hex}
    server -> member   {"type": "hs-server", "cert": server_cert, "Y": Y_hex,
                        "sig": sign_server(["hs-server", GROUP, name, X_hex, Y_hex])}
    member -> server   {"type": "hs-member",
                        "sig": sign_member(["hs-member", GROUP, name, X_hex, Y_hex])}
    server -> member   {"type": "hs-ok"}            or {"type": "hs-error", "error": str}

``X`` / ``Y`` are ephemeral P-256 public keys as uncompressed SEC1 points in
lowercase hex ("04" || x || y, 130 characters). ``name`` is always the member's
certified name. Signatures are raw ``r || s`` hex (``crypto_utils.sign_raw``)
over ``canonical_json(transcript)``. The shared secret is the raw 32-byte ECDH
x-coordinate; ``channel.derive_directional_keys`` binds it to
``["hs", GROUP, name, X_hex, Y_hex]``.

Weak mode ``unsigned-handshake`` (attack A1) omits **both** handshake
signatures and skips their verification. Certificate verification still runs,
and AES-GCM plus signed-request checks stay enabled after the handshake.
"""
from dataclasses import dataclass, field
from typing import Iterable

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from .certificates import verify_certificate
from .channel import build_handshake_transcript  # noqa: F401  (re-exported, see docs §8)
from .config import GROUP, MEMBER_NAMES
from .crypto_utils import load_public_key, sign_raw, verify_raw
from .encoding import canonical_json
from .framing import ProtocolError, recv_json, send_json

WEAK_UNSIGNED = "unsigned-handshake"
SERVER_NAME = "server"
POINT_HEX_LENGTH = 130  # "04" + 32-byte x + 32-byte y
_HEX = frozenset("0123456789abcdef")


class HandshakeError(ProtocolError):
    """The handshake failed; the connection must be closed."""


@dataclass
class SessionContext:
    """Result of a completed handshake, consumed by ``SecureChannel.from_session``."""
    shared_secret: bytes
    member_name: str
    X_hex: str
    Y_hex: str
    peer_certificate: dict = field(default_factory=dict, repr=False)
    peer_public_key: object = field(default=None, repr=False)
    signed: bool = True

    def __repr__(self) -> str:  # never print the shared secret
        return (f"SessionContext(member_name={self.member_name!r}, X={self.X_hex[:10]}..., "
                f"Y={self.Y_hex[:10]}..., signed={self.signed})")


# -- transcripts -----------------------------------------------------------------
def hs_server_transcript(name: str, X_hex: str, Y_hex: str) -> list:
    return ["hs-server", GROUP, name, X_hex, Y_hex]


def hs_member_transcript(name: str, X_hex: str, Y_hex: str) -> list:
    return ["hs-member", GROUP, name, X_hex, Y_hex]


# -- ephemeral key helpers (also used by Mallory) ----------------------------------
def generate_ephemeral() -> tuple[ec.EllipticCurvePrivateKey, str]:
    """Fresh ephemeral P-256 key and its public point as uncompressed hex."""
    private_key = ec.generate_private_key(ec.SECP256R1())
    return private_key, encode_point(private_key.public_key())


def encode_point(public_key: ec.EllipticCurvePublicKey) -> str:
    return public_key.public_bytes(serialization.Encoding.X962,
                                   serialization.PublicFormat.UncompressedPoint).hex()


def decode_point(point_hex) -> ec.EllipticCurvePublicKey:
    """Parse an uncompressed P-256 point; rejects bad encodings and off-curve points."""
    if (not isinstance(point_hex, str) or len(point_hex) != POINT_HEX_LENGTH
            or not point_hex.startswith("04") or any(c not in _HEX for c in point_hex)):
        raise HandshakeError("ephemeral key must be a 130-char lowercase uncompressed P-256 point")
    try:
        return ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), bytes.fromhex(point_hex))
    except ValueError as exc:
        raise HandshakeError("ephemeral key is not a valid P-256 point") from exc


def ecdh(private_key: ec.EllipticCurvePrivateKey, peer_point_hex: str) -> bytes:
    return private_key.exchange(ec.ECDH(), decode_point(peer_point_hex))


def _sign(private_key, transcript: list) -> str:
    return sign_raw(private_key, canonical_json(transcript))


def _verify(public_key, transcript: list, sig) -> bool:
    return verify_raw(public_key, canonical_json(transcript), sig)


def _is_weak(weak: Iterable[str] | None) -> bool:
    return WEAK_UNSIGNED in set(weak or ())


def _expect(message, expected_type: str, required: set[str]) -> dict:
    if message is None:
        raise HandshakeError(f"peer closed the connection before {expected_type!r}")
    if not isinstance(message, dict):
        raise HandshakeError(f"malformed handshake message (expected {expected_type!r})")
    if message.get("type") == "hs-error":
        raise HandshakeError(f"peer rejected the handshake: {message.get('error', 'no reason')}")
    if message.get("type") != expected_type:
        raise HandshakeError(f"expected {expected_type!r}, got {message.get('type')!r}")
    missing = required - set(message)
    if missing:
        raise HandshakeError(f"{expected_type!r} is missing {', '.join(sorted(missing))}")
    return message


def _reject(sock, reason: str) -> HandshakeError:
    """Best-effort hs-error to the peer, then return the exception to raise."""
    try:
        send_json(sock, {"type": "hs-error", "error": reason})
    except OSError:
        pass
    return HandshakeError(reason)


# -- member side -------------------------------------------------------------------
def client_handshake(sock, cert: dict, private_key, founder_pub, name: str,
                     weak: set[str] | None = None) -> SessionContext:
    """Run the member side of the handshake and return the session context."""
    unsigned = _is_weak(weak)
    if not isinstance(cert, dict) or cert.get("name") != name:
        raise HandshakeError(f"own certificate does not belong to {name!r}")

    x, X_hex = generate_ephemeral()
    send_json(sock, {"type": "hs-hello", "cert": cert, "X": X_hex})

    required = {"cert", "Y"} if unsigned else {"cert", "Y", "sig"}
    reply = _expect(recv_json(sock), "hs-server", required)
    if not verify_certificate(reply["cert"], founder_pub, SERVER_NAME):
        raise _reject(sock, "invalid server certificate")
    server_key = load_public_key(reply["cert"]["public_key"])
    Y_hex = reply["Y"]
    try:
        decode_point(Y_hex)
    except HandshakeError as exc:
        raise _reject(sock, str(exc)) from exc
    if not unsigned and not _verify(server_key, hs_server_transcript(name, X_hex, Y_hex), reply["sig"]):
        raise _reject(sock, "invalid server handshake signature")

    finish = {"type": "hs-member"}
    if not unsigned:
        finish["sig"] = _sign(private_key, hs_member_transcript(name, X_hex, Y_hex))
    send_json(sock, finish)
    _expect(recv_json(sock), "hs-ok", set())

    shared_secret = ecdh(x, Y_hex)
    del x  # the ephemeral private key is not kept beyond this handshake
    return SessionContext(shared_secret, name, X_hex, Y_hex,
                          peer_certificate=reply["cert"], peer_public_key=server_key,
                          signed=not unsigned)


# -- server side -------------------------------------------------------------------
def server_handshake(conn, cert: dict, private_key, founder_pub, name: str = SERVER_NAME,
                     weak: set[str] | None = None) -> SessionContext:
    """Run the server side; ``name`` is the server's own certified name.

    The member's identity comes only from its founder-signed certificate, and
    ``SessionContext.member_name`` is that certified name.
    """
    unsigned = _is_weak(weak)
    hello = _expect(recv_json(conn), "hs-hello", {"cert", "X"})
    member_cert = hello["cert"]
    member_name = member_cert.get("name") if isinstance(member_cert, dict) else None
    if member_name not in MEMBER_NAMES:
        raise _reject(conn, "certificate is not for a treasury member")
    if not verify_certificate(member_cert, founder_pub, member_name):
        raise _reject(conn, "invalid member certificate")
    member_key = load_public_key(member_cert["public_key"])
    X_hex = hello["X"]
    try:
        decode_point(X_hex)
    except HandshakeError as exc:
        raise _reject(conn, str(exc)) from exc

    y, Y_hex = generate_ephemeral()
    reply = {"type": "hs-server", "cert": cert, "Y": Y_hex}
    if not unsigned:
        reply["sig"] = _sign(private_key, hs_server_transcript(member_name, X_hex, Y_hex))
    send_json(conn, reply)

    finish = _expect(recv_json(conn), "hs-member", set() if unsigned else {"sig"})
    if not unsigned and not _verify(member_key, hs_member_transcript(member_name, X_hex, Y_hex),
                                    finish["sig"]):
        raise _reject(conn, "invalid member handshake signature")
    send_json(conn, {"type": "hs-ok"})

    shared_secret = ecdh(y, X_hex)
    del y
    return SessionContext(shared_secret, member_name, X_hex, Y_hex,
                          peer_certificate=member_cert, peer_public_key=member_key,
                          signed=not unsigned)
