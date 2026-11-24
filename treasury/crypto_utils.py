"""Shared P-256 identity-key helpers and fixed-width ECDSA signature encoding.

This module deliberately contains no protocol logic: it only handles key
generation/storage and the conversion between DER signatures (used by the
``cryptography`` library) and the project's raw ``r || s`` representation.
"""
import os
from pathlib import Path

from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature,
    encode_dss_signature,
)

HEX_DIGITS = frozenset("0123456789abcdef")  # canonical lowercase hex only
SIGNATURE_HEX_LENGTH = 128  # r (32 bytes) + s (32 bytes), big-endian


def generate_p256_keypair() -> tuple[ec.EllipticCurvePrivateKey, str]:
    """Return a fresh P-256 private key and its PEM-encoded public key."""
    private_key = ec.generate_private_key(ec.SECP256R1())
    return private_key, public_key_pem(private_key)


def public_key_pem(key) -> str:
    """PEM (SubjectPublicKeyInfo) for a P-256 public or private key."""
    if isinstance(key, ec.EllipticCurvePrivateKey):
        key = key.public_key()
    return key.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")


def save_private_key(path, key: ec.EllipticCurvePrivateKey) -> None:
    """Write a P-256 private key to ``path`` in unencrypted PKCS#8 PEM form."""
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    # Restrictive permissions on POSIX; Windows inherits the user's ACLs.
    if os.name != "nt":
        os.chmod(target, 0o600)


def load_private_key(path) -> ec.EllipticCurvePrivateKey:
    """Load a P-256 private key written by :func:`save_private_key`.

    Invalid PEM, unsupported algorithms and non-P-256 keys all raise
    ``ValueError`` so callers can handle failures consistently.
    """
    try:
        key = serialization.load_pem_private_key(Path(path).read_bytes(), password=None)
    except (ValueError, TypeError, UnsupportedAlgorithm) as exc:
        raise ValueError("invalid or unsupported private key PEM") from exc
    if not isinstance(key, ec.EllipticCurvePrivateKey) or not isinstance(key.curve, ec.SECP256R1):
        raise ValueError("private key is not a P-256 key")
    return key


def load_public_key(pem_or_bytes) -> ec.EllipticCurvePublicKey:
    """Load a P-256 public key from PEM text or bytes.

    Only P-256 keys are accepted; malformed PEM and unsupported key types
    (e.g. RSA or another curve) raise ``ValueError``.
    """
    data = pem_or_bytes.encode("ascii") if isinstance(pem_or_bytes, str) else bytes(pem_or_bytes)
    try:
        key = serialization.load_pem_public_key(data)
    except (ValueError, UnsupportedAlgorithm) as exc:
        raise ValueError("invalid or unsupported public key PEM") from exc
    if not isinstance(key, ec.EllipticCurvePublicKey) or not isinstance(key.curve, ec.SECP256R1):
        raise ValueError("public key is not a P-256 key")
    return key


def sign_raw(private_key: ec.EllipticCurvePrivateKey, data: bytes) -> str:
    """ECDSA-SHA256 sign ``data`` and return fixed-width ``r || s`` as hex.

    The result is exactly 64 bytes / 128 lowercase hex characters: ``r`` and
    ``s`` are each encoded as 32 bytes, big-endian.
    """
    der_signature = private_key.sign(data, ec.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(der_signature)
    return f"{r:064x}{s:064x}"


def verify_raw(public_key: ec.EllipticCurvePublicKey, data: bytes, sig_hex: str) -> bool:
    """Verify a fixed-width raw ``r || s`` signature.

    Rejects anything that is not exactly 128 hex characters, and catches
    invalid DER, invalid signatures and out-of-range values.
    """
    if not isinstance(sig_hex, str) or len(sig_hex) != SIGNATURE_HEX_LENGTH:
        return False
    if any(char not in HEX_DIGITS for char in sig_hex):
        return False
    try:
        r = int(sig_hex[:64], 16)
        s = int(sig_hex[64:], 16)
        der_signature = encode_dss_signature(r, s)
        public_key.verify(der_signature, data, ec.ECDSA(hashes.SHA256()))
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False
