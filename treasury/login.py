"""Milestone 1 proof-of-knowledge (Schnorr) login.

Non-interactive transcript (freeze in docs/M1_INTERFACES.md):

    e = H("login-ni", name, X_M, R, nonce, q=q)
    z = k + e * x_M mod q

The verifier must take ``name`` from the certified session identity, not from
the proof message.  ``nonce`` is a fresh server-supplied value.
"""
import secrets
from typing import Callable

from .encoding import H
from .group import G, P, Q, is_valid_element, random_exponent

SECURE_CHALLENGE_BITS = 128
WEAK_CHALLENGE_BITS = 4
NONINTERACTIVE_LABEL = "login-ni"

ChallengeSource = Callable[[], int]


def _is_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _is_valid_name(name: object) -> bool:
    return isinstance(name, str) and bool(name.strip())


def _is_valid_nonce(nonce: object) -> bool:
    if isinstance(nonce, str):
        return bool(nonce)
    return _is_int(nonce)


def _is_valid_parameters(p: object, q: object, g: object) -> bool:
    return (all(_is_int(v) for v in (p, q, g))
            and p >= 3 and q >= 3 and 1 < g < p)


def register_login_secret(name: str, p: int, q: int, g: int) -> tuple[int, int]:
    """Choose x_M in [1, q-1] and return (secret x_M, public X_M = g^x_M mod p)."""
    if not _is_valid_name(name):
        raise ValueError("name must be a non-empty string")
    if not _is_valid_parameters(p, q, g):
        raise ValueError("invalid group parameters")
    x_M = random_exponent(q)
    return x_M, pow(g, x_M, p)


def make_interactive_response(x_M: int, challenge: int, q: int) -> tuple[int, int]:
    """Return (R = g^k mod P, z = k + e*x_M mod q) with a fresh k."""
    if not _is_int(q) or q < 3:
        raise ValueError("q must be an integer >= 3")
    if not _is_int(x_M) or not 0 < x_M < q:
        raise ValueError("x_M must be an integer in [1, q-1]")
    if not _is_int(challenge):
        raise ValueError("challenge must be an integer")
    k = random_exponent(q)
    R = pow(G, k, P)
    z = (k + (challenge % q) * x_M) % q
    return R, z


def verify_interactive_login(R: int, z: int, e: int, X_M: int,
                             p: int, q: int, g: int) -> bool:
    """Check R and X_M are subgroup elements and g^z = R * X_M^e mod p."""
    if not all(_is_int(v) for v in (R, z, e, X_M, p, q, g)):
        return False
    if not _is_valid_parameters(p, q, g) or not 0 <= z < q:
        return False
    if not (is_valid_element(R) and is_valid_element(X_M)):
        return False
    try:
        return pow(g, z, p) == (R * pow(X_M, e % q, p)) % p
    except (TypeError, ValueError):
        return False


def generate_challenge(bits: int = SECURE_CHALLENGE_BITS, weak: bool = False,
                       source: ChallengeSource | None = None) -> int:
    """Return a uniform challenge in [0, 2**bits); weak forces 4 bits.

    ``source`` may return the value directly (in range) to make tests
    deterministic; by default ``secrets.randbits`` is used.
    """
    if not _is_int(bits) or bits < 1:
        raise ValueError("bits must be a positive integer")
    if weak:
        bits = WEAK_CHALLENGE_BITS
    if source is None:
        return secrets.randbits(bits)
    value = source()
    if not _is_int(value) or not 0 <= value < 1 << bits:
        raise ValueError("challenge source returned an out-of-range value")
    return value


def make_noninteractive_response(x_M: int, name: str, nonce: int | str,
                                 p: int = P, q: int = Q,
                                 g: int = G) -> tuple[int, int]:
    """Return a Fiat-Shamir (R, z) proof bound to name and nonce."""
    if not _is_valid_name(name):
        raise ValueError("name must be a non-empty string")
    if not _is_valid_nonce(nonce):
        raise ValueError("nonce must be a non-empty string or an integer")
    if not _is_valid_parameters(p, q, g):
        raise ValueError("invalid group parameters")
    if not _is_int(x_M) or not 0 < x_M < q:
        raise ValueError("x_M must be an integer in [1, q-1]")
    k = random_exponent(q)
    R = pow(g, k, p)
    X_M = pow(g, x_M, p)
    e = H(NONINTERACTIVE_LABEL, name, X_M, R, nonce, q=q)
    z = (k + e * x_M) % q
    return R, z


def verify_noninteractive_login(name: str, R: int, z: int, nonce: int | str,
                                X_M: int, p: int = P, q: int = Q,
                                g: int = G) -> bool:
    """Verify a Fiat-Shamir proof using the session-certified name."""
    if not _is_valid_name(name) or not _is_valid_nonce(nonce):
        return False
    if not all(_is_int(v) for v in (R, z, X_M, p, q, g)):
        return False
    if not _is_valid_parameters(p, q, g) or not 0 <= z < q:
        return False
    if not (is_valid_element(R) and is_valid_element(X_M)):
        return False
    try:
        e = H(NONINTERACTIVE_LABEL, name, X_M, R, nonce, q=q)
    except (TypeError, ValueError):
        return False
    return verify_interactive_login(R, z, e, X_M, p, q, g)
