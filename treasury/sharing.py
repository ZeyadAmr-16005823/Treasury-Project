"""Milestone 2 Shamir sharing, Feldman-style commitments and vault helpers.

All group elements and scalars are encoded as fixed-width lowercase hex without
``0x``. ``GROUP`` is bound into the vault transcript and the founder signatures.
See docs/M2_INTERFACES.md for the frozen byte-level contract.
"""
import secrets

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .config import GROUP
from .encoding import canonical_json, sha256
from .group import P

GROUP_ELEMENT_BYTES = (P.bit_length() + 7) // 8
HEX_WIDTH = GROUP_ELEMENT_BYTES * 2  # 512 characters for the 2048-bit group
DIGEST_HEX_WIDTH = 64


def _is_int(value) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def is_subgroup_element(u: int, p: int, q: int, *, allow_identity: bool = False) -> bool:
    """Relaxed subgroup check: identity is permitted only when explicitly allowed.

    This is a local helper so Member 1 does not edit Member 4's ``group.py``.
    Member 4 may later provide a shared equivalent; until then importers use this.
    """
    if not all(_is_int(v) for v in (u, p, q)) or p < 3 or q < 3:
        return False
    if not (1 <= u < p):
        return False
    if not allow_identity and u == 1:
        return False
    return pow(u, q, p) == 1


def random_nonzero_scalar(q: int) -> int:
    """Uniformly sample from ℤ_q* = {1,…,q-1} using the OS CSPRNG."""
    if not _is_int(q) or q < 3:
        raise ValueError("q must be an integer >= 3")
    return secrets.randbelow(q - 1) + 1


def evaluate_polynomial(coefficients: list[int], x: int, q: int) -> int:
    """Evaluate f(x)=a0+a1*x+... modulo q using Horner's method."""
    if not isinstance(coefficients, (list, tuple)) or not coefficients:
        raise ValueError("coefficients must be a non-empty sequence")
    if not all(_is_int(a) for a in coefficients):
        raise ValueError("coefficients must be integers")
    if not _is_int(x) or not _is_int(q) or q < 2:
        raise ValueError("x and q must be integers, q >= 2")
    result = 0
    for coefficient in reversed(coefficients):
        result = (result * x + coefficient) % q
    return result


def make_shares(secret: int, t: int, n: int, q: int) -> tuple[list[int], list[int]]:
    """Random polynomial of degree AT MOST t-1 with a0=secret; return coefficients and shares.

    All coefficients a1…a(t-1) are drawn from ℤ_q as the handout specifies, so a
    zero highest coefficient is possible. With a published Feldman commitment
    C_{t-1}=1 that would reveal the polynomial is linear and effectively reduce
    the threshold; this negligible exception is documented in M2_INTERFACES.md
    pending the TA's interpretation.
    """
    if not all(_is_int(v) for v in (secret, t, n, q)):
        raise ValueError("secret, t, n and q must be integers")
    if not (1 <= t <= n) or q < 3:
        raise ValueError("require 1 <= t <= n and q >= 3")
    if not 0 <= secret < q:
        raise ValueError("secret must be in [0, q-1]")
    coefficients = [secret] + [secrets.randbelow(q) for _ in range(t - 1)]
    shares = [evaluate_polynomial(coefficients, i, q) for i in range(1, n + 1)]
    return coefficients, shares


def make_commitments(coefficients: list[int], p: int, q: int, g: int) -> list[int]:
    """Feldman-style commitments C_k = g^{a_k} mod p for each coefficient."""
    if not isinstance(coefficients, (list, tuple)) or not coefficients:
        raise ValueError("coefficients must be a non-empty sequence")
    if not all(_is_int(v) for v in (p, q, g)) or p < 3 or q < 3 or not 1 < g < p:
        raise ValueError("invalid group parameters")
    if not all(_is_int(a) for a in coefficients):
        raise ValueError("coefficients must be integers")
    return [pow(g, coefficient % q, p) for coefficient in coefficients]


def verify_share(share: int, member_index: int, commitments: list[int],
                 p: int, q: int, g: int) -> bool:
    """Check g^{s_i} == product(C_k^{i^k}) mod p, with M2 validation rules."""
    if not all(_is_int(v) for v in (share, member_index, p, q, g)):
        return False
    if member_index < 1 or not 0 <= share < q:
        return False
    if not isinstance(commitments, (list, tuple)) or not commitments:
        return False
    if not all(_is_int(c) for c in commitments):
        return False
    if not all(1 <= c < p for c in commitments):
        return False
    # C_0 = g^s and s is nonzero; later commitments may be the identity.
    if commitments[0] == 1:
        return False
    if not all(is_subgroup_element(c, p, q, allow_identity=(k > 0))
               for k, c in enumerate(commitments)):
        return False
    right = 1
    for k, commitment in enumerate(commitments):
        right = right * pow(commitment, pow(member_index, k), p) % p
    return pow(g, share, p) == right


def lagrange_coefficient(i: int, selected_indices: list[int], q: int) -> int:
    """Coefficient at zero for member i in the interpolation set."""
    if not _is_int(i) or not _is_int(q) or q < 2:
        raise ValueError("i and q must be integers, q >= 2")
    if not isinstance(selected_indices, (list, tuple)) or not selected_indices:
        raise ValueError("selected_indices must be a non-empty sequence")
    if not all(_is_int(j) for j in selected_indices):
        raise ValueError("indices must be integers")
    if len(set(selected_indices)) != len(selected_indices):
        raise ValueError("duplicate member indices")
    if i not in selected_indices:
        raise ValueError("member i is not in the selected set")
    result = 1
    for j in selected_indices:
        if j == i:
            continue
        difference = (j - i) % q
        if difference == 0:
            raise ValueError("indices are not distinct modulo q")
        result = result * (j % q) * pow(difference, -1, q) % q
    return result


def hex_element(value: int) -> str:
    """Fixed-width lowercase hex (no 0x) for a scalar or group element."""
    if not _is_int(value) or not 0 <= value < (1 << (8 * GROUP_ELEMENT_BYTES)):
        raise ValueError("value does not fit in the fixed hex width")
    return format(value, f"0{HEX_WIDTH}x")


def _check_hex(value, width: int, label: str) -> str:
    if not isinstance(value, str) or len(value) != width:
        raise ValueError(f"{label} must be exactly {width} lowercase hex characters")
    if any(char not in "0123456789abcdef" for char in value):
        raise ValueError(f"{label} must be lowercase hex without 0x")
    return value


def vault_transcript(c1_hex: str, c2_hex: str, D_C: str) -> bytes:
    _check_hex(c1_hex, HEX_WIDTH, "c1_hex")
    _check_hex(c2_hex, HEX_WIDTH, "c2_hex")
    _check_hex(D_C, DIGEST_HEX_WIDTH, "D_C")
    return canonical_json(["vault", GROUP, c1_hex, c2_hex, D_C])


def vault_aad(c1_hex: str, c2_hex: str, D_C: str) -> bytes:
    _check_hex(c1_hex, HEX_WIDTH, "c1_hex")
    _check_hex(c2_hex, HEX_WIDTH, "c2_hex")
    _check_hex(D_C, DIGEST_HEX_WIDTH, "D_C")
    return canonical_json(["vault-aad", GROUP, c1_hex, c2_hex, D_C, "AES-256-GCM"])


def vault_key(m: int, c1_hex: str, c2_hex: str, D_C: str) -> bytes:
    """HKDF-SHA256 derive the 32-byte vault key from the recovered group element m."""
    if not _is_int(m) or not 1 <= m < P:
        raise ValueError("m must be a non-identity group element modulo P")
    info = b"ICS505|" + GROUP.encode("ascii") + b"|vault|" + sha256(
        vault_transcript(c1_hex, c2_hex, D_C)
    )
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=info,
    ).derive(m.to_bytes(GROUP_ELEMENT_BYTES, "big"))
