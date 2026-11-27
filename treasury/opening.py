"""Milestone 2 verifiable decryption shares (Member 3). A5 is mandatory.

Threshold ElGamal opening of any ciphertext (c1, c2) encrypted to h = C_0:

    member i     d_i = c1^{s_i}                                   (decryption share)
                 w <- Z_q*, T1 = g^w, T2 = c1^w
                 e = H("dec", i, c1, h_i, d_i, T1, T2)
                 z = w + e*s_i mod q                               (Chaum-Pedersen proof)
    verifier     h_i = prod_k C_k^{i^k}
                 g^z == T1 * h_i^e   and   c1^z == T2 * d_i^e      (same s_i in both)
    combiner     D = prod_{i in S} d_i^{lambda_i},  m = c2 * D^{-1}   (|S| = t)

The proof shows d_i was made with the same secret s_i that is committed in h_i,
without revealing s_i. Nothing here is specific to the vault: Milestone 3 reuses
``threshold_decrypt`` on the aggregated ballot ciphertext.

Who uses what:
  * members (member.py):  load_public_vault, load_member_share, make_decryption_share
  * server (Member 2):    load_public_vault, DecryptionShare.from_dict,
                          verify_decryption_share / threshold_decrypt, decrypt_vault
  * A5 (Member 4/2):      threshold_decrypt(..., verify_proofs=False) is the
                          deliberately weak ``--weak no-proof`` path.

Wire encoding follows docs/M2_INTERFACES.md §2: group elements and scalars are
fixed-width 512-char lowercase hex (``sharing.hex_element``).
"""
import json
from dataclasses import dataclass, field
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .config import DATA_DIR, GROUP
from .crypto_utils import verify_raw
from .encoding import H, canonical_json, sha256
from .group import G, P, Q, is_valid_element, random_exponent
from .sharing import (DIGEST_HEX_WIDTH, HEX_WIDTH, hex_element, lagrange_coefficient,
                      vault_aad, vault_key, verify_share)

DEC_LABEL = "dec"
VAULT_NONCE_BYTES = 12


class OpeningError(ValueError):
    """Bad public data, a bad share file, or not enough valid decryption shares."""


def _is_int(value) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _parse_hex(value, label: str, width: int = HEX_WIDTH) -> int:
    if not isinstance(value, str) or len(value) != width:
        raise OpeningError(f"{label} must be exactly {width} lowercase hex characters")
    if any(char not in "0123456789abcdef" for char in value):
        raise OpeningError(f"{label} must be lowercase hex without 0x")
    return int(value, 16)


# -- data types ----------------------------------------------------------------------------
@dataclass(frozen=True)
class DecryptionProof:
    T1: int
    T2: int
    e: int
    z: int

    def to_dict(self) -> dict:
        return {"T1": hex_element(self.T1), "T2": hex_element(self.T2),
                "e": hex_element(self.e), "z": hex_element(self.z)}

    @classmethod
    def from_dict(cls, data) -> "DecryptionProof":
        if not isinstance(data, dict) or set(data) != {"T1", "T2", "e", "z"}:
            raise OpeningError("proof must have exactly T1, T2, e, z")
        return cls(*(_parse_hex(data[k], f"proof.{k}") for k in ("T1", "T2", "e", "z")))


@dataclass(frozen=True)
class DecryptionShare:
    """d_i = c1^{s_i} from member ``index``; ``proof`` is None only in the A5 weak demo."""
    index: int
    d: int
    proof: DecryptionProof | None

    def to_dict(self) -> dict:
        return {"index": self.index, "d": hex_element(self.d),
                "proof": self.proof.to_dict() if self.proof is not None else None}

    @classmethod
    def from_dict(cls, data) -> "DecryptionShare":
        if not isinstance(data, dict) or not {"index", "d"} <= set(data) <= {"index", "d", "proof"}:
            raise OpeningError("decryption share must have index, d and proof")
        index = data["index"]
        if not _is_int(index):
            raise OpeningError("index must be an integer")
        proof = data.get("proof")
        return cls(index, _parse_hex(data["d"], "d"),
                   DecryptionProof.from_dict(proof) if proof is not None else None)


# -- maths ----------------------------------------------------------------------------------
def public_share_key(member_index: int, commitments: list[int], p: int = P) -> int:
    """h_i = prod_k C_k^{i^k} mod p, i.e. g^{s_i}, computed only from public commitments."""
    if not _is_int(member_index) or member_index < 1:
        raise OpeningError("member index must be an integer >= 1")
    if not isinstance(commitments, (list, tuple)) or not commitments:
        raise OpeningError("commitments must be a non-empty list")
    if not all(is_valid_element(c) for c in commitments):
        raise OpeningError("every commitment must be a strict group element")
    h_i = 1
    for k, commitment in enumerate(commitments):
        h_i = h_i * pow(commitment, pow(member_index, k), p) % p
    return h_i


def decryption_challenge(member_index: int, c1: int, h_i: int, d_i: int,
                         T1: int, T2: int, q: int = Q) -> int:
    """e = H("dec", i, c1, h_i, d_i, T1, T2) — the transcript fixed in M2_INTERFACES §9."""
    return H(DEC_LABEL, member_index, c1, h_i, d_i, T1, T2, q=q)


def make_decryption_share(share: int, member_index: int, c1: int, h_i: int | None = None,
                          *, p: int = P, q: int = Q, g: int = G) -> DecryptionShare:
    """d_i = c1^{s_i} and a Chaum-Pedersen equality-of-discrete-logs proof.

    ``h_i`` (from the public commitments) is checked against g^{s_i} when given,
    so a member never publishes a share that would fail verification.
    """
    if not _is_int(share) or not 0 < share < q:
        raise OpeningError("share must be an integer in [1, q-1]")
    if not _is_int(member_index) or member_index < 1:
        raise OpeningError("member index must be an integer >= 1")
    if not is_valid_element(c1):
        raise OpeningError("c1 must be a strict group element")
    own_h = pow(g, share, p)
    if h_i is not None and h_i != own_h:
        raise OpeningError("share does not match the public commitments")
    d_i = pow(c1, share, p)
    w = random_exponent(q)                 # uniform in [1, q-1]: w = 0 never happens
    T1, T2 = pow(g, w, p), pow(c1, w, p)
    e = decryption_challenge(member_index, c1, own_h, d_i, T1, T2, q)
    z = (w + e * share) % q
    del w
    return DecryptionShare(member_index, d_i, DecryptionProof(T1, T2, e, z))


def verify_decryption_share(decryption_share: DecryptionShare, c1: int, h_i: int,
                            *, p: int = P, q: int = Q, g: int = G) -> bool:
    """Accept d_i only if both proof equations hold for the recomputed challenge.

    Mandatory A5 comparison: ``--weak no-proof`` skips this call (see
    ``threshold_decrypt(verify_proofs=False)``); secure mode rejects an invalid or
    missing proof and continues with the remaining valid participants.
    """
    if not isinstance(decryption_share, DecryptionShare):
        return False
    proof = decryption_share.proof
    if proof is None:
        return False
    i, d_i = decryption_share.index, decryption_share.d
    if not _is_int(i) or i < 1:
        return False
    if not all(_is_int(v) for v in (proof.T1, proof.T2, proof.e, proof.z)):
        return False
    if not all(is_valid_element(v) for v in (c1, h_i, d_i, proof.T1, proof.T2)):
        return False
    if not 0 <= proof.z < q:
        return False
    e = decryption_challenge(i, c1, h_i, d_i, proof.T1, proof.T2, q)
    if e != proof.e:
        return False
    return (pow(g, proof.z, p) == proof.T1 * pow(h_i, e, p) % p
            and pow(c1, proof.z, p) == proof.T2 * pow(d_i, e, p) % p)


def combine_decryption_shares(decryption_shares, q: int = Q, p: int = P) -> int:
    """D = prod d_i^{lambda_i} over exactly the shares given (the caller picks t of them)."""
    shares = list(decryption_shares)
    if not shares:
        raise OpeningError("no decryption shares to combine")
    indices = [s.index for s in shares]
    if len(set(indices)) != len(indices):
        raise OpeningError("duplicate member index in decryption shares")
    D = 1
    for s in shares:
        if not is_valid_element(s.d):
            raise OpeningError(f"d_{s.index} is not a strict group element")
        D = D * pow(s.d, lagrange_coefficient(s.index, indices, q), p) % p
    return D


def recover_message(c2: int, D: int, p: int = P) -> int:
    """m = c2 * D^{-1} mod p."""
    if not is_valid_element(c2) or not is_valid_element(D):
        raise OpeningError("c2 and D must be strict group elements")
    return c2 * pow(D, -1, p) % p


@dataclass
class OpeningResult:
    m: int
    used: list[int]                                   # indices combined
    rejected: dict[int, str] = field(default_factory=dict)  # index -> reason


def threshold_decrypt(c1: int, c2: int, commitments: list[int], decryption_shares,
                      t: int, n: int, *, verify_proofs: bool = True,
                      p: int = P, q: int = Q, g: int = G) -> OpeningResult:
    """Server-side opening of any (c1, c2): check, verify, pick t, combine, recover m.

    Performs the caller checks that ``verify_share`` cannot (``len(commitments) == t``,
    ``1 <= i <= n``), drops duplicates and invalid shares, and uses the first t valid
    shares in index order. ``verify_proofs=False`` is ONLY for ``--weak no-proof`` (A5):
    shares are then combined without checking their proofs. Raises ``OpeningError``
    if fewer than t shares survive.
    """
    if not (_is_int(t) and _is_int(n) and 1 <= t <= n):
        raise OpeningError("require 1 <= t <= n")
    if not isinstance(commitments, (list, tuple)) or len(commitments) != t:
        raise OpeningError(f"expected exactly t={t} commitments")
    if not is_valid_element(c1) or not is_valid_element(c2):
        raise OpeningError("c1 and c2 must be strict group elements")
    accepted: dict[int, DecryptionShare] = {}
    rejected: dict[int, str] = {}
    for s in decryption_shares:
        i = getattr(s, "index", None)
        if not isinstance(s, DecryptionShare) or not _is_int(i):
            rejected[-1] = "malformed decryption share"
            continue
        if not 1 <= i <= n:
            rejected[i] = "member index out of range"
        elif i in accepted:
            rejected[i] = "duplicate share"
        elif not is_valid_element(s.d):
            rejected[i] = "d_i is not a strict group element"
        elif verify_proofs and not verify_decryption_share(
                s, c1, public_share_key(i, commitments, p), p=p, q=q, g=g):
            rejected[i] = "missing or invalid proof"
        else:
            accepted[i] = s
    if len(accepted) < t:
        raise OpeningError(f"only {len(accepted)} valid decryption share(s); {t} required"
                           + (f" (rejected: {rejected})" if rejected else ""))
    chosen = [accepted[i] for i in sorted(accepted)[:t]]
    D = combine_decryption_shares(chosen, q, p)
    return OpeningResult(recover_message(c2, D, p), [s.index for s in chosen], rejected)


# -- published vault data ----------------------------------------------------------------
def vault_dir(data_dir: Path = DATA_DIR) -> Path:
    return Path(data_dir) / "vault"


def member_share_path(name: str, generation: str, data_dir: Path = DATA_DIR) -> Path:
    return Path(data_dir) / name / "m2" / "generations" / generation / "share.json"


@dataclass
class PublicVault:
    generation: str
    t: int
    n: int
    commitments: list[int]
    commitments_digest: str
    c1: int
    c2: int
    c1_hex: str
    c2_hex: str
    frame: bytes                      # vault.enc = 12-byte nonce || ciphertext+tag


def _read_json(path: Path) -> dict:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise OpeningError(f"missing {path}") from exc
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise OpeningError(f"{path} is not valid JSON") from exc
    if not isinstance(value, dict):
        raise OpeningError(f"{path} must contain a JSON object")
    return value


def load_public_vault(founder_public_key, data_dir: Path = DATA_DIR) -> PublicVault:
    """Load the active generation and check everything the founder signed.

    Checks: current.json -> completed generation (manifest present, artifact digests
    match), GROUP everywhere, founder signature on the commitments and on vault.json,
    the commitments digest D_C in all three places, t/n consistency, and strict
    group membership of every commitment, c1 and c2.
    """
    current = _read_json(vault_dir(data_dir) / "current.json")
    generation = current.get("generation")
    if not isinstance(generation, str) or not generation.startswith("generation-") \
            or not generation[len("generation-"):].isdigit():
        raise OpeningError("current.json does not name a valid generation")
    root = vault_dir(data_dir) / "generations" / generation
    manifest = _read_json(root / "manifest.json")
    commitments_file = _read_json(root / "public" / "commitments.json")
    vault = _read_json(root / "public" / "vault.json")

    for label, doc in (("current.json", current), ("manifest.json", manifest),
                       ("commitments.json", commitments_file), ("vault.json", vault)):
        if doc.get("group") != GROUP:
            raise OpeningError(f"{label} belongs to another group")
    if manifest.get("generation") != generation:
        raise OpeningError("manifest generation does not match current.json")
    artifacts = manifest.get("artifacts")
    if not isinstance(artifacts, dict) or not artifacts:
        raise OpeningError("manifest has no artifact digests")
    for rel, digest in artifacts.items():
        if not isinstance(rel, str) or rel.startswith("/") or "\\" in rel or ".." in rel.split("/"):
            raise OpeningError(f"unsafe manifest path {rel!r}")
        path = root / rel
        if not path.is_file() or sha256(path.read_bytes()).hex() != digest:
            raise OpeningError(f"artifact {rel} does not match its manifest digest")
    for rel in ("public/commitments.json", "public/vault.json", "public/vault.enc"):
        if rel not in artifacts:
            raise OpeningError(f"manifest does not cover {rel}")

    t, n = commitments_file.get("t"), commitments_file.get("n")
    if not (_is_int(t) and _is_int(n) and 1 <= t <= n):
        raise OpeningError("commitments.json has invalid t/n")
    for label, doc in (("current.json", current), ("manifest.json", manifest), ("vault.json", vault)):
        if doc.get("t") != t or doc.get("n") != n:
            raise OpeningError(f"{label} disagrees on t/n")

    C_hexes = commitments_file.get("commitments")
    if not isinstance(C_hexes, list) or len(C_hexes) != t:
        raise OpeningError(f"expected exactly t={t} commitments")
    commitments = [_parse_hex(c, "commitment") for c in C_hexes]
    if not all(is_valid_element(c) for c in commitments):
        raise OpeningError("a commitment is not a strict group element")
    commitments_bytes = canonical_json(["commitments", GROUP, t, n, C_hexes])
    D_C = sha256(commitments_bytes).hex()
    if not verify_raw(founder_public_key, commitments_bytes, commitments_file.get("sig")):
        raise OpeningError("founder signature on commitments is invalid")
    for label, value in (("commitments.json", commitments_file.get("digest")),
                         ("vault.json", vault.get("commitments_digest")),
                         ("current.json", current.get("commitments_digest")),
                         ("manifest.json", manifest.get("commitments_digest"))):
        if value != D_C:
            raise OpeningError(f"{label} has the wrong commitments digest")

    unsigned = {k: v for k, v in vault.items() if k != "sig"}
    if not verify_raw(founder_public_key, canonical_json(unsigned), vault.get("sig")):
        raise OpeningError("founder signature on vault.json is invalid")
    c1, c2 = _parse_hex(vault.get("c1"), "c1"), _parse_hex(vault.get("c2"), "c2")
    if not (is_valid_element(c1) and is_valid_element(c2)):
        raise OpeningError("c1 and c2 must be strict group elements")
    frame = (root / "public" / "vault.enc").read_bytes()
    _parse_hex(D_C, "commitments digest", DIGEST_HEX_WIDTH)
    return PublicVault(generation, t, n, commitments, D_C, c1, c2,
                       vault["c1"], vault["c2"], frame)


def member_index(name: str) -> int:
    """The Shamir index bound to a certified member name: "M3" -> 3."""
    if not isinstance(name, str) or not name.startswith("M") or not name[1:].isdigit():
        raise OpeningError(f"{name!r} is not a member name")
    return int(name[1:])


def load_member_share(name: str, vault: PublicVault, data_dir: Path = DATA_DIR) -> int:
    """Member-side: read ONLY this member's share for the active generation and check it.

    Checks the caller-side rules verify_share() cannot (index bound to the certified
    name, index <= n, generation matches current.json) and then the Feldman equation
    g^{s_i} = prod C_k^{i^k} against the founder-signed commitments.
    """
    i = member_index(name)
    if not 1 <= i <= vault.n:
        raise OpeningError(f"{name} is not one of the n={vault.n} share holders")
    record = _read_json(member_share_path(name, vault.generation, data_dir))
    if set(record) != {"index", "generation", "s_i"}:
        raise OpeningError("share file has unexpected fields")
    if record["index"] != i:
        raise OpeningError(f"share file index {record['index']!r} does not match {name}")
    if record["generation"] != vault.generation:
        raise OpeningError("share file is from a different generation")
    s_i = _parse_hex(record["s_i"], "s_i")
    if not verify_share(s_i, i, vault.commitments, P, Q, G):
        raise OpeningError(f"{name}'s share does not match the founder's commitments")
    return s_i


def decrypt_vault(m: int, vault: PublicVault) -> bytes:
    """Derive K from the recovered m and open vault.enc; raises OpeningError if m is wrong."""
    if len(vault.frame) < VAULT_NONCE_BYTES + 16:
        raise OpeningError("vault.enc is too short")
    try:
        key = vault_key(m, vault.c1_hex, vault.c2_hex, vault.commitments_digest)
        aad = vault_aad(vault.c1_hex, vault.c2_hex, vault.commitments_digest)
        return AESGCM(key).decrypt(vault.frame[:VAULT_NONCE_BYTES],
                                   vault.frame[VAULT_NONCE_BYTES:], aad)
    except (InvalidTag, ValueError) as exc:
        raise OpeningError("vault decryption failed: wrong m or modified vault") from exc
