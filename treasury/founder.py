"""Founder setup: CA certificates and Milestone 2 vault generation.

M1: --init creates the CA key, --sign-certs issues founder-signed certificates.
M2: --setup-vault generates Shamir shares, signed Feldman commitments and the
encrypted vault, publishing a complete generation atomically.

The founder never reads another program's private key. All founder-only secrets
(s, polynomial coefficients, u, r, m and the derived key K) are used in memory
only and are never written to disk or logged.

M2 candidate setup uses rejection sampling: a candidate that would publish an
identity group element or a zero share is discarded and regenerated before any
artifact is written (see docs/M2_INTERFACES.md §4).
"""
import argparse
import json
import os
import secrets
import shutil

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .certificates import create_certificate
from .config import (CERT_EXPIRY, DATA_DIR, DEFAULT_N, DEFAULT_T, GROUP,
                     PROGRAM_NAMES, validate_group)
from .crypto_utils import (
    generate_p256_keypair,
    load_private_key,
    load_public_key,
    public_key_pem,
    save_private_key,
    sign_raw,
)
from .encoding import canonical_json, sha256
from .group import G, P, Q, is_valid_element
from .logging_utils import get_logger
from .sharing import (
    hex_element,
    lagrange_coefficient,
    make_commitments,
    make_shares,
    random_nonzero_scalar,
    vault_aad,
    vault_key,
    verify_share,
)

FOUNDER_DIR = DATA_DIR / "founder"
FOUNDER_PRIVATE = FOUNDER_DIR / "founder_private.pem"
FOUNDER_PUBLIC = DATA_DIR / "founder.pub"
REQUESTS_DIR = DATA_DIR / "requests"
CERTS_DIR = DATA_DIR / "certs"

# "vault" (not "m2") avoids a case-insensitive collision with member M2's own
# directory on Windows/macOS: m2 and M2 would otherwise be the same directory.
VAULT_DIR = DATA_DIR / "vault"
GENERATIONS_DIR = VAULT_DIR / "generations"
CURRENT_FILE = VAULT_DIR / "current.json"


def member_share_path(name: str, generation: str):
    """Versioned private share file: a member reads only its active generation."""
    return DATA_DIR / name / "m2" / "generations" / generation / "share.json"


def member_share_staging_path(name: str, generation: str):
    """Versioned temp directory for one member's next private share."""
    return DATA_DIR / name / "m2" / "generations" / f"{generation}.tmp"


VAULT_VERSION = 1
MAX_SETUP_ATTEMPTS = 32  # rejection sampling for degenerate candidates
VAULT_PLAINTEXT = b"Treasury vault: the club's treasure is protected by 3-of-5 shares.\n"


# --------------------------------------------------------------------------- M1
def setup_ca(log) -> None:
    """Create the founder's P-256 CA key and publish its public key."""
    FOUNDER_DIR.mkdir(parents=True, exist_ok=True)
    if FOUNDER_PRIVATE.exists():
        private_key = load_private_key(FOUNDER_PRIVATE)
        log.info("founder CA key already exists; not overwriting it")
    else:
        private_key, _ = generate_p256_keypair()
        save_private_key(FOUNDER_PRIVATE, private_key)
        log.info("founder CA key created")

    FOUNDER_PUBLIC.write_text(public_key_pem(private_key), encoding="ascii")
    log.info("founder public key written to %s", FOUNDER_PUBLIC)
    log.info("founder public key prefix %s", public_key_pem(private_key).splitlines()[1][:8])


def sign_certificates(log, allow_partial: bool = False) -> None:
    """Validate all requests, then stage and activate a complete certificate set."""
    if not FOUNDER_PRIVATE.exists():
        raise RuntimeError("founder CA key is missing; run with --init first")
    founder_private_key = load_private_key(FOUNDER_PRIVATE)

    selected, missing = [], []
    for name in PROGRAM_NAMES:
        request_path = REQUESTS_DIR / f"{name}.json"
        if request_path.exists():
            selected.append((name, request_path))
        else:
            missing.append(name)
    if missing and not allow_partial:
        raise ValueError("missing public-key requests: " + ", ".join(missing))
    if missing:
        log.warning("partial issuance (test-only); missing requests: %s", ", ".join(missing))

    prepared = []
    for name, request_path in selected:
        request = json.loads(request_path.read_text(encoding="utf-8"))
        if not isinstance(request, dict) or set(request) != {"name", "public_key"}:
            raise ValueError(f"invalid public-key request for {name}")
        if request["name"] != name:
            raise ValueError(f"public-key request name {request['name']!r} != expected {name!r}")
        public_key_pem_text = request["public_key"]
        try:
            load_public_key(public_key_pem_text)
        except ValueError as exc:
            raise ValueError(f"invalid public key in request {request_path.name}") from exc
        prepared.append((name, create_certificate(
            founder_private_key, name, public_key_pem_text, CERT_EXPIRY
        )))

    staging = CERTS_DIR.parent / "certs.staging"
    backup = CERTS_DIR.parent / "certs.backup"
    for directory in (staging, backup):
        if directory.exists():
            shutil.rmtree(directory)
    staging.mkdir(parents=True, exist_ok=True)
    try:
        for name, certificate in prepared:
            (staging / f"{name}.json").write_text(
                json.dumps(certificate.to_dict(), indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            log.info(
                "certificate issued for %s: group %s, expires %s, sig %s...",
                name, GROUP, CERT_EXPIRY, certificate.sig[:8],
            )
        if CERTS_DIR.exists():
            CERTS_DIR.rename(backup)
        try:
            os.replace(staging, CERTS_DIR)
        except OSError:
            if backup.exists():
                backup.rename(CERTS_DIR)
            raise
        if backup.exists():
            shutil.rmtree(backup)
    finally:
        if staging.exists():
            shutil.rmtree(staging)
    log.info("activated %d certificate(s) in %s", len(prepared), CERTS_DIR)


# --------------------------------------------------------------------------- M2
def _commitments_bytes(t: int, n: int, C_hexes: list[str]) -> bytes:
    return canonical_json(["commitments", GROUP, t, n, C_hexes])


def _write_json(path, value: dict, private: bool = False) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f"{path.name}.{secrets.token_hex(6)}.tmp")
    tmp.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if private and os.name != "nt":
        os.chmod(tmp, 0o600)
    os.replace(tmp, path)


def _sha256_file(path) -> str:
    return sha256(path.read_bytes()).hex()


def _next_generation(force: bool) -> tuple[str, object, object]:
    GENERATIONS_DIR.mkdir(parents=True, exist_ok=True)
    numbers = []
    for entry in GENERATIONS_DIR.iterdir():
        if entry.is_dir() and entry.name.startswith("generation-"):
            suffix = entry.name[len("generation-"):]
            if suffix.isdigit():
                numbers.append(int(suffix))
            if (entry / "manifest.json").exists() and not force:
                raise ValueError("a completed generation already exists; refusing to regenerate")
    number = max(numbers, default=0) + 1
    name = f"generation-{number:03d}"
    final = GENERATIONS_DIR / name
    staging = GENERATIONS_DIR / f"{name}.tmp"
    if staging.exists():
        shutil.rmtree(staging)
    return name, final, staging


def _candidate_is_valid(commitments: list[int], shares: list[int], m: int,
                        c1: int, c2: int, c1_hex: str, c2_hex: str,
                        D_C: str, t: int, n: int) -> bool:
    """Return False for a candidate that must be discarded before publication.

    Rejection rules: every published group element (commitments, m, c1, c2) is
    strict/non-identity, and no member share is zero (which would make h_i=1).
    Length checks are explicit caller checks in ``setup_vault``; they are
    repeated here defensively. ``verify_share`` itself cannot see n or t.
    """
    if len(commitments) != t or len(shares) != n:
        return False
    if not all(is_valid_element(c) for c in commitments):
        return False
    if not all(0 < share < Q for share in shares):
        return False
    for index, share in enumerate(shares, start=1):
        if not verify_share(share, index, commitments, P, Q, G):
            return False
    if not all(is_valid_element(value) for value in (m, c1, c2)):
        return False
    try:
        vault_key(m, c1_hex, c2_hex, D_C)
    except ValueError:
        return False
    return True


def _stage_shares(generation: str, shares: list[int]) -> None:
    """Stage each share in its member's versioned temp directory.

    Nothing visible to the active generation is modified here, so an interruption
    cannot make the current generation's shares unusable.
    """
    for index, share in enumerate(shares, start=1):
        staging_dir = member_share_staging_path(f"M{index}", generation)
        if staging_dir.exists():
            shutil.rmtree(staging_dir)
        _write_json(staging_dir / "share.json", {
            "index": index,
            "generation": generation,
            "s_i": hex_element(share),
        }, private=True)


def _activate_shares(generation: str, n: int) -> None:
    """Activate all staged member share directories in one pass.

    Previous generations are never modified. If this is interrupted, the current
    pointer still selects the old generation with its intact shares.
    """
    for index in range(1, n + 1):
        staging_dir = member_share_staging_path(f"M{index}", generation)
        final_dir = member_share_path(f"M{index}", generation).parent
        if not staging_dir.exists():
            raise RuntimeError(f"missing staged share directory for M{index}")
        os.replace(staging_dir, final_dir)


def setup_vault(log, t: int = DEFAULT_T, n: int = DEFAULT_N, force: bool = False) -> None:
    """Generate shares, signed commitments and the encrypted vault atomically."""
    if not (1 <= t <= n):
        raise ValueError("require 1 <= t <= n")
    if not FOUNDER_PRIVATE.exists():
        raise RuntimeError("founder CA key is missing; run with --init first")
    founder_private_key = load_private_key(FOUNDER_PRIVATE)

    # Founder-only secrets: never written to disk or logged. A candidate that
    # would publish an identity element or a zero share is discarded and a new
    # polynomial/ciphertext is generated before anything is written.
    for _attempt in range(MAX_SETUP_ATTEMPTS):
        s = random_nonzero_scalar(Q)
        coefficients, shares = make_shares(s, t, n, Q)
        if len(shares) != n:
            raise RuntimeError("share count does not match n")
        commitments = make_commitments(coefficients, P, Q, G)
        if len(commitments) != t:
            raise RuntimeError("commitment count does not match t")
        C_hexes = [hex_element(c) for c in commitments]
        commitments_bytes = _commitments_bytes(t, n, C_hexes)
        D_C = sha256(commitments_bytes).hex()
        u = random_nonzero_scalar(Q)
        m = pow(G, u, P)
        r = random_nonzero_scalar(Q)
        c1 = pow(G, r, P)
        c2 = m * pow(commitments[0], r, P) % P
        c1_hex, c2_hex = hex_element(c1), hex_element(c2)
        if _candidate_is_valid(commitments, shares, m, c1, c2,
                               c1_hex, c2_hex, D_C, t, n):
            break
    else:
        raise RuntimeError("could not generate a valid vault candidate")

    commitments_sig = sign_raw(founder_private_key, commitments_bytes)
    key = vault_key(m, c1_hex, c2_hex, D_C)
    aad = vault_aad(c1_hex, c2_hex, D_C)
    nonce = (0).to_bytes(12, "big")  # vault frame counter starts at 0
    sealed = AESGCM(key).encrypt(nonce, VAULT_PLAINTEXT, aad)
    frame = nonce + sealed

    vault_fields = {
        "group": GROUP,
        "version": VAULT_VERSION,
        "t": t,
        "n": n,
        "c1": c1_hex,
        "c2": c2_hex,
        "commitments_digest": D_C,
    }
    vault_sig = sign_raw(founder_private_key, canonical_json(vault_fields))

    generation, final, staging = _next_generation(force)
    published = False
    try:
        public_dir = staging / "public"
        public_dir.mkdir(parents=True, exist_ok=True)
        # Private shares are NOT published in the generation directory: each
        # member receives only its own versioned file (see _stage_shares).
        _write_json(public_dir / "commitments.json", {
            "group": GROUP, "t": t, "n": n, "commitments": C_hexes,
            "digest": D_C, "sig": commitments_sig,
        })
        _write_json(public_dir / "vault.json", {**vault_fields, "sig": vault_sig})
        (public_dir / "vault.enc").write_bytes(frame)
        _stage_shares(generation, shares)  # versioned temp dirs; active shares untouched

        # Validate the whole generation before publishing it.
        selected = list(range(1, t + 1))
        D = 1
        for index in selected:
            d_i = pow(c1, shares[index - 1], P)
            D = D * pow(d_i, lagrange_coefficient(index, selected, Q), P) % P
        recovered_m = c2 * pow(D, -1, P) % P
        recovered_key = vault_key(recovered_m, c1_hex, c2_hex, D_C)
        if recovered_m != m or AESGCM(recovered_key).decrypt(nonce, sealed, aad) != VAULT_PLAINTEXT:
            raise RuntimeError("vault self-check failed; nothing was published")

        digests = {
            # POSIX separators; keys are relative to the generation root and
            # never absolute, so consumers on any OS resolve them identically.
            path.relative_to(staging).as_posix(): _sha256_file(path)
            for path in sorted(staging.rglob("*")) if path.is_file()
        }
        _write_json(staging / "manifest.json", {
            "generation": generation, "group": GROUP, "t": t, "n": n,
            "commitments_digest": D_C, "artifacts": digests,
        })

        os.replace(staging, final)
        published = True
    finally:
        if staging.exists():
            shutil.rmtree(staging)
        if not published:
            for index in range(1, n + 1):
                leftover = member_share_staging_path(f"M{index}", generation)
                if leftover.exists():
                    shutil.rmtree(leftover)

    try:
        _activate_shares(generation, n)
    except Exception:
        for index in range(1, n + 1):
            leftover = member_share_staging_path(f"M{index}", generation)
            if leftover.exists():
                shutil.rmtree(leftover)
        raise
    _write_json(CURRENT_FILE, {
        "generation": generation, "group": GROUP, "t": t, "n": n,
        "commitments_digest": D_C,
    })
    log.info("published %s: t=%d n=%d commitments_digest=%s... c1=%s... c2=%s...",
             generation, t, n, D_C[:8], c1_hex[:8], c2_hex[:8])

    # Best-effort erasure: Python integers are immutable, so this clears
    # references rather than scrubbing memory (see docs/M2_INTERFACES.md).
    del s, u, r, m, key, recovered_m, recovered_key, coefficients, shares
    del commitments_bytes, sealed, frame, aad


def main() -> None:
    parser = argparse.ArgumentParser(description="Treasury founder setup")
    parser.add_argument("--t", type=int, default=DEFAULT_T)
    parser.add_argument("--n", type=int, default=DEFAULT_N)
    parser.add_argument("--init", action="store_true", help="create the founder CA key")
    parser.add_argument("--sign-certs", action="store_true",
                        help="sign certificates from public-key request files")
    parser.add_argument("--allow-partial", action="store_true",
                        help="TEST ONLY: issue certificates from available requests")
    parser.add_argument("--setup-vault", action="store_true",
                        help="generate shares, commitments and the encrypted vault")
    parser.add_argument("--force", action="store_true",
                        help="with --setup-vault: publish a new immutable generation; never overwrite")
    args = parser.parse_args()
    validate_group()
    log = get_logger("founder")
    if not (1 <= args.t <= args.n):
        parser.error("require 1 <= t <= n")

    if not any((args.init, args.sign_certs, args.setup_vault)):
        args.init = args.sign_certs = True
    try:
        if args.init:
            setup_ca(log)
        if args.sign_certs:
            sign_certificates(log, allow_partial=args.allow_partial)
        if args.setup_vault:
            setup_vault(log, t=args.t, n=args.n, force=args.force)
    except ValueError as exc:
        parser.error(str(exc))
    log.info("setup complete for t=%d, n=%d", args.t, args.n)


if __name__ == "__main__":
    main()
