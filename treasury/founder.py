"""Founder setup: create the CA key and issue founder-signed certificates.

The founder only ever handles its own CA private key and other programs'
*public* key requests. Each program generates its own identity key and writes
its own public request file; this module reads those requests and publishes the
signed certificates that everyone can verify with founder.pub.
"""
import argparse
import json
import os
import shutil

from .certificates import create_certificate
from .config import CERT_EXPIRY, DATA_DIR, GROUP, PROGRAM_NAMES, validate_group
from .crypto_utils import (
    generate_p256_keypair,
    load_private_key,
    load_public_key,
    public_key_pem,
    save_private_key,
)
from .logging_utils import get_logger

FOUNDER_DIR = DATA_DIR / "founder"
FOUNDER_PRIVATE = FOUNDER_DIR / "founder_private.pem"
FOUNDER_PUBLIC = DATA_DIR / "founder.pub"
REQUESTS_DIR = DATA_DIR / "requests"
CERTS_DIR = DATA_DIR / "certs"


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

    # Always re-derive the public key from the real private key, so a stale or
    # corrupted founder.pub is repaired and everyone verifies against the
    # correct CA key. The private key itself is never regenerated here.
    FOUNDER_PUBLIC.write_text(public_key_pem(private_key), encoding="ascii")
    log.info("founder public key written to %s", FOUNDER_PUBLIC)
    log.info("founder public key prefix %s", public_key_pem(private_key).splitlines()[1][:8])


def sign_certificates(log, allow_partial: bool = False) -> None:
    """Validate all requests, then stage and activate a complete certificate set.

    Normal setup is fail-closed: all six requests must be present and valid before
    anything is written. ``allow_partial`` is restricted to tests/demos.
    """
    if not FOUNDER_PRIVATE.exists():
        raise RuntimeError("founder CA key is missing; run with --init first")
    founder_private_key = load_private_key(FOUNDER_PRIVATE)

    # Pass 1a — locate every expected request before touching the active certs.
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

    # Pass 1b — validate every selected request, building certificates in memory.
    prepared = []
    for name, request_path in selected:
        request = json.loads(request_path.read_text(encoding="utf-8"))
        if not isinstance(request, dict) or set(request) != {"name", "public_key"}:
            raise ValueError(f"invalid public-key request for {name}")
        if request["name"] != name:
            raise ValueError(f"public-key request name {request['name']!r} != expected {name!r}")
        public_key_pem_text = request["public_key"]
        try:
            load_public_key(public_key_pem_text)  # P-256 only, malformed PEM rejected
        except ValueError as exc:
            raise ValueError(f"invalid public key in request {request_path.name}") from exc
        prepared.append((name, create_certificate(
            founder_private_key, name, public_key_pem_text, CERT_EXPIRY
        )))

    # Pass 2 — stage the complete set, then activate it in one swap. A failure
    # cannot leave a partial set or make stale certificates look newly issued.
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


def main() -> None:
    parser = argparse.ArgumentParser(description="Treasury founder setup")
    parser.add_argument("--t", type=int, default=3)
    parser.add_argument("--n", type=int, default=5)
    parser.add_argument("--init", action="store_true", help="create the founder CA key")
    parser.add_argument("--sign-certs", action="store_true",
                        help="sign certificates from public-key request files")
    parser.add_argument("--allow-partial", action="store_true",
                        help="TEST ONLY: issue certificates from available requests")
    args = parser.parse_args()
    validate_group()
    log = get_logger("founder")
    if not (1 <= args.t <= args.n):
        parser.error("require 1 <= t <= n")

    if not args.init and not args.sign_certs:
        args.init = args.sign_certs = True
    try:
        if args.init:
            setup_ca(log)
        if args.sign_certs:
            sign_certificates(log, allow_partial=args.allow_partial)
    except ValueError as exc:
        parser.error(str(exc))
    log.info("setup complete for t=%d, n=%d", args.t, args.n)


if __name__ == "__main__":
    main()
