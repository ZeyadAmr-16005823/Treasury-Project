"""Founder setup: create the CA key and issue founder-signed certificates.

The founder only ever handles its own CA private key and other programs'
*public* key requests. Each program generates its own identity key and writes
its own public request file; this module reads those requests and publishes the
signed certificates that everyone can verify with founder.pub.
"""
import argparse
import json

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
        log.info("founder CA key already exists; reusing it")
    else:
        private_key, pem = generate_p256_keypair()
        save_private_key(FOUNDER_PRIVATE, private_key)
        FOUNDER_PUBLIC.write_text(pem, encoding="ascii")
        log.info("founder CA key created; public key written to %s", FOUNDER_PUBLIC)
    if not FOUNDER_PUBLIC.exists():
        FOUNDER_PUBLIC.write_text(public_key_pem(private_key), encoding="ascii")
    log.info("founder public key prefix %s", public_key_pem(private_key).splitlines()[1][:8])


def sign_certificates(log) -> None:
    """Sign one certificate per available public-key request."""
    if not FOUNDER_PRIVATE.exists():
        raise RuntimeError("founder CA key is missing; run with --init first")
    founder_private_key = load_private_key(FOUNDER_PRIVATE)
    CERTS_DIR.mkdir(parents=True, exist_ok=True)
    for name in PROGRAM_NAMES:
        request_path = REQUESTS_DIR / f"{name}.json"
        if not request_path.exists():
            log.warning("no public-key request found for %s; skipping", name)
            continue
        request = json.loads(request_path.read_text(encoding="utf-8"))
        if not isinstance(request, dict) or set(request) != {"name", "public_key"}:
            raise ValueError(f"invalid public-key request for {name}")
        if request["name"] != name:
            raise ValueError(f"public-key request name {request['name']!r} != expected {name!r}")
        public_key_pem_text = request["public_key"]
        load_public_key(public_key_pem_text)  # reject malformed/non-P-256 keys early

        certificate = create_certificate(
            founder_private_key, name, public_key_pem_text, CERT_EXPIRY
        )
        cert_path = CERTS_DIR / f"{name}.json"
        cert_path.write_text(json.dumps(certificate.to_dict(), indent=2, sort_keys=True) + "\n",
                             encoding="utf-8")
        log.info(
            "certificate issued for %s: group %s, expires %s, sig %s...",
            name, GROUP, CERT_EXPIRY, certificate.sig[:8],
        )


def main() -> None:
    parser = argparse.ArgumentParser(description="Treasury founder setup")
    parser.add_argument("--t", type=int, default=3)
    parser.add_argument("--n", type=int, default=5)
    parser.add_argument("--init", action="store_true", help="create the founder CA key")
    parser.add_argument("--sign-certs", action="store_true",
                        help="sign certificates from public-key request files")
    args = parser.parse_args()
    validate_group()
    log = get_logger("founder")
    if not (1 <= args.t <= args.n):
        parser.error("require 1 <= t <= n")

    if not args.init and not args.sign_certs:
        args.init = args.sign_certs = True
    if args.init:
        setup_ca(log)
    if args.sign_certs:
        sign_certificates(log)
    log.info("setup complete for t=%d, n=%d", args.t, args.n)


if __name__ == "__main__":
    main()
