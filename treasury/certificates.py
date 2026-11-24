"""Milestone 1 certificate structure: founder-signed identity certificates."""
from dataclasses import dataclass, asdict
from datetime import date

from .config import GROUP
from .crypto_utils import load_public_key, sign_raw, verify_raw
from .encoding import canonical_json

CERTIFICATE_FIELDS = frozenset({"group", "name", "public_key", "expires", "sig"})


@dataclass
class Certificate:
    group: str
    name: str
    public_key: str
    expires: str
    sig: str = ""

    def unsigned_fields(self) -> dict:
        return {k: v for k, v in asdict(self).items() if k != "sig"}

    def to_dict(self) -> dict:
        return asdict(self)


def create_certificate(founder_private_key, name: str, public_key_pem: str,
                       expires: str) -> Certificate:
    """Build a certificate and sign its four unsigned fields with the founder key."""
    certificate = Certificate(
        group=GROUP,
        name=name,
        public_key=public_key_pem,
        expires=expires,
    )
    certificate.sig = sign_raw(founder_private_key, canonical_json(certificate.unsigned_fields()))
    return certificate


def verify_certificate(certificate: dict, founder_public_key, expected_name: str) -> bool:
    """Accept a certificate only if the founder signed it for this exact identity.

    Checks the field set, GROUP, expected name, expiry date, public-key format
    and the founder's ECDSA signature over the canonical unsigned fields.
    """
    if not isinstance(certificate, dict) or set(certificate) != CERTIFICATE_FIELDS:
        return False
    if any(not isinstance(certificate[field], str) for field in CERTIFICATE_FIELDS):
        return False
    if certificate["group"] != GROUP:
        return False
    if certificate["name"] != expected_name:
        return False
    try:
        if date.fromisoformat(certificate["expires"]) < date.today():
            return False
        load_public_key(certificate["public_key"])
    except (ValueError, TypeError):
        return False
    unsigned = {field: value for field, value in certificate.items() if field != "sig"}
    return verify_raw(founder_public_key, canonical_json(unsigned), certificate["sig"])
