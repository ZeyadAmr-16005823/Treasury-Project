"""Shared, non-secret project configuration."""
from pathlib import Path

# Numeric student IDs of all four members, sorted and hyphen-joined.
GROUP = "16005823-16006499-16009599-17005797"

# Certificates are valid until this date (ISO YYYY-MM-DD). Live evaluation
# happens after the 12 December 2026 deadline, so keep this safely in the
# future; verification compares it with the current date.
CERT_EXPIRY = "2030-12-31"

HOST = "127.0.0.1"
SERVER_PORT = 5050
MALLORY_PORT = 6000
MAX_FRAME_BYTES = 4 * 1024 * 1024
SOCKET_TIMEOUT_SECONDS = 10
LOG_DIR = Path("runtime") / "logs"
DATA_DIR = Path("runtime") / "data"

# Project parameters. Keep these configurable; do not hard-code t=3 or n=5
# inside protocol algorithms.
DEFAULT_T = 3
DEFAULT_N = 5
MEMBER_NAMES = tuple(f"M{i}" for i in range(1, DEFAULT_N + 1))
PROGRAM_NAMES = ("server",) + MEMBER_NAMES

WEAKNESS_NAMES = {
    "unsigned-handshake", "fixed-nonce", "short-challenge", "no-nonce",
    "no-proof", "no-share-check", "unsigned-ballots", "no-encryption",
}


def validate_group() -> None:
    if not GROUP or GROUP.startswith("REPLACE-"):
        raise RuntimeError("Set GROUP in treasury/config.py before running the project")
