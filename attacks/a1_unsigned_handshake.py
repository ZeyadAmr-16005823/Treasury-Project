"""A1: unsigned handshake -> Mallory man-in-the-middle (Member 2).

Self-contained demonstration in a temporary directory (it never touches
``runtime/data``). It starts the real server, the Mallory proxy and the real
member client in one process and runs four scenarios:

  1. weak  + passive : Mallory reads registration, login and the signed request
  2. weak  + modify  : Mallory changes the request body -> ECDSA check rejects it
  3. weak  + replay  : Mallory re-sends an accepted request -> sequence check rejects it
  4. secure          : the signed handshake detects the key substitution

Run from the repository root with either:

    python -m attacks.a1_unsigned_handshake
    python attacks/a1_unsigned_handshake.py

For the live demo with three terminals use ``python -m treasury.mallory`` (see README).
"""
import json
import logging
import socket
import sys
import tempfile
from contextlib import closing
from dataclasses import dataclass
from pathlib import Path

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from treasury import member as member_mod
from treasury.certificates import create_certificate
from treasury.config import CERT_EXPIRY, SOCKET_TIMEOUT_SECONDS
from treasury.crypto_utils import generate_p256_keypair, public_key_pem, save_private_key
from treasury.handshake import client_handshake
from treasury.logging_utils import get_logger
from treasury.mallory import MalloryProxy
from treasury.server import ServerPaths, TreasuryServer, load_identity

WEAK = "unsigned-handshake"
MEMBER = "M1"
REQUEST = ("spend", {"amount": 50, "reason": "team pizza"})


@dataclass
class World:
    """Founder CA, server and one member, all inside ``data_dir``."""
    data_dir: Path
    paths: ServerPaths


def build_world(data_dir: Path, member_names=(MEMBER,)) -> World:
    """Create founder.pub, the server key/cert and member keys/certs (test/demo only)."""
    data_dir = Path(data_dir)
    founder_key, founder_pem = generate_p256_keypair()
    (data_dir / "certs").mkdir(parents=True, exist_ok=True)
    (data_dir / "founder.pub").write_text(founder_pem, encoding="ascii")

    def issue(name: str, private_key) -> None:
        cert = create_certificate(founder_key, name, public_key_pem(private_key), CERT_EXPIRY)
        (data_dir / "certs" / f"{name}.json").write_text(
            json.dumps(cert.to_dict()), encoding="utf-8")

    paths = ServerPaths(data_dir)
    server_key, _ = generate_p256_keypair()
    save_private_key(paths.private_key, server_key)
    issue("server", server_key)

    member_mod.DATA_DIR = data_dir  # member.py resolves its files from this module global
    quiet = logging.getLogger("a1-setup")
    quiet.addHandler(logging.NullHandler())
    quiet.propagate = False
    for name in member_names:
        member_mod.init_identity(name, quiet)
        issue(name, member_mod.load_private_key(member_mod.private_key_path(name)))
    return World(data_dir, paths)


@dataclass
class Outcome:
    member_ok: bool
    member_error: str
    interception: object  # mallory.Interception or None


def run_scenario(world: World, *, weak: bool, tamper: str = "none",
                 logs: tuple = None, login_mode: str = "interactive") -> Outcome:
    """Run server + Mallory + one member session and report what happened."""
    server_log, mallory_log, member_log = logs or (get_logger("server"), get_logger("mallory"),
                                                   get_logger(MEMBER))
    weak_set = {WEAK} if weak else set()
    server = TreasuryServer(load_identity(world.paths), world.paths, server_log,
                            weak=weak_set, port=0)
    server.start_background()
    proxy = MalloryProxy(mallory_log, listen_port=0, server_port=server.port, tamper=tamper)
    proxy.start_background()
    try:
        identity = member_mod.load_identity(MEMBER)
        error = ""
        try:
            with closing(socket.create_connection(("127.0.0.1", proxy.listen_port),
                                                  timeout=SOCKET_TIMEOUT_SECONDS)) as sock:
                member_mod.run_session(sock, identity, member_log, handshake=client_handshake,
                                       login_mode=login_mode, requests=[REQUEST], weak=weak_set)
        except Exception as exc:  # the member closes on any refusal
            error = f"{type(exc).__name__}: {exc}"
            member_log.error("connection closed: %s", error)
        # Let Mallory's relay thread finish logging the final exchange.
        interception = proxy.interceptions[-1] if proxy.interceptions else None
        if interception is not None:
            interception.done.wait(timeout=5)
        return Outcome(not error, error, interception)
    finally:
        proxy.stop()
        server.stop()


def main() -> int:
    log = get_logger("a1")
    with tempfile.TemporaryDirectory(prefix="a1-demo-") as tmp:
        world = build_world(Path(tmp))
        log.info("=" * 70)
        log.info("A1 demo - temporary identities in %s", tmp)

        scenarios = [
            ("1. WEAK handshake, Mallory passive", dict(weak=True, tamper="none")),
            ("2. WEAK handshake, Mallory modifies the signed request", dict(weak=True, tamper="modify")),
            ("3. WEAK handshake, Mallory replays the signed request", dict(weak=True, tamper="replay")),
            ("4. SECURE handshake, Mallory in the middle", dict(weak=False, tamper="none")),
        ]
        summary = []
        for title, options in scenarios:
            log.info("-" * 70)
            log.info(title)
            outcome = run_scenario(world, **options)
            seen = outcome.interception.seen if outcome.interception else []
            results = outcome.interception.request_results if outcome.interception else []
            summary.append((title, outcome, len(seen), results))

        log.info("=" * 70)
        log.info("SUMMARY")
        for title, outcome, seen, results in summary:
            verdicts = ", ".join(("replay " if r.get("replay") else "") +
                                 ("accepted" if r.get("ok") else f"REJECTED ({r.get('error')})")
                                 for r in results) or "-"
            log.info("%s", title)
            log.info("    member session: %s | Mallory read %d plaintext message(s) | requests: %s",
                     "completed" if outcome.member_ok else f"closed ({outcome.member_error})",
                     seen, verdicts)
    return 0


if __name__ == "__main__":
    sys.exit(main())
