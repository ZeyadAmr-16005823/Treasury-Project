"""Member program (Member 3): identity setup and the Milestone 1 client flow.

Setup (once per member, before the founder signs certificates):

    python -m treasury.member --name M1 --init

Normal run:

    python -m treasury.member --name M1                       # interactive login
    python -m treasury.member --name M1 --login noninteractive
    python -m treasury.member --name M1 --login both          # two sessions, one per method
    python -m treasury.member --name M1 --op spend --body '{"amount": 50, "reason": "pizza"}'
    python -m treasury.member --name M1 --port 6000           # through Mallory (A1)
    python -m treasury.member --name M3 --open                # M2: send my decryption share

Flow per connection: TCP connect -> signed ECDH handshake (handshake.py) ->
AES-256-GCM channel (channel.py) -> registration (first time) -> login ->
signed requests -> bye. Any failure closes the connection.

Wire messages after the handshake (all inside the encrypted channel):

    register        {"type": "register", "X_M": hex, "sig": hex128}
                    sig over ["register", GROUP, name, X_M_hex]
                 <- {"type": "register-result", "ok": bool, "status"?: str, "error"?: str}
    interactive     {"type": "login", "mode": "interactive", "R": hex}
                 <- {"type": "challenge", "e": hex}
                    {"type": "login-response", "z": hex}
                 <- {"type": "login-result", "ok": bool, "last_seq"?: int}
    non-interactive {"type": "login", "mode": "noninteractive"}
                 <- {"type": "login-nonce", "nonce": hex-string}
                    {"type": "login-proof", "R": hex, "z": hex}
                 <- {"type": "login-result", "ok": bool, "last_seq"?: int}
    request         {"type": "request", "request": {op, seq, body, name, sig}}
                 <- {"type": "request-result", "ok": bool, "seq": int, "error"?: str}
    bye             {"type": "bye"}

Milestone 2 (``--open``): the decryption share travels as a signed request
    op "open-share", body {"generation": str, "c1": hex512,
                           "index": int, "d": hex512,
                           "proof": {"T1": hex512, "T2": hex512, "e": hex512, "z": hex512}}
Before sending, the member verifies the founder-signed public vault data and
its own share against the commitments (opening.load_public_vault /
load_member_share). The share s_i itself is never sent or logged.

Integers (X_M, R, e, z) are lowercase hex without "0x"; the non-interactive
nonce is passed to login.py verbatim as the hex string the server sent.
"""
import argparse
import json
import os
import socket
import sys
from contextlib import closing
from dataclasses import dataclass
from pathlib import Path

from .channel import ChannelError, SecureChannel, recv_secure, send_secure
from .config import (DATA_DIR, GROUP, HOST, MEMBER_NAMES, SERVER_PORT,
                     SOCKET_TIMEOUT_SECONDS, WEAKNESS_NAMES, validate_group)
from .crypto_utils import (generate_p256_keypair, load_private_key, load_public_key,
                           public_key_pem, save_private_key, sign_raw)
from .encoding import canonical_json
from .framing import ProtocolError
from .group import G, P, Q, random_exponent
from .logging_utils import get_logger
from .login import make_noninteractive_response, register_login_secret
from .opening import (OpeningError, load_member_share, load_public_vault,
                      make_decryption_share, public_share_key)
from .requests import sign_request
from .sharing import hex_element

LOGIN_MODES = ("interactive", "noninteractive")


class MemberError(Exception):
    """The server refused a step or answered with an unexpected message."""


# -- file locations -------------------------------------------------------------
def member_dir(name: str) -> Path:
    return DATA_DIR / name


def private_key_path(name: str) -> Path:
    return member_dir(name) / "private.pem"


def login_secret_path(name: str) -> Path:
    return member_dir(name) / "login_secret.json"


def state_path(name: str) -> Path:
    return member_dir(name) / "state.json"


def request_path(name: str) -> Path:
    return DATA_DIR / "requests" / f"{name}.json"


def certificate_path(name: str) -> Path:
    return DATA_DIR / "certs" / f"{name}.json"


def founder_public_path() -> Path:
    return DATA_DIR / "founder.pub"


def _write_private_json(path: Path, value: dict) -> None:
    """Atomic write with owner-only permissions (POSIX) for private member files."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if os.name != "nt":
        os.chmod(tmp, 0o600)
    os.replace(tmp, path)


# -- identity setup (--init) ----------------------------------------------------
def init_identity(name: str, log, force: bool = False) -> None:
    """Create this member's own P-256 key and public request, plus its login secret.

    The private key and x_M stay in runtime/data/<name>/; only the public key is
    written to runtime/data/requests/<name>.json for the founder.
    """
    key_file = private_key_path(name)
    if key_file.exists() and not force:
        private_key = load_private_key(key_file)
        log.info("identity key for %s already exists; reusing it (use --force to replace)", name)
    else:
        private_key, _ = generate_p256_keypair()
        save_private_key(key_file, private_key)
        log.info("identity key for %s created in %s", name, key_file)

    req_file = request_path(name)
    req_file.parent.mkdir(parents=True, exist_ok=True)
    req_file.write_text(json.dumps({"name": name, "public_key": public_key_pem(private_key)},
                                   indent=2) + "\n", encoding="utf-8")
    log.info("public-key request written to %s", req_file)

    if force or not login_secret_path(name).exists():
        _new_login_secret(name)
        if state_path(name).exists():
            state_path(name).unlink()
        log.info("login secret for %s created (kept private, never sent)", name)


def _new_login_secret(name: str) -> dict:
    x_M, X_M = register_login_secret(name, P, Q, G)
    record = {"x_M": format(x_M, "x"), "X_M": format(X_M, "x"), "registered": False}
    _write_private_json(login_secret_path(name), record)
    return record


# -- loading what a member needs to connect -------------------------------------
@dataclass
class MemberIdentity:
    name: str
    private_key: object
    certificate: dict
    founder_public_key: object
    x_M: int
    X_M: int
    registered: bool


def load_identity(name: str) -> MemberIdentity:
    for path, hint in ((private_key_path(name), f"python -m treasury.member --name {name} --init"),
                       (certificate_path(name), "python -m treasury.founder --init --sign-certs"),
                       (founder_public_path(), "python -m treasury.founder --init --sign-certs")):
        if not path.exists():
            raise MemberError(f"missing {path}; run: {hint}")
    secret_file = login_secret_path(name)
    record = (json.loads(secret_file.read_text(encoding="utf-8"))
              if secret_file.exists() else _new_login_secret(name))
    x_M, X_M = int(record["x_M"], 16), int(record["X_M"], 16)
    if not (0 < x_M < Q and pow(G, x_M, P) == X_M):
        raise MemberError(f"corrupted login secret file {secret_file}")
    return MemberIdentity(
        name=name,
        private_key=load_private_key(private_key_path(name)),
        certificate=json.loads(certificate_path(name).read_text(encoding="utf-8")),
        founder_public_key=load_public_key(founder_public_path().read_text(encoding="ascii")),
        x_M=x_M,
        X_M=X_M,
        registered=bool(record.get("registered")),
    )


def mark_registered(name: str) -> None:
    record = json.loads(login_secret_path(name).read_text(encoding="utf-8"))
    record["registered"] = True
    _write_private_json(login_secret_path(name), record)


def load_last_seq(name: str) -> int:
    try:
        return int(json.loads(state_path(name).read_text(encoding="utf-8"))["last_seq"])
    except (FileNotFoundError, KeyError, ValueError, TypeError):
        return 0


def save_last_seq(name: str, seq: int) -> None:
    _write_private_json(state_path(name), {"last_seq": seq})


# -- protocol steps (inside the encrypted channel) -------------------------------
def _expect(message, expected_type: str) -> dict:
    if message is None:
        raise MemberError(f"server closed the connection while waiting for {expected_type!r}")
    if not isinstance(message, dict):
        raise MemberError(f"malformed reply while waiting for {expected_type!r}")
    if message.get("type") != expected_type:
        detail = message.get("error") or message.get("type")
        raise MemberError(f"expected {expected_type!r}, got {detail!r}")
    return message


def _hex_int(message: dict, field: str) -> int:
    value = message.get(field)
    if not isinstance(value, str) or not value:
        raise MemberError(f"field {field!r} must be a hex string")
    try:
        return int(value, 16)
    except ValueError as exc:
        raise MemberError(f"field {field!r} is not valid hex") from exc


def registration_transcript(name: str, X_M_hex: str) -> list:
    return ["register", GROUP, name, X_M_hex]


def register(sock, channel, identity: MemberIdentity, log) -> None:
    X_M_hex = format(identity.X_M, "x")
    sig = sign_raw(identity.private_key, canonical_json(registration_transcript(identity.name, X_M_hex)))
    send_secure(sock, channel, {"type": "register", "X_M": X_M_hex, "sig": sig})
    reply = _expect(recv_secure(sock, channel), "register-result")
    if not reply.get("ok"):
        raise MemberError(f"registration refused: {reply.get('error', 'no reason given')}")
    identity.registered = True
    log.info("registration %s: %s", identity.name, reply.get("status", "ok"))


def login_interactive(sock, channel, identity: MemberIdentity, log) -> dict:
    # Commit to a fresh k *before* seeing the challenge, then answer it.
    k = random_exponent(Q)
    R = pow(G, k, P)
    send_secure(sock, channel, {"type": "login", "mode": "interactive", "R": format(R, "x")})
    e = _hex_int(_expect(recv_secure(sock, channel), "challenge"), "e")
    z = (k + e * identity.x_M) % Q
    del k
    send_secure(sock, channel, {"type": "login-response", "z": format(z, "x")})
    result = _expect(recv_secure(sock, channel), "login-result")
    if not result.get("ok"):
        raise MemberError(f"interactive login refused: {result.get('error', 'no reason given')}")
    log.info("login %s OK (interactive)", identity.name)
    return result


def login_noninteractive(sock, channel, identity: MemberIdentity, log) -> dict:
    send_secure(sock, channel, {"type": "login", "mode": "noninteractive"})
    nonce = _expect(recv_secure(sock, channel), "login-nonce").get("nonce")
    if not isinstance(nonce, str) or not nonce:
        raise MemberError("server sent an invalid login nonce")
    R, z = make_noninteractive_response(identity.x_M, identity.name, nonce)
    send_secure(sock, channel, {"type": "login-proof", "R": format(R, "x"), "z": format(z, "x")})
    result = _expect(recv_secure(sock, channel), "login-result")
    if not result.get("ok"):
        raise MemberError(f"non-interactive login refused: {result.get('error', 'no reason given')}")
    log.info("login %s OK (non-interactive, nonce %s...)", identity.name, nonce[:8])
    return result


def send_request(sock, channel, identity: MemberIdentity, seq: int, op: str, body: dict, log) -> dict:
    request = sign_request(identity.private_key, GROUP, identity.name, seq, op, body)
    send_secure(sock, channel, {"type": "request", "request": request})
    reply = _expect(recv_secure(sock, channel), "request-result")
    if not reply.get("ok"):
        raise MemberError(f"request seq={seq} refused: {reply.get('error', 'no reason given')}")
    shown = body if op != OPEN_OP else {"generation": body.get("generation"), "index": body.get("index")}
    log.info("request seq=%d op=%s body=%s accepted", seq, op, json.dumps(shown, sort_keys=True))
    extras = {k: v for k, v in reply.items() if k not in ("type", "ok", "seq")}
    if extras:
        log.info("server reply: %s", json.dumps(extras, sort_keys=True))
    return reply


# -- Milestone 2: decryption share for threshold opening ----------------------------
OPEN_OP = "open-share"


def build_open_share_body(identity: MemberIdentity, c1: int | None = None, log=None) -> dict:
    """Check the public vault and this member's share, then build the open-share body.

    ``c1`` defaults to the vault ciphertext; Milestone 3 passes the aggregated
    ballot's c1 instead. Only d_i and its proof leave the member, never s_i.
    """
    vault = load_public_vault(identity.founder_public_key, DATA_DIR)
    s_i = load_member_share(identity.name, vault, DATA_DIR)
    index = int(identity.name[1:])
    target = vault.c1 if c1 is None else c1
    h_i = public_share_key(index, vault.commitments)
    share = make_decryption_share(s_i, index, target, h_i)
    del s_i
    if log:
        log.info("%s share for %s verified against the signed commitments; "
                 "decryption share with proof ready", identity.name, vault.generation)
    return {"generation": vault.generation, "c1": hex_element(target),
            **share.to_dict()}


def run_session(sock, identity: MemberIdentity, log, *, handshake, login_mode: str = "interactive",
                requests: list[tuple[str, dict]] = (), weak: set[str] = frozenset(),
                force_register: bool = False) -> list[dict]:
    """Run one full member session on an already-connected socket.

    ``handshake`` is ``handshake.client_handshake`` (injected so tests can use a
    stand-in). Returns the server's request-result replies.
    """
    if login_mode not in LOGIN_MODES:
        raise ValueError(f"login_mode must be one of {LOGIN_MODES}")
    session = handshake(sock, identity.certificate, identity.private_key,
                        identity.founder_public_key, identity.name, set(weak))
    if session.member_name != identity.name:
        raise MemberError("handshake returned a session for a different member")
    channel = None
    try:
        if "no-encryption" in weak:
            log.warning("WEAK no-encryption: frames after the handshake are sent in clear")
        else:
            channel = SecureChannel.from_session(session, "member")
            log.info("secure channel established with server (AES-256-GCM, counters from 0)")

        if force_register or not identity.registered:
            register(sock, channel, identity, log)
            mark_registered(identity.name)

        login = login_interactive if login_mode == "interactive" else login_noninteractive
        result = login(sock, channel, identity, log)

        last_seq = load_last_seq(identity.name)
        server_seq = result.get("last_seq")
        if type(server_seq) is int and server_seq > last_seq:
            last_seq = server_seq
        replies = []
        for op, body in requests:
            last_seq += 1
            replies.append(send_request(sock, channel, identity, last_seq, op, body, log))
            save_last_seq(identity.name, last_seq)

        send_secure(sock, channel, {"type": "bye"})
        return replies
    finally:
        # Forget this connection's session secrets (the ephemeral x is erased in handshake.py).
        if channel is not None:
            channel.close()
        for attr in ("shared_secret",):
            if hasattr(session, attr):
                try:
                    setattr(session, attr, b"")
                except AttributeError:
                    pass


def connect_and_run(args, identity: MemberIdentity, log, login_mode: str) -> None:
    from .handshake import client_handshake  # Member 2's module

    if args.open:
        requests = [(OPEN_OP, build_open_share_body(identity, log=log))]
    else:
        requests = [] if args.op == "none" else [(args.op, args.body)] * args.count
    log.info("connecting to %s:%d as %s", args.host, args.port, identity.name)
    with closing(socket.create_connection((args.host, args.port), timeout=SOCKET_TIMEOUT_SECONDS)) as sock:
        run_session(sock, identity, log, handshake=client_handshake, login_mode=login_mode,
                    requests=requests, weak=args.weak, force_register=args.register)
    log.info("session closed")


# -- command line -----------------------------------------------------------------
def _parse_body(text: str) -> dict:
    try:
        body = json.loads(text)
    except json.JSONDecodeError as exc:
        raise argparse.ArgumentTypeError(f"--body must be JSON: {exc}") from exc
    if not isinstance(body, dict):
        raise argparse.ArgumentTypeError("--body must be a JSON object")
    return body


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Treasury member program")
    parser.add_argument("--name", default="M1", choices=MEMBER_NAMES)
    parser.add_argument("--host", default=HOST)
    parser.add_argument("--port", type=int, default=SERVER_PORT,
                        help="server port (use 6000 to go through Mallory for A1)")
    parser.add_argument("--weak", action="append", default=[], choices=sorted(WEAKNESS_NAMES),
                        help="deliberate weakness for an attack demo; repeatable")
    parser.add_argument("--init", action="store_true",
                        help="create this member's identity key, public request and login secret")
    parser.add_argument("--force", action="store_true", help="with --init: replace existing keys")
    parser.add_argument("--login", choices=LOGIN_MODES + ("both",), default="interactive")
    parser.add_argument("--register", action="store_true",
                        help="send the registration again even if it was already done")
    parser.add_argument("--op", default="spend", help='request op, or "none" to send no request')
    parser.add_argument("--body", type=_parse_body, default={"amount": 50, "reason": "pizza"},
                        help="request body as a JSON object")
    parser.add_argument("--count", type=int, default=1, help="number of requests per session")
    parser.add_argument("--open", action="store_true",
                        help="M2: send this member's verified decryption share for the vault")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    args.weak = set(args.weak)
    validate_group()
    log = get_logger(args.name)
    for weakness in sorted(args.weak):
        log.warning("weakness requested: %s", weakness)

    if args.init:
        init_identity(args.name, log, force=args.force)
        return 0

    try:
        identity = load_identity(args.name)
        modes = LOGIN_MODES if args.login == "both" else (args.login,)
        for mode in modes:
            connect_and_run(args, identity, log, mode)
    except (MemberError, OpeningError, ChannelError, ProtocolError, ConnectionError, OSError,
            ValueError) as exc:
        log.error("connection closed: %s", exc)
        return 1
    except Exception as exc:  # e.g. a handshake/certificate failure raised by handshake.py
        log.error("connection closed: %s: %s", type(exc).__name__, exc)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
