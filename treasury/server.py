"""Treasury server (Member 2): signed handshake, secure channel, login and requests.

Setup (once, before the founder signs certificates):

    python -m treasury.server --init

Normal run / attack demos:

    python -m treasury.server
    python -m treasury.server --weak unsigned-handshake     # A1 (with Mallory on 6000)
    python -m treasury.server --weak short-challenge        # A3 (4-bit login challenge)
    python -m treasury.server --weak no-encryption          # plain capture only

Each connection runs in its own thread:

    TCP accept -> server_handshake (handshake.py) -> SecureChannel (channel.py)
    -> register / login / signed requests (dispatch loop) -> bye

Protocol logic is never copied here: certificates, login proofs, requests and
channel framing come from the owning modules. Any protocol failure is answered
with ``ok: false`` (when the peer can still read it) and closes the connection.

Server-side state in ``runtime/data/server/`` (lock + temp file + os.replace):

    private.pem          server identity key (never logged, never shared)
    registrations.json   {member: X_M hex}  - the first X_M per certified name
    sequences.json       {member: last accepted request seq}  - survives restarts
"""
import argparse
import json
import os
import secrets
import socket
import sys
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from .certificates import verify_certificate
from .channel import ChannelError, SecureChannel, recv_secure, send_secure
from .config import (DATA_DIR, GROUP, HOST, SERVER_PORT, SOCKET_TIMEOUT_SECONDS,
                     WEAKNESS_NAMES, validate_group)
from .crypto_utils import (generate_p256_keypair, load_private_key, load_public_key,
                           public_key_pem, save_private_key, verify_raw)
from .encoding import canonical_json
from .framing import ProtocolError
from .group import G, P, Q, is_valid_element
from .handshake import HandshakeError, SessionContext, server_handshake
from .logging_utils import get_logger
from .login import (generate_challenge, verify_interactive_login,
                    verify_noninteractive_login)
from .requests import verify_request

SERVER_NAME = "server"
MAX_HEX_CHARS = 2048  # generous bound for 2048-bit group elements
_HEX = frozenset("0123456789abcdef")


class SessionClosed(Exception):
    """Raised by a handler to end the session after its reply was sent."""


# -- file locations ----------------------------------------------------------------
@dataclass
class ServerPaths:
    data_dir: Path = DATA_DIR

    @property
    def server_dir(self) -> Path:
        return self.data_dir / SERVER_NAME

    @property
    def private_key(self) -> Path:
        return self.server_dir / "private.pem"

    @property
    def registrations(self) -> Path:
        return self.server_dir / "registrations.json"

    @property
    def sequences(self) -> Path:
        return self.server_dir / "sequences.json"

    @property
    def request(self) -> Path:
        return self.data_dir / "requests" / f"{SERVER_NAME}.json"

    @property
    def certificate(self) -> Path:
        return self.data_dir / "certs" / f"{SERVER_NAME}.json"

    @property
    def founder_public(self) -> Path:
        return self.data_dir / "founder.pub"


# -- persistent JSON state (lock + atomic replace) -----------------------------------
class JsonStore:
    """A small {str: value} JSON file guarded by a lock and replaced atomically.

    Readers never see a half-written file: every write goes to a temporary file
    in the same directory and is moved into place with ``os.replace``.
    """

    def __init__(self, path: Path):
        self.path = Path(path)
        self.lock = threading.RLock()

    def _read(self) -> dict:
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            return {}
        if not isinstance(data, dict):
            raise ValueError(f"{self.path} does not contain a JSON object")
        return data

    def _write(self, data: dict) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_name(f"{self.path.name}.{os.getpid()}.{threading.get_ident()}.tmp")
        tmp.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        os.replace(tmp, self.path)

    def get(self, key: str, default=None):
        with self.lock:
            return self._read().get(key, default)

    def snapshot(self) -> dict:
        with self.lock:
            return dict(self._read())

    def update(self, fn: Callable[[dict], object]):
        """Run ``fn(data)`` under the lock; persist the (mutated) data atomically."""
        with self.lock:
            data = self._read()
            result = fn(data)
            self._write(data)
            return result


class RegistrationStore(JsonStore):
    def register_first(self, name: str, X_M_hex: str) -> str:
        """Persist the first X_M for ``name``. Returns "registered" or "already-registered".

        Raises ValueError if a *different* X_M is already registered for the name.
        """
        def apply(data: dict) -> str:
            existing = data.get(name)
            if existing is None:
                data[name] = X_M_hex
                return "registered"
            if existing == X_M_hex:
                return "already-registered"
            raise ValueError("a different login key is already registered for this member")
        return self.update(apply)

    def login_key(self, name: str) -> int | None:
        value = self.get(name)
        return int(value, 16) if isinstance(value, str) else None


class SequenceStore(JsonStore):
    def last(self, name: str) -> int:
        value = self.get(name, 0)
        return value if type(value) is int else 0

    def accept(self, name: str, check: Callable[[int], bool], seq: int) -> bool:
        """Atomically: verify against the current last seq, then advance it.

        Holding the lock across check-and-set stops two concurrent sessions of
        the same member from both accepting the same sequence number.
        """
        with self.lock:
            data = self._read()
            last = data.get(name, 0)
            last = last if type(last) is int else 0
            if not check(last):
                return False
            data[name] = seq
            self._write(data)
            return True


# -- server identity -----------------------------------------------------------------
def init_identity(paths: ServerPaths, log, force: bool = False) -> None:
    """Create the server's own P-256 key and public-key request for the founder."""
    if paths.private_key.exists() and not force:
        private_key = load_private_key(paths.private_key)
        log.info("server identity key already exists; reusing it (use --force to replace)")
    else:
        private_key, _ = generate_p256_keypair()
        save_private_key(paths.private_key, private_key)
        log.info("server identity key created in %s", paths.private_key)
    paths.request.parent.mkdir(parents=True, exist_ok=True)
    paths.request.write_text(json.dumps({"name": SERVER_NAME,
                                         "public_key": public_key_pem(private_key)},
                                        indent=2) + "\n", encoding="utf-8")
    log.info("public-key request written to %s", paths.request)


@dataclass
class ServerIdentity:
    private_key: object
    certificate: dict
    founder_public_key: object


def load_identity(paths: ServerPaths) -> ServerIdentity:
    for path, hint in ((paths.private_key, "python -m treasury.server --init"),
                       (paths.certificate, "python -m treasury.founder --init --sign-certs"),
                       (paths.founder_public, "python -m treasury.founder --init --sign-certs")):
        if not path.exists():
            raise RuntimeError(f"missing {path}; run: {hint}")
    private_key = load_private_key(paths.private_key)
    certificate = json.loads(paths.certificate.read_text(encoding="utf-8"))
    founder_public_key = load_public_key(paths.founder_public.read_text(encoding="ascii"))
    if not verify_certificate(certificate, founder_public_key, SERVER_NAME):
        raise RuntimeError("the server certificate does not verify under founder.pub")
    if load_public_key(certificate["public_key"]).public_numbers() != private_key.public_key().public_numbers():
        raise RuntimeError("the server certificate does not match server/private.pem")
    return ServerIdentity(private_key, certificate, founder_public_key)


# -- helpers ---------------------------------------------------------------------------
def parse_hex_int(value) -> int:
    """Strict canonical lowercase hex (no 0x, no leading zeros) -> int."""
    if (not isinstance(value, str) or not value or len(value) > MAX_HEX_CHARS
            or any(c not in _HEX for c in value)):
        raise ValueError("expected a lowercase hex integer")
    number = int(value, 16)
    if format(number, "x") != value:
        raise ValueError("hex integer must not have leading zeros")
    return number


def registration_transcript(name: str, X_M_hex: str) -> list:
    return ["register", GROUP, name, X_M_hex]


def default_request_handler(name: str, request: dict, log) -> dict:
    """Milestone 1: accept and record the signed request. M2/M3 add their own ops."""
    log.info("ACCEPTED request from %s: seq=%d op=%s body=%s", name, request["seq"],
             request["op"], json.dumps(request["body"], sort_keys=True))
    return {}


# -- one connection ----------------------------------------------------------------------
@dataclass
class Session:
    sock: socket.socket
    context: SessionContext
    channel: SecureChannel | None
    logged_in: bool = False
    pending_nonce: str | None = None
    pending_challenge: tuple[int, int] | None = None  # (R, e) awaiting login-response
    extra: dict = field(default_factory=dict)

    @property
    def name(self) -> str:
        return self.context.member_name

    def send(self, message: dict) -> None:
        send_secure(self.sock, self.channel, message)

    def recv(self):
        return recv_secure(self.sock, self.channel)


class TreasuryServer:
    """Threaded TCP server running the Milestone 1 protocol for each member."""

    def __init__(self, identity: ServerIdentity, paths: ServerPaths, log,
                 weak: set[str] | None = None, host: str = HOST, port: int = SERVER_PORT,
                 request_handlers: dict | None = None):
        self.identity = identity
        self.paths = paths
        self.log = log
        self.weak = set(weak or ())
        self.host, self.port = host, port
        self.registrations = RegistrationStore(paths.registrations)
        self.sequences = SequenceStore(paths.sequences)
        self.request_handlers = dict(request_handlers or {})
        self._issued_nonces: set[str] = set()
        self._nonce_lock = threading.Lock()
        self._listener: socket.socket | None = None
        self._stopping = threading.Event()
        self._threads: list[threading.Thread] = []

    # -- listener ------------------------------------------------------------
    def bind(self) -> tuple[str, int]:
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind((self.host, self.port))
        listener.listen()
        listener.settimeout(0.5)
        self._listener = listener
        self.host, self.port = listener.getsockname()[:2]
        self.log.info("listening on %s:%d (weak: %s)", self.host, self.port,
                      ", ".join(sorted(self.weak)) or "none - secure mode")
        return self.host, self.port

    def serve_forever(self) -> None:
        if self._listener is None:
            self.bind()
        try:
            while not self._stopping.is_set():
                try:
                    conn, address = self._listener.accept()
                except socket.timeout:
                    continue
                except OSError:
                    if self._stopping.is_set():
                        break
                    raise
                thread = threading.Thread(target=self.handle_connection, args=(conn, address),
                                          daemon=True)
                self._threads = [t for t in self._threads if t.is_alive()] + [thread]
                thread.start()
        finally:
            self._listener.close()

    def start_background(self) -> threading.Thread:
        """Bind and serve in a daemon thread (used by tests and the A1 demo)."""
        self.bind()
        thread = threading.Thread(target=self.serve_forever, daemon=True)
        thread.start()
        return thread

    def stop(self) -> None:
        self._stopping.set()
        for thread in list(self._threads):
            thread.join(timeout=2)

    # -- per connection -----------------------------------------------------------
    def handle_connection(self, conn: socket.socket, address) -> None:
        peer = f"{address[0]}:{address[1]}"
        conn.settimeout(SOCKET_TIMEOUT_SECONDS)
        session = None
        try:
            with conn:
                context = server_handshake(conn, self.identity.certificate, self.identity.private_key,
                                           self.identity.founder_public_key, SERVER_NAME, self.weak)
                if context.signed:
                    self.log.info("handshake OK with %s (%s): certificate + signatures verified, X=%s... Y=%s...",
                                  context.member_name, peer, context.X_hex[2:10], context.Y_hex[2:10])
                else:
                    self.log.warning("WEAK unsigned-handshake with %s (%s): handshake signatures NOT checked",
                                     context.member_name, peer)
                if "no-encryption" in self.weak:
                    self.log.warning("WEAK no-encryption: frames to %s are sent in clear", context.member_name)
                    channel = None
                else:
                    channel = SecureChannel.from_session(context, "server")
                context.shared_secret = b""  # keys now live only inside the channel
                session = Session(conn, context, channel)
                self._run_session(session)
        except HandshakeError as exc:
            self.log.warning("handshake REJECTED from %s: %s", peer, exc)
        except ChannelError as exc:
            self.log.warning("channel error from %s, closing: %s",
                             session.name if session else peer, exc)
        except (ProtocolError, ConnectionError, socket.timeout, OSError) as exc:
            self.log.warning("connection %s closed: %s", session.name if session else peer, exc)
        except Exception as exc:  # never let one connection kill the server
            self.log.exception("unexpected error on %s: %s", peer, exc)
        finally:
            if session is not None and session.channel is not None:
                session.channel.close()

    def _run_session(self, session: Session) -> None:
        handlers = {
            "register": self.on_register,
            "login": self.on_login,
            "login-response": self.on_login_response,
            "login-proof": self.on_login_proof,
            "request": self.on_request,
        }
        while True:
            message = session.recv()
            if message is None:
                self.log.info("%s disconnected", session.name)
                return
            if not isinstance(message, dict) or not isinstance(message.get("type"), str):
                session.send({"type": "error", "ok": False, "error": "malformed message"})
                return
            kind = message["type"]
            if kind == "bye":
                self.log.info("%s said bye; session closed", session.name)
                return
            handler = handlers.get(kind)
            if handler is None:
                session.send({"type": "error", "ok": False, "error": f"unsupported message {kind!r}"})
                self.log.warning("%s sent unsupported message %r; closing", session.name, kind)
                return
            try:
                handler(session, message)
            except SessionClosed:
                return

    def _fail(self, session: Session, reply_type: str, error: str, **extra) -> None:
        self.log.warning("REJECTED %s from %s: %s", reply_type, session.name, error)
        session.send({"type": reply_type, "ok": False, "error": error, **extra})
        raise SessionClosed

    # -- registration -----------------------------------------------------------------
    def on_register(self, session: Session, message: dict) -> None:
        X_M_hex, sig = message.get("X_M"), message.get("sig")
        try:
            X_M = parse_hex_int(X_M_hex)
        except ValueError as exc:
            self._fail(session, "register-result", f"invalid X_M: {exc}")
        if not is_valid_element(X_M):
            self._fail(session, "register-result", "X_M is not a valid group element")
        # The name is the certified session identity, never a field of the message.
        transcript = registration_transcript(session.name, X_M_hex)
        if not verify_raw(session.context.peer_public_key, canonical_json(transcript), sig):
            self._fail(session, "register-result", "invalid registration signature")
        try:
            status = self.registrations.register_first(session.name, X_M_hex)
        except ValueError as exc:
            self._fail(session, "register-result", str(exc))
        self.log.info("registration %s: %s (X_M=%s...)", session.name, status, X_M_hex[:8])
        session.send({"type": "register-result", "ok": True, "status": status})

    # -- login -----------------------------------------------------------------------
    def _registered_key(self, session: Session) -> int:
        X_M = self.registrations.login_key(session.name)
        if X_M is None:
            self._fail(session, "login-result", "member is not registered")
        return X_M

    def on_login(self, session: Session, message: dict) -> None:
        mode = message.get("mode")
        self._registered_key(session)
        if mode == "interactive":
            try:
                R = parse_hex_int(message.get("R"))
            except ValueError as exc:
                self._fail(session, "login-result", f"invalid R: {exc}")
            if not is_valid_element(R):
                self._fail(session, "login-result", "R is not a valid group element")
            weak = "short-challenge" in self.weak
            e = generate_challenge(weak=weak)
            if weak:
                self.log.warning("WEAK short-challenge: 4-bit challenge sent to %s", session.name)
            session.pending_challenge = (R, e)
            session.send({"type": "challenge", "e": format(e, "x")})
        elif mode == "noninteractive":
            nonce = secrets.token_bytes(16).hex()
            with self._nonce_lock:
                while nonce in self._issued_nonces:  # practically impossible, but never reuse
                    nonce = secrets.token_bytes(16).hex()
                self._issued_nonces.add(nonce)
            session.pending_nonce = nonce
            session.send({"type": "login-nonce", "nonce": nonce})
        else:
            self._fail(session, "login-result", "unknown login mode")

    def _login_ok(self, session: Session, how: str) -> None:
        session.logged_in = True
        last_seq = self.sequences.last(session.name)
        self.log.info("login %s OK (%s); last accepted seq %d", session.name, how, last_seq)
        session.send({"type": "login-result", "ok": True, "last_seq": last_seq})

    def on_login_response(self, session: Session, message: dict) -> None:
        pending, session.pending_challenge = session.pending_challenge, None
        if pending is None:
            self._fail(session, "login-result", "no outstanding challenge")
        R, e = pending
        try:
            z = parse_hex_int(message.get("z"))
        except ValueError as exc:
            self._fail(session, "login-result", f"invalid z: {exc}")
        if not verify_interactive_login(R, z, e, self._registered_key(session), P, Q, G):
            self._fail(session, "login-result", "interactive proof did not verify")
        self._login_ok(session, "interactive")

    def on_login_proof(self, session: Session, message: dict) -> None:
        # Consume the nonce first: it is valid for exactly one proof on this session.
        nonce, session.pending_nonce = session.pending_nonce, None
        if nonce is None:
            self._fail(session, "login-result", "no outstanding login nonce for this session")
        try:
            R = parse_hex_int(message.get("R"))
            z = parse_hex_int(message.get("z"))
        except ValueError as exc:
            self._fail(session, "login-result", f"invalid proof: {exc}")
        if not verify_noninteractive_login(session.name, R, z, nonce, self._registered_key(session)):
            self._fail(session, "login-result", "non-interactive proof did not verify")
        self._login_ok(session, f"non-interactive, nonce {nonce[:8]}...")

    # -- signed requests -------------------------------------------------------------
    def on_request(self, session: Session, message: dict) -> None:
        request = message.get("request")
        seq = request.get("seq") if isinstance(request, dict) else None
        if not session.logged_in:
            self._fail(session, "request-result", "login required before requests", seq=seq)
        if not isinstance(request, dict) or request.get("name") != session.name:
            self._fail(session, "request-result", "request name does not match the certified session",
                       seq=seq)
        public_key = session.context.peer_public_key
        if not self.sequences.accept(session.name,
                                     lambda last: verify_request(public_key, request, last), seq):
            self._fail(session, "request-result",
                       "invalid request signature or replayed/old sequence number", seq=seq)
        handler = self.request_handlers.get(request["op"], default_request_handler)
        result = handler(session.name, request, self.log) or {}
        session.send({"type": "request-result", "ok": True, "seq": seq, **result})


# -- command line -------------------------------------------------------------------------
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Treasury server")
    parser.add_argument("--name", default=SERVER_NAME)
    parser.add_argument("--host", default=HOST)
    parser.add_argument("--port", type=int, default=SERVER_PORT)
    parser.add_argument("--weak", action="append", default=[], choices=sorted(WEAKNESS_NAMES),
                        help="deliberate weakness for an attack demo; repeatable")
    parser.add_argument("--init", action="store_true",
                        help="create the server identity key and public-key request")
    parser.add_argument("--force", action="store_true", help="with --init: replace the existing key")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    validate_group()
    if args.name != SERVER_NAME:
        print("the server's certified name is always 'server'", file=sys.stderr)
        return 2
    log = get_logger(SERVER_NAME)
    paths = ServerPaths()
    if args.init:
        init_identity(paths, log, force=args.force)
        return 0
    for weakness in sorted(set(args.weak)):
        log.warning("weakness requested: %s", weakness)
    try:
        identity = load_identity(paths)
    except (RuntimeError, ValueError) as exc:
        log.error("cannot start: %s", exc)
        return 1
    server = TreasuryServer(identity, paths, log, weak=set(args.weak), host=args.host, port=args.port)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        log.info("server stopped")
    return 0


if __name__ == "__main__":
    sys.exit(main())
