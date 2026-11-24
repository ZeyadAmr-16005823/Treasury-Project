# Milestone 1 — shared interface contract

Draft owner: Member 1 (Zeyad). All four members review and approve; Member 1 merges the final version.
This document freezes function names, data formats and file locations **before** parallel implementation.
Anything not listed here is an internal detail of the owning module.

## 1. Global rules

- `GROUP` is imported from `treasury.config` — never copied into another module. It appears in every
  certificate, hash, key derivation and signed transcript.
- Canonical bytes for anything signed or hashed: `canonical_json(value)` from `treasury.encoding`
  (= `json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")`).
- Project hash: `H(label, *values, q=q)` from `treasury.encoding`; it already prefixes `ICS505` and `GROUP`.
- ECDSA signatures are stored/transmitted as **raw `r || s`, each exactly 32 bytes big-endian**,
  hex-encoded: **64 bytes / 128 lowercase hex characters**. Convert with DER helpers in `crypto_utils`.
- All secret randomness uses `secrets`, never `random`. Private material is never logged.
- Each program reads only its own private files. Public files (`founder.pub`, `certs/*`) are shared.

## 2. File layout (relative to repository root)

```
runtime/data/
  founder/founder_private.pem   # CA key, founder only
  founder.pub                   # founder's public key, everyone
  requests/<name>.json          # {"name": str, "public_key": PEM}, written by each program --init
  certs/<name>.json             # signed certificate dict, public
  <name>/private.pem            # P-256 identity key, that program only
  server/registrations.json     # first registered X_M per name; see §8
runtime/logs/<program>.log      # via logging_utils.get_logger
```

`<name>` is `server` or `M1`…`M5` (`config.PROGRAM_NAMES`).

### Public-key request workflow (identity setup)

| Step | Owner | Generates / writes |
|---|---|---|
| 1 | Member 2 — `server --init` | `runtime/data/server/private.pem` and `runtime/data/requests/server.json` |
| 2 | Member 3 — `member --init` | `runtime/data/M1…M5/private.pem` and `runtime/data/requests/M1…M5.json` |
| 3 | Member 1 — `founder --init --sign-certs` | Reads the six public requests and writes `runtime/data/certs/<name>.json` |

Each request file has exactly this shape:
```json
{"name": "M1", "public_key": "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----\n"}
```
The public key is a P-256 key in PEM (`SubjectPublicKeyInfo`) form. **The private key stays in the
owning program's own directory and is never sent to or read by the founder.** `founder.py` reads
only the six public request files and its own CA private key. Use the helpers in `crypto_utils.py`
(`generate_p256_keypair`, `save_private_key`, `public_key_pem`) to produce these files.

Normal setup requires all six requests; `--allow-partial` is test-only. Issuance validates every
request first, then stages and activates the complete certificate set, so a failure never leaves a
partially issued or stale certificate directory.

## 3. `config.py` — Member 1

```python
GROUP: str                  # "16005823-16006499-16009599-17005797"
CERT_EXPIRY: str            # "2030-12-31", ISO date
HOST: str; SERVER_PORT: int; MALLORY_PORT: int
MAX_FRAME_BYTES: int; SOCKET_TIMEOUT_SECONDS: int
LOG_DIR: Path; DATA_DIR: Path
DEFAULT_T: int; DEFAULT_N: int; MEMBER_NAMES: tuple; PROGRAM_NAMES: tuple
WEAKNESS_NAMES: set[str]    # includes "no-encryption" for 1_plain.pcapng only
validate_group() -> None
```

## 4. `group.py` — Member 4 (new)

```python
P: int                          # RFC 3526 group 14, 2048-bit MODP prime
Q: int                          # (P - 1) // 2
G: int                          # 4
is_valid_element(u: int) -> bool  # 1 < u < P and pow(u, Q, P) == 1
```
No other module may duplicate these constants or the validation check.

## 5. `crypto_utils.py` — Member 1 (new)

```python
generate_p256_keypair() -> tuple[ec.EllipticCurvePrivateKey, str]
public_key_pem(key) -> str                       # PEM, SubjectPublicKeyInfo
save_private_key(path, key) -> None              # parents created, restricted permissions
load_private_key(path) -> ec.EllipticCurvePrivateKey
load_public_key(pem_or_bytes) -> ec.EllipticCurvePublicKey
sign_raw(private_key, data: bytes) -> str        # 128 hex chars
verify_raw(public_key, data: bytes, sig_hex: str) -> bool
```
`verify_raw` rejects anything that is not exactly 128 hex characters. No protocol logic here.

## 6. `certificates.py` — Member 1

Certificate dict (starter dataclass, unchanged):
```python
{"group": GROUP, "name": name, "public_key": PEM, "expires": YYYY-MM-DD, "sig": hex128}
```
```python
create_certificate(founder_private_key, name: str, public_key_pem: str, expires: str) -> Certificate
verify_certificate(certificate: dict, founder_public_key, expected_name: str) -> bool
```
`create_certificate` signs `canonical_json(unsigned_fields())`. `verify_certificate` checks the strict
field set, `group == GROUP`, `name == expected_name`, expiry not in the past, and the founder signature.

## 7. `requests.py` — Member 1

```python
request_transcript(group, name, seq, op, body) -> list   # ["request", group, name, seq, op, body]
sign_request(private_key, group, name, seq, op, body) -> dict
verify_request(public_key, request: dict, last_sequence: int) -> bool
```
Request dict: `{"op": str, "seq": int, "body": dict, "name": str, "sig": hex128}`.
The `name` is **signed** and must equal the session's certified identity (server-side check by Member 2).
`verify_request` requires `type(seq) is int`, `seq > last_sequence`, and a valid signature over
`canonical_json(request_transcript(GROUP, name, seq, op, body))`.

## 8. `handshake.py` — Member 2 (new, extracted from `channel.py`)

```python
client_handshake(sock, cert: dict, private_key, founder_pub, name: str, weak: set[str]) -> SessionContext
server_handshake(conn, cert: dict, private_key, founder_pub, name: str, weak: set[str]) -> SessionContext
hs_server_transcript(name, X_hex, Y_hex) -> list   # ["hs-server", GROUP, name, X_hex, Y_hex]
hs_member_transcript(name, X_hex, Y_hex) -> list   # ["hs-member", GROUP, name, X_hex, Y_hex]
build_handshake_transcript(name, X_hex, Y_hex) -> list  # ["hs", GROUP, name, X_hex, Y_hex]
```
`SessionContext` carries `shared_secret: bytes`, `member_name: str`, `X_hex: str`, `Y_hex: str`.
`build_handshake_transcript()` remains importable from `channel.py` as a backward-compatible wrapper.
Weak mode `unsigned-handshake` omits **both** handshake signatures; certificate verification,
AES-GCM and signed-request verification stay enabled.

## 9. `channel.py` — Member 3

```python
derive_directional_keys(shared_secret: bytes, member_name: str,
                        X_hex: str, Y_hex: str) -> tuple[bytes, bytes]
class SecureChannel:
    def __init__(self, send_key: bytes, receive_key: bytes): ...
    def encrypt(self, plaintext: bytes) -> bytes: ...   # 12-byte counter nonce || ciphertext+tag
    def decrypt(self, frame: bytes) -> bytes: ...       # strict next counter, reject on failure
```
HKDF-SHA256, no salt, info = `b"ICS505|" + GROUP.encode() + b"|channel|" + sha256(canonical_json(build_handshake_transcript(...))).digest()`;
64 bytes → first 32 member→server, last 32 server→member. Counters start at 0 per direction.

## 10. `login.py` — Member 4

Actual public API (do not change without team agreement):

```python
register_login_secret(name, p, q, g) -> tuple[int, int]                     # (x_M, X_M)
make_interactive_response(x_M, challenge, q) -> tuple[int, int]             # (R, z)
verify_interactive_login(R, z, e, X_M, p, q, g) -> bool
make_noninteractive_response(x_M, name, nonce, p=P, q=Q, g=G) -> tuple[int, int]  # (R, z)
verify_noninteractive_login(name, R, z, nonce, X_M, p=P, q=Q, g=G) -> bool
```

Interactive login: `R = g^k mod p`, `z = k + e·x_M mod q`; the server accepts when
`g^z = R · X_M^e mod p`. `R` and `X_M` must pass `group.is_valid_element`. The
`source=` argument of `generate_challenge()` allows deterministic tests.

Non-interactive transcript, exactly as specified in Milestone 1:

```
e = H("login", name, X_M, R, nonce, q=q)
z = k + e * x_M mod q
```

- `q=q` is `H`'s modulus/output-range parameter, **not** a value in the transcript.
- `X_M` and `R` are integers; `H` encodes them with `format(v, "x")`.
- `nonce` is a **lowercase hex string** produced by `secrets.token_bytes(16).hex()`, preserved
  verbatim on both sides. Passing the equivalent integer instead produces a different challenge.
- The verifier takes `name` from the certified session identity, not from the proof message.

Responsibilities: `login.py` calculates the challenge and verifies the mathematics only; it does
not track used nonces. `server.py` (Member 2) issues fresh nonces, checks that each nonce was issued
for that member/session, consumes it atomically, and rejects reuse.

Registration is signed by the member over `["register", GROUP, name, X_M_hex]` using
`crypto_utils.sign_raw`; the server persists the first `X_M` per certified name in
`server/registrations.json` with a lock and atomic write.

## 11. Server/member integration — Members 2 / 3

`server.py` (Member 2) calls exported functions from `certificates.py`, `requests.py`, `login.py`,
`opening.py`, `voting.py` — it never copies their logic. `member.py` (Member 3) owns the client flow
connect → handshake → channel → registration/login → signed requests.

## 12. Forward contracts for later weeks

- `sharing.py` (M2, Member 1): Shamir polynomial, shares, commitments, encrypted vault.
- `opening.py` (M2, Member 3, keep starter file intact): member-side share + proof creation **and**
  exported verification/combining helpers called by Member 2 from `server.py`. Must accept arbitrary
  `(C1, C2)` pairs so M3 can reuse threshold decryption for the aggregate ballot. Proofs bind to the
  supplied `C1` via `H("dec", i, c1, h_i, d_i, T1, T2)`.
- `voting.py` (M3, Member 3): keep `encrypt_vote`, `ballot_transcript`, `verify_ballot`; no `ballots.py`.
- Attacks: A1 → Member 2, A3 → Member 4, A5 → Member 4 (attack) / Member 2 (server weak mode) /
  Member 3 (honest proof path). A7 is out of scope unless the TA confirms it is additionally required.
