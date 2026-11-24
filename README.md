# Treasury Project — Student Starter

This is the common starting point for the Treasury Project. It provides a runnable TCP server/client baseline, length-prefixed JSON messaging, configuration, logging, command-line parsing, and shared serialization/hash helpers.

It deliberately does **not** implement the assessed cryptographic protocols. Complete the `TODO` sections in the milestone modules and keep private values in the owning program's files.

## Requirements

- Python 3.10+
- `cryptography`
- `ecdsa` (needed only if you implement optional attack A2)
- Wireshark for the required captures

Install:

```bash
python -m venv .venv
# Windows: .venv\Scripts\activate
# macOS/Linux: source .venv/bin/activate
python -m pip install -r requirements.txt
```

## Before running

1. Set `GROUP` in `config.py` to all group members' student IDs, sorted numerically and joined with `-`.
2. Agree on the same `GROUP` value across every machine/program.
3. Read `docs/IMPLEMENTATION_CHECKLIST.md` and the project Overview/Milestones supplied by the instructor.

## Identity setup (Milestone 1)

1. Initialise each program so it generates **its own** P-256 identity key and writes a **public**
   key request (implemented by Member 2 for `server` and Member 3 for `M1`–`M5`):

   ```bash
   python -m treasury.server --init
   python -m treasury.member --name M1 --init     # repeat for M2 … M5
   ```

   Each request is `runtime/data/requests/<name>.json` with
   `{"name": "M1", "public_key": "<PEM>"}`. The private key stays in
   `runtime/data/<name>/private.pem` — the founder never reads it.

2. Create the founder CA key and sign all six certificates:

   ```bash
   python -m treasury.founder --init --sign-certs
   ```

   This requires all six requests. It fails clearly and writes nothing if any request is missing
   or malformed. Certificates are staged and activated as a complete set, so a failed run cannot
   leave stale certificates that look newly issued.

   `--allow-partial` exists **for tests and demos only**:

   ```bash
   python -m treasury.founder --sign-certs --allow-partial
   ```

   It is **not** the normal team setup procedure and must never be used for the live evaluation.

See `docs/M1_INTERFACES.md` for the full interface and ownership contract.

## Run Milestone 1 (secure channel, login, signed requests)

Terminal 1:

```bash
python -m treasury.server
```

Terminal 2:

```bash
python -m treasury.member --name M1                          # register (first time) + interactive login + one request
python -m treasury.member --name M1 --login noninteractive
python -m treasury.member --name M2 --op spend --body '{"amount": 7}' --count 2
```

Each connection runs: signed ECDH handshake → AES-256-GCM channel → registration → login →
signed requests. The server logs every accepted/rejected step in `runtime/logs/server.log`.

Stop either program with Ctrl+C.

## A1 — unsigned handshake (Mallory MITM)

Three terminals, all with the deliberate weakness:

```bash
python -m treasury.server --weak unsigned-handshake
python -m treasury.mallory --attack A1 --weak unsigned-handshake        # add --tamper modify | replay
python -m treasury.member --name M1 --port 6000 --weak unsigned-handshake
```

Mallory swaps both ephemeral keys and reads every message (registration, login, the signed
request). With `--tamper modify` the server rejects the altered request (ECDSA signature), with
`--tamper replay` it rejects the old sequence number. Run the server and member **without**
`--weak` and the member rejects the handshake (`invalid server handshake signature`).

One-command scripted demo (temporary identities, does not touch `runtime/`):

```bash
python -m attacks.a1_unsigned_handshake
```

## Project layout

```text
treasury/
  config.py          Shared project parameters
  encoding.py        Canonical JSON and project hash H
  logging_utils.py   Consistent console + per-program file logs
  framing.py         4-byte big-endian length-prefixed JSON over TCP
  network.py         Small reusable TCP server/client helpers
  certificates.py    Certificate data model and TODOs
  channel.py         HKDF directional keys + AES-256-GCM frames (Member 3)
  login.py           Milestone 1 proof-of-knowledge login TODOs
  requests.py        Milestone 1 signed request/replay protection TODOs
  sharing.py         Milestone 2 Shamir sharing/commitment TODOs
  opening.py         Milestone 2 verifiable decryption TODOs
  voting.py          Milestone 3 encrypted ballot TODOs
  handshake.py       Signed ephemeral ECDH handshake (Member 2)
  server.py          Threaded secure server: registration, login, signed requests (Member 2)
  member.py          Member client flow (Member 3)
  founder.py         Founder CA setup and certificate issuance (Member 1)
  mallory.py         Attack harness: A1 MITM proxy (Member 2)
attacks/
  a1_unsigned_handshake.py   Scripted A1 demo
  a3_short_challenge.py      A3 short-challenge demo
```

## Important rules

- Use `secrets`, never `random`, for cryptographic randomness.
- Never log private keys, login secrets, Shamir shares, or plaintext vault keys.
- Keep each program's private values in its own data directory. Do not read another program's private files.
- Use `--weak <name>` only when demonstrating the corresponding deliberately weakened implementation. With no `--weak` option, run the secure implementation.
- The default listener is `127.0.0.1:5050`. Mallory's proxy should listen on port `6000` when you implement A1.
- The transport smoke test sends JSON in cleartext. Do not mistake it for the encrypted channel required by Milestone 1.
- Add tests as you implement each protocol. Do not rely only on a successful demo run.

## Weakness names reserved by the specification

| Attack | CLI weakness name | Status |
|---|---|---|
| A1 unsigned handshake | `unsigned-handshake` | Mandatory |
| A2 reused signing nonce | `fixed-nonce` | Optional bonus |
| A3 short login challenge | `short-challenge` | Optional bonus |
| A4 replayed non-interactive login | `no-nonce` | Optional bonus |
| A5 missing decryption proof | `no-proof` | Mandatory |
| A6 missing share check | `no-share-check` | Optional bonus |
| A7 unsigned ballots | `unsigned-ballots` | Optional bonus |

## Tests

```bash
python -m unittest discover -s tests -v
```
