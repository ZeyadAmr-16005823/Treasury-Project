# Milestone 2 — proposed shared interface contract

Owner: Member 1 (Zeyad). This document **proposes** the byte-level contract the founder produces and
how Members 2 and 3 consume it. It is implemented on `feature/m2-founder-sharing` but is **not yet
fully agreed by the team**; see §11. Please review before implementing M2 on any branch.

## 1. Scope and ownership

| Area | Owner |
|---|---|
| `sharing.py` (Shamir, shares, commitments, Lagrange, vault key) | Member 1 |
| Founder vault setup in `founder.py` | Member 1 |
| This document | Member 1 |
| `opening.py`: decryption shares, Chaum-Pedersen proofs, exported verification/combining helpers | Member 3 |
| Server-side proof verification, Lagrange combination, vault opening | Member 2 |
| A5 malicious-member demonstration | Member 4 |
| `group.py` (`P, Q, G`, strict `is_valid_element`) | Member 4 — **do not edit from Member 1** |

Terminology: `C_k = g^{a_k}` are **Feldman-style coefficient commitments**, not Pedersen.
All programs use `group.is_valid_element()` as the single strict group validator. A relaxed
subgroup helper with `allow_identity=True` is **not** part of the contract.

## 2. Group and scalar domains

- `P, Q=(P−1)//2, G=4` come from `treasury.group`; never copy constants.
- Group elements are encoded as **fixed-width 256-byte big-endian → 512 lowercase hex chars**, no `0x`.
- Scalars (`s_i`, `w`, etc.) are encoded as fixed-width 256-byte big-endian hex (512 chars).
- `s`, `u`, `r` are sampled by rejection from `ℤ_q* = {1,…,q−1}`: uniform over `ℤ_q*`, **not** uniform
  over all of `ℤ_q`. This deliberately avoids `h=1`, `c₁=1`, `c₂=m` and `m=1`.
- Polynomial coefficients `a₁…a_{t−1}` are **drawn** from all of `ℤ_q` (zero is a legal draw). The
  founder then applies the rejection rules in §4 before publishing anything.
- Identity is forbidden for every received group element at a protocol boundary: `C_k`, `c₁`, `c₂`,
  `h_i`, `d_i`, `m`, `T₁`, `T₂` must all satisfy `group.is_valid_element()`.

## 3. Validation responsibilities

Strict validator: `group.is_valid_element(u)` → `1 < u < P−1` and `pow(u, Q, P) == 1`.
It rejects 1, `P−1`, values outside `[1, P−1]` and non-subgroup values.

| Element | Rule | Enforced by |
|---|---|---|
| `C₀ = g^s` | strict | `verify_share` + founder candidate check |
| `C₁ … C_{t−1}` | strict — zero coefficient draws are rejected at setup | `verify_share` + founder candidate check |
| `c₁ = g^r` | strict | `vault_key` + founder candidate check |
| `c₂` | strict — `c₂=1` is rejected and the vault regenerated | `vault_key` + founder candidate check |
| `h_i = ∏ C_k^{i^k}` | strict — zero share draws are rejected at setup | founder candidate check; member re-check |
| `d_i = c₁^{s_i}` | strict | Member 3 output / Member 2 input check |
| recovered `m` | strict | `vault_key` + Member 2 check |
| `T₁ = g^w`, `T₂ = c₁^w` | strict — `w ← ℤ_q` but `w = 0` is retried | Member 3 / Member 2 |

**`verify_share()` can only check what its starter signature lets it see.** The signature is
`verify_share(share, member_index, commitments, p, q, g)`; it receives no `n` and no `t`.

| Validation | Responsible code |
|---|---|
| Feldman equation `g^{s_i} = ∏ C_k^{i^k}` | `verify_share()` |
| Share is in the permitted scalar range (`0 < s_i < q`) | `verify_share()` |
| Member index is at least 1 | `verify_share()` |
| Member index does not exceed `n` | **calling program** (founder / Member 2) |
| Number of commitments equals `t` | **calling program** (founder / Member 2) |
| Member index is bound to a certified identity | **member-side program** (Member 3) |

Member 3 must not assume `verify_share()` performs the last three checks. The founder enforces the
first two caller checks explicitly in `setup_vault` (`len(shares) == n`, `len(commitments) == t`),
and Member 2 must repeat them using `t`/`n` from `current.json`.

## 4. Shamir sharing — `sharing.py` (Member 1)

Starter signatures preserved:

```python
evaluate_polynomial(coefficients: list[int], x: int, q: int) -> int
make_shares(secret: int, t: int, n: int, q: int) -> tuple[list[int], list[int]]
verify_share(share: int, member_index: int, commitments: list[int], p: int, q: int, g: int) -> bool
lagrange_coefficient(i: int, selected_indices: list[int], q: int) -> int
```

- Polynomial: `f(x) = a₀ + a₁x + … + a_{t−1}x^{t−1} mod q`, `a₀ = s`. The **sampling rule** draws every
  `a_k` from all of `ℤ_q`, so the primitive is described as degree **at most** `t−1`.
- **Candidate rejection (founder policy, applied before publication):** draw with
  `secrets.randbelow(q)`, compute commitments and shares, then discard and redraw the whole
  candidate if (a) any `C_k = 1` (i.e. `a_k = 0`, including the top coefficient), (b) any share
  `s_i = 0` (which would make `h_i = 1`), (c) `c₁`, `c₂` or `m` is not a strict group element, or
  (d) the vault self-check fails. Consequently every **published** generation has nonzero
  coefficients and exact degree `t−1`, and no identity-valued artifact is ever published.
- The accepted distribution is the original `ℤ_q` sampling **conditioned** on these rejection
  rules; this is stated honestly here rather than silently changing the sampling helper.
- `make_shares` returns `(coefficients, [f(1), …, f(n)])` and never uses `random`.
- `verify_share` validates the index lower bound (`≥1`), strict commitment values and the Feldman
  equation. It deliberately does **not** claim to validate the upper bound `n` or the length `t`.
- `lagrange_coefficient(i, S, q)`: `∏_{j∈S, j≠i} j·(j−i)^{-1} mod q`, 1-based `S`, `i ∈ S`,
  modular inverse via `pow(x, -1, q)`.

Additional exported helpers (new):

```python
random_nonzero_scalar(q: int) -> int
make_commitments(coefficients: list[int], p: int, q: int, g: int) -> list[int]
hex_element(value: int) -> str          # 512 lowercase hex chars
vault_transcript(c1_hex, c2_hex, D_C) -> bytes
vault_aad(c1_hex, c2_hex, D_C) -> bytes
vault_key(m, c1_hex, c2_hex, D_C) -> bytes
```

Strict group validation uses `group.is_valid_element` directly (Member 4's file is not edited).

## 5. Commitments and their signature

```
commitments_bytes = canonical_json(["commitments", GROUP, t, n, C_hexes])  # already bytes
D_C               = sha256(commitments_bytes).hex()                        # 64 lowercase hex
sig               = sign_raw(founder_private_key, commitments_bytes)       # 128 hex chars
```

`commitments.json` lives in the generation's `public/` directory:
```json
{"group": GROUP, "t": t, "n": n, "commitments": ["<512hex>", ...],
 "digest": "<64hex>", "sig": "<128hex>"}
```
The same `commitments_bytes` is used for both the digest and the founder signature. Every
commitment is checked with `is_valid_element` before it is signed or published.

## 6. Vault encryption — byte-level contract

```
h     = C₀
m     = g^u mod p                      (u ≠ 0, m strict)
c₁    = g^r mod p                      (r ≠ 0, c₁ strict)
c₂    = m · h^r mod p                  (strict; c₂ = 1 is rejected and regenerated)
ikm   = m.to_bytes(256, "big")
transcript = canonical_json(["vault", GROUP, c1_hex, c2_hex, D_C])  # already bytes
info  = b"ICS505|" + GROUP.encode("ascii") + b"|vault|" + sha256(transcript).digest()
K     = HKDF-SHA256(ikm=ikm, salt=None, info=info, length=32).derive()
AAD   = canonical_json(["vault-aad", GROUP, c1_hex, c2_hex, D_C, "AES-256-GCM"])  # bytes
frame = nonce(12 bytes, counter 0) ‖ AESGCM(K).encrypt(nonce, plaintext, AAD)
```
`AESGCM.encrypt` appends the 16-byte tag. Members 2 and 3 must reconstruct exactly the same `ikm`,
`info`, `AAD` and nonce to decrypt. Changing `c₁`, `c₂` or `D_C` changes the key/AAD.
`vault_key` rejects identity or non-subgroup `m`, `c₁` and `c₂` before deriving the key.

`vault.json` (signed metadata):
```json
{"group": GROUP, "version": 1, "t": t, "n": n, "c1": "<512hex>", "c2": "<512hex>",
 "commitments_digest": "<64hex>", "sig": "<128hex>"}
```
The founder signature covers `canonical_json` of every field except `sig`.

## 7. Published directory layout

```
runtime/data/vault/
  current.json                 # atomically updated pointer to the active generation
  generations/
    generation-001/
      public/
        commitments.json
        vault.json
        vault.enc
      manifest.json            # written LAST: generation id, group, t, n, D_C, artifact digests

runtime/data/M1/m2/generations/generation-001/share.json   # private to M1
runtime/data/M2/m2/generations/generation-001/share.json   # private to M2
... M3, M4, M5
```

The protocol directory is `vault`, **not** `m2`: on Windows/macOS `m2` and member `M2` are the
same case-insensitive path, which would put Member 2's private key inside the public vault tree.
`runtime/data/M<i>/m2/generations/...` is unaffected because `M<i>` is a distinct name.

`current.json` schema:
```json
{"generation": "generation-001", "group": GROUP, "t": t, "n": n,
 "commitments_digest": "<64hex>"}
```

`manifest.json` schema:
```json
{"generation": "generation-001", "group": GROUP, "t": t, "n": n,
 "commitments_digest": "<64hex>",
 "artifacts": {"public/commitments.json": "<64hex>", "public/vault.json": "<64hex>",
               "public/vault.enc": "<64hex>"}}
```
Manifest path keys are **relative to the generation root**, always use `/` (POSIX separators,
via `Path.as_posix()`), and never contain an absolute filesystem path or `\`. This makes digests
resolvable identically on Windows, macOS and Linux.

**Private-share handoff.** Shares are versioned per generation inside each member's own private
tree. The founder generates all five shares but publishes only public data in the generation
directory. Each share is staged in `runtime/data/M<i>/m2/generations/generation-NNN.tmp/share.json`,
then activated by one directory rename. A member reads only
`runtime/data/M<i>/m2/generations/<active generation>/share.json`.

Ownership rules (enforced by application code, not just filesystem permissions):

- `M1` reads only its own `M1/m2/generations/.../share.json`; `M2` only its own; and so on.
  No member program opens another member's directory or share file.
- The server and Mallory never read any private share file — they receive only public commitments,
  vault metadata and ciphertext, plus decryption shares produced over the secure channel.
- After setup the founder does not retain, load or re-read all five shares; it keeps only its own CA
  key and the published public artifacts.
- No share value is logged or written to a public manifest or to the public vault tree; manifests
  contain only digests.
- 0600 permissions on POSIX are defence in depth. Because all programs may run as the same OS user,
  they do **not** provide process isolation — the ownership boundary above is the real control.

Each share file is `{"index": i, "generation": "generation-NNN", "s_i": "<512hex>"}`; a member uses
it only when its directory generation matches `current.json`.

**Atomic publication:** (1) generate and validate a candidate, rejecting degenerate ones; (2) build
the public artifacts in `generation-NNN.tmp` on the same filesystem; (3) stage all versioned member
shares in `.../<generation>.tmp/`; (4) re-validate shares, signatures and vault decryption, then
write `manifest.json` last; (5) rename the public directory to `generation-NNN`; (6) atomically
rename each staged member directory to `generation-NNN`; (7) **atomically update `current.json`
last**. Consumers ignore any generation without `manifest.json` and any member share whose
generation differs from `current.json`. Never overwrite an existing completed generation. Without
`--force`, setup refuses if one exists; **with `--force`, a new immutable generation is created**
(`generation-002`, etc.; old share directories are untouched). An interrupted forced setup leaves
`current.json` pointing at the previous generation with all five of its original shares intact.

## 8. Erasure

After encrypting, drop references to `s`, `a₁…a_{t−1}`, `u`, `r`, **`m`**, **`K`**, and temporary byte
representations; do not write or log them. Python integers are immutable, so `del` is **best-effort**
and cannot guarantee memory scrubbing — documented as such. Tests inspect persistent artifacts for
unexpected secret-bearing fields; they do not substring-scan binary ciphertext.

## 9. Opening (consumers, not Member 1 implementation)

Member 3 samples `w ← ℤ_q` and **retries when `w = 0`**, so `T₁=g^w` and `T₂=c₁^w` are strict
non-identity group elements. It produces `d_i = c₁^{s_i}` (strict) and a proof `(T₁, T₂, e, z)` with
`e = H("dec", i, c₁, h_i, d_i, T₁, T₂)`, `z = w + e·s_i mod q`.
Member 2 first checks `1 ≤ i ≤ n`, `len(commitments) == t`, and strict subgroup membership of all
incoming elements, verifies `g^z = T₁·h_i^e` and `c₁^z = T₂·d_i^e`, accepts `t` valid shares, computes
`λ_i` with `lagrange_coefficient`, then `D = ∏ d_i^{λ_i}` and `m = c₂·D^{-1}`.

## 10. Tests

Member 1 owns unit tests: all ten 3-of-5 subsets, `(2,4)` generic helper test, sub-threshold proof via
`g(x)=f(x)+c∏(x−j)`, zero coefficients/identity commitments, invalid indices/shares/commitments,
explicit helper-limit tests (`verify_share` does not enforce `n`/`t`), strict `vault_key` rejection,
founder setup artifacts and signatures, rejection of degenerate candidates, key-change on `c₁`/`c₂`
modification, refusal to regenerate, no partial publication on failure, `vault`/`M2` directory
separation, no shares in the public vault tree, and POSIX manifest keys.

The **joint** end-to-end test (after Members 2/3 integrate) is separate: founder → Member 3 proofs →
Member 2 verification/combination → `m` → AES-GCM decryption of the original file.

## 11. Contract status

The code on `feature/m2-founder-sharing` implements this proposed document. Final internal decisions
are recorded above so they are not relitigated:

- Highest Shamir coefficient is sampled from `ℤ_q`; published polynomials are described as degree
  at most `t−1`, with degenerate candidates rejected before publication (§4).
- Identity elements are forbidden at protocol boundaries; the relaxed subgroup helper is not used.
- Member 3 samples `w ← ℤ_q` and retries on zero, so `T₁/T₂` are strictly validated (§9).
- `s, u, r` are nonzero; zero shares and `c₂ = 1` reject the candidate; `group.py` keeps Member 4's
  strict validator; `verify_share()` keeps the starter signature; founder erasure is best-effort;
  forced regeneration creates a new immutable generation.

Still pending: Members 2 and 3 must approve the commitment digest, HKDF/AAD bytes, path layout and
caller-side validation checks before M2 integration is frozen.
