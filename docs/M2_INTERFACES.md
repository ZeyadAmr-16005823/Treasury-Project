# Milestone 2 — shared interface contract

Owner: Member 1 (Zeyad). This document freezes the cryptographic material the founder produces and
how Members 2 and 3 consume it. Please review before implementing M2 on any branch.

## 1. Scope and ownership

| Area | Owner |
|---|---|
| `sharing.py` (Shamir, shares, commitments, Lagrange) | Member 1 |
| Founder vault setup in `founder.py` | Member 1 |
| This document | Member 1 |
| `opening.py`: decryption shares, Chaum-Pedersen proofs, exported verification/combining helpers | Member 3 |
| Server-side proof verification, Lagrange combination, vault opening | Member 2 |
| A5 malicious-member demonstration | Member 4 |
| `group.py` (`P, Q, G`, subgroup validation) | Member 4 — **do not edit from Member 1** |

Terminology: `C_k = g^{a_k}` are **Feldman-style coefficient commitments**, not Pedersen.

## 2. Group and scalar domains

- `P, Q=(P−1)//2, G=4` come from `treasury.group`; never copy constants.
- Group elements are encoded as **fixed-width 256-byte big-endian → 512 lowercase hex chars**, no `0x`.
- Scalars (`s_i`, `w`, etc.) are encoded as fixed-width 256-byte big-endian hex (512 chars).
- `s`, `u`, `r` are sampled by rejection from `ℤ_q* = {1,…,q−1}`: uniform over `ℤ_q*`, **not** uniform
  over all of `ℤ_q`. This deliberately avoids `h=1`, `c₁=1`, `c₂=m` and `m=1`. The handout says
  "random … in ℤ_q"; ℤ_q* is a strict subset. Confirm this interpretation with the TA.
- Polynomial coefficients `a₁…a_{t−1}` are sampled from all of ℤ_q (zero **is** allowed).

## 3. Subgroup validation

`sharing.py` exports a local helper (Member 4 may later move it into `group.py`):

```python
is_subgroup_element(u, p, q, *, allow_identity=False) -> bool
# 1 <= u < p and pow(u, q, p) == 1; if not allow_identity, also u != 1
```

| Element | Rule |
|---|---|
| `C₀ = g^s` | strict (identity forbidden, since `s ≠ 0`) |
| `C₁ … C_{t−1}` | identity permitted (coefficient may be 0) |
| `c₁ = g^r` | strict (`r ≠ 0`) |
| `c₂` | identity permitted |
| `h_i = ∏ C_k^{i^k}` | identity permitted (share may be 0) |
| `d_i = c₁^{s_i}` | identity permitted |
| recovered `m` | strict (`u ≠ 0`) |
| `T₁ = g^w`, `T₂ = c₁^w` | **pending Member 3 confirmation**: if `w` may be 0 → identity permitted; if `w ← ℤ_q*` → strict |

`group.is_valid_element()` remains the strict M1 validator; `is_subgroup_element(..., allow_identity=True)`
is the relaxed M2 check.

## 4. Shamir sharing — `sharing.py` (Member 1)

Starter signatures preserved:

```python
evaluate_polynomial(coefficients: list[int], x: int, q: int) -> int
make_shares(secret: int, t: int, n: int, q: int) -> tuple[list[int], list[int]]
verify_share(share: int, member_index: int, commitments: list[int], p: int, q: int, g: int) -> bool
lagrange_coefficient(i: int, selected_indices: list[int], q: int) -> int
```

- Polynomial: `f(x) = a₀ + a₁x + … + a_{t−1}x^{t−1} mod q`, `a₀ = s`, degree **at most** `t−1`.
  All coefficients are sampled from all of ℤ_q as the handout specifies. Consequently the highest
  coefficient can be zero; then `C_{t−1} = 1` publicly reveals a lower-degree polynomial. How far the
  effective threshold drops depends on the remaining coefficients: with `a_{t−1}=0, a_{t−2}≠0` a
  polynomial of degree `t−2` remains and `t−1` shares suffice; if every higher coefficient is also
  zero the polynomial is constant and **one** share reveals `s`. Probability `1/q` per coefficient is
  negligible for this group but nonzero. Ask the TA whether to instead sample `a_{t−1}` from ℤ_q* to
  guarantee exact degree `t−1`. Do not silently change the handout's rule; until clarified, describe
  the polynomial as "degree at most t−1". The deterministic test uses nonzero lower coefficients when
  demonstrating the two-share case.
- `make_shares` returns `(coefficients, [f(1), …, f(n)])`; uses `secrets.randbelow(q)`, never `random`.
- `verify_share`: validates index `1…n`, scalar range, commitment list length `t`, `C₀ != 1`, all
  commitments in subgroup (identity permitted for `k≥1`), then checks `g^{share} == ∏ C_k^{i^k} mod p`.
- `lagrange_coefficient(i, S, q)`: `∏_{j∈S, j≠i} j·(j−i)^{-1} mod q`, 1-based sorted `S`,
  `i ∈ S`, modular inverse via `pow(x, -1, q)`.

Additional exported helpers (new):

```python
is_subgroup_element(u, p, q, *, allow_identity=False) -> bool
random_nonzero_scalar(q: int) -> int
make_commitments(coefficients: list[int], p: int, q: int, g: int) -> list[int]
hex_element(value: int) -> str          # 512 lowercase hex chars
vault_transcript(c1_hex, c2_hex, D_C) -> bytes
vault_aad(c1_hex, c2_hex, D_C) -> bytes
vault_key(m, c1_hex, c2_hex, D_C) -> bytes
```

## 5. Commitments and their signature

```
commitments_bytes = canonical_json(["commitments", GROUP, t, n, C_hexes])  # already bytes
D_C               = hashlib.sha256(commitments_bytes).hexdigest()   # 64 lowercase hex chars
sig               = sign_raw(founder_private_key, commitments_bytes)  # 128 hex chars
```

`commitments.json` lives in the generation's `public/` directory:
```json
{"group": GROUP, "t": t, "n": n, "commitments": ["<512hex>", ...],
 "digest": "<64hex>", "sig": "<128hex>"}
```
The same `commitments_bytes` is used for both the digest and the founder signature.

## 6. Vault encryption — byte-level contract

```
h     = C₀
m     = g^u mod p                      (u ≠ 0)
c₁    = g^r mod p                      (r ≠ 0)
c₂    = m · h^r mod p
ikm   = m.to_bytes(256, "big")
transcript = canonical_json(["vault", GROUP, c1_hex, c2_hex, D_C])  # already bytes
info  = b"ICS505|" + GROUP.encode("ascii") + b"|vault|" + hashlib.sha256(transcript).digest()
K     = HKDF-SHA256(ikm=ikm, salt=None, info=info, length=32).derive()
AAD   = canonical_json(["vault-aad", GROUP, c1_hex, c2_hex, D_C, "AES-256-GCM"])  # bytes
frame = nonce(12 bytes, counter 0) ‖ AESGCM(K).encrypt(nonce, plaintext, AAD)
```
`AESGCM.encrypt` appends the 16-byte tag. Members 2 and 3 must reconstruct exactly the same `ikm`,
`info`, `AAD` and nonce to decrypt. Changing either `c₁` or `c₂` or `D_C` changes the key/AAD.

`vault.json` (signed metadata):
```json
{"group": GROUP, "version": 1, "t": t, "n": n, "c1": "<512hex>", "c2": "<512hex>",
 "commitments_digest": "<64hex>", "sig": "<128hex>"}
```
The founder signature covers `canonical_json` of every field except `sig`.

## 7. Published directory layout

```
runtime/data/m2/
  generations/
    generation-001/
      public/
        commitments.json
        vault.json
        vault.enc
        manifest.json          # written LAST: generation id, t, n, D_C, artifact digests
  current.json                 # atomically updated pointer to the active generation

runtime/data/M1/m2/generations/generation-001/share.json   # private to M1
runtime/data/M2/m2/generations/generation-001/share.json
... M3, M4, M5
```

**Private-share handoff.** Shares are **versioned per generation** inside each member's own private
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
- No share value is logged or written to a public manifest; manifests contain only digests.
- 0600 permissions on POSIX are defence in depth. Because all programs may run as the same OS user,
  they do **not** provide process isolation — the ownership boundary above is the real control.

Each share file is `{"index": i, "generation": "generation-NNN", "s_i": "<512hex>"}`; a member uses
it only when its directory generation matches `current.json`.

**Atomic publication:** (1) build the public artifacts in `generation-NNN.tmp` on the same
filesystem; (2) stage all five versioned member shares in `.../<generation>.tmp/`; (3) validate
shares + signatures + vault decryption; (4) write `manifest.json` last and rename the public
directory to `generation-NNN`; (5) atomically rename each staged member directory to `generation-NNN`;
(6) **atomically update `current.json` last**. Consumers ignore any generation without
`manifest.json`, and any member share whose generation differs from `current.json`. Never overwrite
an existing completed generation. Without `--force`, setup refuses if one exists; **with `--force`, a
new immutable generation is created** (`generation-002`, etc.; old share directories are untouched).
An interrupted forced setup leaves `current.json` pointing at the previous generation with all five
of its original shares intact.

## 8. Erasure

After encrypting, drop references to `s`, `a₁…a_{t−1}`, `u`, `r`, **`m`**, **`K`**, and temporary byte
representations; do not write or log them. Python integers are immutable, so `del` is **best-effort**
and cannot guarantee memory scrubbing — documented as such. Tests inspect persistent artifacts for
unexpected secret-bearing fields; they do not substring-scan binary ciphertext.

## 9. Opening (consumers, not Member 1 implementation)

Member 3 produces `d_i = c₁^{s_i}` and proof `(T₁, T₂, e, z)` with
`e = H("dec", i, c₁, h_i, d_i, T₁, T₂)`, `z = w + e·s_i mod q`.
Member 2 verifies `g^z = T₁·h_i^e` and `c₁^z = T₂·d_i^e`, accepts `t` valid shares, computes
`λ_i` with `lagrange_coefficient`, then `D = ∏ d_i^{λ_i}` and `m = c₂·D^{-1}`.

## 10. Tests

Member 1 owns unit tests: all ten 3-of-5 subsets, `(2,4)` generic helper test, sub-threshold proof
via `g(x)=f(x)+c∏(x−j)`, zero coefficients/identity commitments, invalid indices/shares/commitments,
founder setup artifacts and signatures, key-change on `c₁`/`c₂` modification, refusal to regenerate,
no partial publication on failure.

The **joint** end-to-end test (after Members 2/3 integrate) is separate: founder → Member 3 proofs →
Member 2 verification/combination → `m` → AES-GCM decryption of the original file.

## 11. Contract status

The code on `feature/m2-founder-sharing` implements this document, but the contract is **not yet fully
agreed by the team**:
- Member 3 must confirm the `w` nonce rule so `T₁`/`T₂` validation is frozen.
- Member 4 must add the backward-compatible `is_subgroup_element()` helper to `group.py`.
- Members 2 and 3 must approve the commitment digest, HKDF/AAD bytes, validation rules and paths.
- The TA must confirm whether `a_{t−1}` may be zero (§4) before the sampling rule is frozen.
