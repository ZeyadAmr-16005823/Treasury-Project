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

- Polynomial: `f(x) = a₀ + a₁x + … + a_{t−1}x^{t−1} mod q`, `a₀ = s`, degree `t−1`.
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
      M1/share.json
      M2/share.json
      M3/share.json
      M4/share.json
      M5/share.json
  current.json                 # atomically updated pointer to the active generation
```
`share.json = {"index": i, "s_i": "<512hex>"}`, private key file permissions on POSIX, never logged.
This tree is separate from M1 certificates and registrations.

**Atomic publication:** build everything in `generation-NNN.tmp` on the same filesystem, validate
shares + signatures + vault decryption there, then **one** directory rename to `generation-NNN`,
write `manifest.json` last (or rename a prebuilt complete directory), then atomically update
`current.json`. Consumers ignore any generation without `manifest.json`. Never overwrite an
existing completed generation; `--setup-vault` refuses if one exists unless explicitly forced.

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
