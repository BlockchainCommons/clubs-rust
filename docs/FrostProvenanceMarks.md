# Seedless, Roster‑Invariant Provenance Marks with a FROST‑controlled VRF on secp256k1

**Goal**: Replace per‑chain seeds / PRNG state in Blockchain Commons *Provenance Marks (PM)* with a *group‑controlled*, auditable, deterministic source of pseudorandomness that is independent of which particular quorum of group members is live.

**NOTE:** Readers unfamiliar with symbols and terms in this document may wish to consult [Appendix A](#Appendix-A-—-Glossary-of-Symbols-and-Terms).

## Abstract

We present a practical construction that lets a FROST threshold group advance a Provenance Mark (PM) chain **without any seed or secret PRNG state**. At each step, the group collectively produces a VRF output

$$
\Gamma_j \;=\; x\cdot H(m_j)
$$

and a short DLEQ proof that links the group public key $X=x\cdot G$ to $\Gamma_j$. The **PM key** for step $j$ is derived as

$$
\text{key}_j \;=\; \mathrm{SHA256}\big(\text{compress}(\Gamma_j)\big),
$$

optionally truncated to the PM resolution (4/8/16/32 bytes). The message $m_j$ is built entirely from **public** inputs (the group key $X$, a chain identifier, the public ratchet state, and the step index), so anyone can recompute $H(m_j)$ and verify the proof; but only the FROST group (who hold $x$) can compute $\Gamma_j$, hence only they can advance the chain.

Our tests demonstrate:

* **Determinism** (same inputs ⇒ same keys),
* **Roster‑invariance** (any valid $t$-of‑$n$ quorum yields the same keys), and
* **Statistical quality** via a SP 800‑22 battery over \~2 M bits.

The construction is implemented against **`frost-secp256k1-tr`** (Taproot/BIP‑340 ciphersuite) and the RustCrypto **`k256`** group, integrating with the `provenance-mark` crate via an “EnhancedMark” wrapper that carries the DLEQ proof. No protocol changes to PM are assumed yet; we outline a minimal `proof` field addition for future adoption as part of a revision to the `provenance-mark` specification and implementation.

## 1. Motivation & Requirements

Traditional PM chains start from a **seed** and advance a **PRNG**, which raises operational questions:

* who generates / safeguards the seed,
* how a multi‑party team agrees to advance,
* how verifiers gain assurance that a claimed key really came from the intended team.

Our requirements:

1. **No per‑chain seed and no secret PRNG state.**
2. **Group control**: only an authorized FROST $t$-of‑$n$ quorum can advance.
3. **Public verifiability**: anyone can verify each step from public data.
4. **Roster‑invariance**: *any* valid quorum yields the **same** next key.
5. **Deterministic** and **statistically random** outputs.

## 2. Testbed Implementation

The proof of concept code for this methdology is contained in  [frost-vrf-dleq-secp](https://github.com/BlockchainCommons/frost-vrf-dleq-secp).

**NOTE:** Our tests deliberately **do not** run an interactive, two‑round FROST‑style MPC to produce $\Gamma$ and the DLEQ proof. They are math‑equivalent (because $x = \sum_i \lambda_i x_i$) and keep the code small so we can focus on correctness of the VRF/DLEQ, the PM binding/ratchet, roster‑invariance, and randomness quality.

## 3. Design Overview

Think of the group’s long‑term (public/verifying) key $X$ as the group’s “identity.” For each step $j$, we build a public message $m_j$ whose contents are fixed and transparent (group identity, chain id, previous public state, and a counter). We hash that message **onto the curve** to a point $H(m_j)$, which is unpredictable and uniformly random in the group. Only the group knows the private scalar $x$ such that $X=x\cdot G$; multiplying $H(m_j)$ by $x$ gives a new secret‑looking point $\Gamma_j$. Hashing $\Gamma_j$ produces the **PM key** for that step.

Anyone can recompute $H(m_j)$, but **no one** without $x$ can compute $\Gamma_j$. To prove correctness, the group publishes a tiny **DLEQ proof** that says:

> “The same secret $x$ that makes our public key $X=x\cdot G$ also generated $\Gamma_j = x\cdot H(m_j)$.”

Verifiers check the DLEQ and then hash $\Gamma_j$ to confirm the announced key.

## 4. Primitives & Dependencies

### 4.1 Curve and ciphersuite

* **Curve**: `k256` (secp256k1), prime‑order group.
* **Threshold signatures**: **`frost-secp256k1-tr`** (Taproot/BIP‑340 flavored ciphersuite).
  * *Why this choice?* It aligns with BIP‑340 Schnorr semantics and even‑Y normalization used broadly in Bitcoin/Taproot stacks, making our keys and points **wire‑compatible** with existing tooling and avoiding cofactor subtleties.

### 4.2 Hash‑to‑curve (H2C)

* We use RustCrypto’s standardized **random‑oracle hash‑to‑curve** for secp256k1 (SSWU with XMD\:SHA‑256) via:

  * `src/lib.rs :: hash_to_curve`

```rust
<Secp256k1 as GroupDigest>::hash_from_bytes::<ExpandMsgXmd<Sha256>>(&[msg], &[H2C_DST])
```

* Domain separation tag: `H2C_DST = "FROST-VRF-secp256k1-SHA256-RO"`.

### 4.3 VRF with DLEQ

* **VRF output**: `Gamma = x·H(m)`
* **Proof** (Chaum–Pedersen over two bases):
  * Prover picks random $k$, sets $A=k·G$, $B=k·H$.
  * Challenge $e = H_2(X || \Gamma || A || B || \text{DLEQ\_DST})$.
  * Response $z = k + e·x$.
  * Verify: $z·G = A + e·X$ and $z·H = B + e·\Gamma$.
* Implemented in:
  * `src/lib.rs :: vrf_gamma_and_proof_for_x` (prover),
  * `src/lib.rs :: vrf_verify_for_x` (verifier),
  * `src/lib.rs :: dleq_challenge_x` (Fiat–Shamir transcript).
* Domain separation tag: `DLEQ_DST = "FROST-VRF-DLEQ-2025"`.

> **Note.** In the tests we reconstruct $x$ from a quorum to exercise the math end‑to‑end. In deployment, the same DLEQ can be produced *without* reconstructing $x$ by having each participant contribute to $A$ and $B$ with their FROST nonces on bases $G$ and $H$, and aggregating (standard Chaum–Pedersen in MPC). The proof *format* and verification remain identical.

## 5. How a PM key is produced

### 5.1 Message binding

We bind each step to public, objective inputs:

* group key $X$ (fixed for the chain),
* `chain_id` (byte string, fixed for the chain),
* previous public state $S_{j-1}$ (32 bytes),
* step index $j$ (u64).

This is constructed by:

* `src/lib.rs :: pm_message(x_point, chain_id, state_prev, j)`

Result: a byte string `m_j` anyone can reconstruct.

### 5.2 VRF and proof

* Compute $H_j = H(m_j)$ using `hash_to_curve`.
* Compute $\Gamma_j = x·H_j$ and DLEQ proof using
  `vrf_gamma_and_proof_for_x(x, X, H_j)`.

### 5.3 Key derivation & public ratchet

* **Key**: `key_j = SHA256("PMKEY-v1" || compress(Γ_j))`
  via `src/lib.rs :: key_from_gamma`.
* **State**: `S_j = SHA256("PMSTATE-v1" || S_{j-1} || key_j)`
  via `src/lib.rs :: ratchet_state`.

The ratchet is **public** and deterministic. No secret state is kept anywhere.

> **Resolutions.** PM defines four key “link lengths” (4, 8, 16, 32 bytes). We derive a full 32‑byte key then **truncate** to the chosen link length for the stored `key`/`nextKey` fields. (See the integration test for this truncation.)

## 6. Data that appears in a mark (today)

We currently keep `provenance-mark` unchanged and carry the DLEQ externally in a wrapper used only by the tests:

* `tests/pm_integration.rs :: EnhancedMark { mark, gamma_next_bytes, proof_next }`

Here, each `ProvenanceMark` is created with:

* `res` : resolution (Low/Medium/Quartile/High),
* `key_j` : the mark’s key (truncated to link length),
* `next_key_j` : the next mark’s key (also truncated),
* `chain_id` : public chain id (truncated to link length),
* `seq` : sequence number,
* `date` : monotone timestamp,
* `info` : left `None` in the test.

**Verification** in the test suite:

* `ProvenanceMark::precedes` for each adjacent pair,
* `ProvenanceMark::is_sequence_valid` for the whole chain, and
* for each `j`, public verification of DLEQ for `next_key_j`:

  * reconstruct `m_{j+1}` from public data,
  * recompute `H_{j+1}`,
  * verify `vrf_verify_for_x(X, H_{j+1}, Γ_{j+1}, proof_{j+1})`,
  * check that `hash(Γ_{j+1})` truncated equals the stored `key_{j+1}` in the next mark.

> **Future change to PM**: add an optional `proof` field carrying `(Γ, A, B, z, e, alg-id)` so a mark can stand alone. Our `EnhancedMark` shows exactly what needs to be stored.

## 7. Why this meets the requirements

### Deterministic and roster‑invariant

* $m_j$ is a function of public $X$, `chain_id`, $S_{j-1}$, $j$.
* $\Gamma_j = x·H(m_j)$ is *unique* for a given $x$.
* Any $t$-of‑$n$ quorum for the same group key computes **the same** $\Gamma_j$ and hence the same key. (Tests: `pm_chain_deterministic_and_roster_invariant`.)

### Group‑controlled; no seed and no secret PRNG state

* There is **no seed** and no secret ratchet state.
* Only holders of $x$ can compute $\Gamma_j$; observers cannot.
* The DLEQ proof gives **public evidence** that the published key truly came from the group secret $x$.

### Statistically random

* With random‑oracle $H_2C$, the point $H(m_j)$ is uniform in the group; multiplying by fixed $x$ preserves uniformity; hashing a compressed point yields high‑quality pseudorandom bits.
* Tests (NIST SP 800‑22 via `nistrs`) pass a broad battery (Frequency, Block Frequency, Runs, Cumulative Sums, Longest Run, Rank, FFT, Universal, Approximate Entropy, Serial, Overlapping/Non‑overlapping Templates). We evaluate **pass‑rates** for the large Non‑overlapping family and log/skips for the two Random Excursions tests when their preconditions aren’t met.

## 8. Cryptographic details

### 8.1 Groups & encodings

* `k256` secp256k1, prime order $n$; compressed SEC1 (33 bytes) everywhere.
* `src/lib.rs :: point_bytes`, `point_from_bytes` encapsulate encoding/decoding (reject identity).

### 8.2 Domain separation

* H2C: `H2C_DST = "FROST-VRF-secp256k1-SHA256-RO"`.
* DLEQ challenge: `DLEQ_DST = "FROST-VRF-DLEQ-2025"`.
* PM ratchet and key derivation use distinct tags `"PMSTATE-v1"` and `"PMKEY-v1"`.
* PM message prefix: `"PMVRF-secp256k1-v1"` in `pm_message`.

### 8.3 VRF proof (DLEQ)

Prover:

1. $A = k·G$, $B = k·H$ with random $k$.
2. $e = H_2(X || \Gamma || A || B || \mathrm{DLEQ\_DST})$.
3. $z = k + e·x$.

Verifier:

1. Recompute $e$ from the same transcript.
2. Check $z·G \stackrel{?}{=} A + e·X$ and $z·H \stackrel{?}{=} B + e·\Gamma$.

See `vrf_gamma_and_proof_for_x` / `vrf_verify_for_x`.
**Security note:** all inputs to the transcript are ciphersuite‑serialized group elements (33‑byte compressed) to avoid ambiguity.

### 8.4 Taproot parity (BIP‑340)

* The Taproot ciphersuite fixes **even‑Y** for public keys. Our helper
  `normalize_secret_to_pubkey(x, X)` ensures the scalar we use satisfies $x·G=X$ under that normalization. (The *tests* reconstruct $x$ for demonstration; production protocols don’t.)
* This affects only *representation*, not the proof or derived keys.

## 9. Integration with the `provenance-mark` crate

We keep PM unchanged and wrap marks with `EnhancedMark` carrying the proof:

* `tests/pm_integration.rs :: EnhancedMark`
* `run_resolution(..)` builds **100‑mark** chains for all four PM resolutions and verifies:
  * `is_genesis`, `precedes`, `is_sequence_valid`,
  * DLEQ correctness for every `next_key`, and
  * `key_{j+1}` (from $\Gamma_{j+1}$) equals the next mark’s stored key.

**Chain id.** In tests we generate a chain id deterministically from $X$ and a label, truncated to the resolution’s link length (see `make_chain_id`).

**Public ratchet.** We ratchet on a 32‑byte expansion of the stored (possibly truncated) key via `expand_key_to_32` in the test; in the library we expose `ratchet_state` and `key_from_gamma`.

## 10. Security considerations

* **Unpredictability**: Under discrete‑log hardness and random‑oracle H2C, $\Gamma_j = x·H(m_j)$ is pseudorandom from the perspective of anyone without $x$. Publishing $\Gamma_j$ (or its hash) reveals no usable information about $x$.
* **Unbiasability**: Once $m_j$ is fixed, $\Gamma_j$ is determined; the group cannot steer the output by choosing nonces or roster. We bind $m_j$ to $X$, `chain_id`, $S_{j-1}$, and $j$. (`chain_id` is established at genesis and is immutable thereafter.)
* **Soundness**: The DLEQ proof prevents a malicious coordinator from substituting a wrong $\Gamma$; both base equations must hold under a Fiat–Shamir challenge bound to the transcript.
* **No secret state**: Only the long‑term secret $x$ exists (already present if the group has a FROST key). The PM ratchet state $S_j$ is public and deterministic.
* **Key truncation**: PM’s low/medium resolutions (4/8 bytes) intend *linkability*, not cryptographic collision resistance. For cryptographic comparators, use the 32‑byte `High` resolution (or the underlying full 32‑byte `SHA256(Γ)` before truncation).
* **Side channels**: All verification is public. Provers must use a CSPRNG for the proof nonce $k$ (we use `OsRng` in `vrf_gamma_and_proof_for_x`).
* **Liveness**: Any $t$-of‑$n$ quorum can advance a step; roster churn is tolerated so long as the group public key $X$ remains the same (via resharing if membership changes).
* **Auditability**: Verifiers need only $X$, `chain_id`, $S_{j-1}$, $j$, and the mark’s proof to check `key_j`.

## 11. Test methodology & results

* **Determinism & roster‑invariance** (`tests/pm_chain.rs :: pm_chain_deterministic_and_roster_invariant`)
  Two different 3‑of‑5 quorums produce the same 64‑step chain (keys and final state equal). Re‑running with the same quorum reproduces the same sequence byte‑for‑byte.

* **Integration with PM** (`tests/pm_integration.rs`)
  For each resolution (Low/Medium/Quartile/High), we build **100 marks**, check `precedes` and `is_sequence_valid`, and verify the DLEQ for every `next_key`.

* **Randomness quality** (`tests/pm_chain.rs :: pm_chain_nist_randomness_suite`)
  We generate \~2 M bits (8,192 keys × 32 bytes) and run a **NIST SP 800‑22** battery via `nistrs`.

  * Single‑result tests assert $p \ge \alpha$ (α=0.01).
  * For **non‑overlapping templates** (many subtests), we assert a high pass‑rate (allow ≤ 2% failing subtests) to avoid family‑wise false positives.
  * **Random Excursions** tests are run when their preconditions (enough walk cycles) are met; otherwise they are skipped with an informative message.
    The suite passes under these criteria.

## 12. Implementation notes & where to look

* **Library entry points** (all in `src/lib.rs`):

  * VRF prover/verifier: `vrf_gamma_and_proof_for_x`, `vrf_verify_for_x`.
  * H2C: `hash_to_curve`.
  * PM message & ratchet: `pm_message`, `key_from_gamma`, `ratchet_state`.
  * Encodings: `point_bytes`, `point_from_bytes`.
  * Taproot normalization helper: `normalize_secret_to_pubkey`.
* **Tests**:

  * VRF/DLEQ core: `tests/vrf_dleq.rs`.
  * Determinism, roster‑invariance, NIST suite: `tests/pm_chain.rs`.
  * PM integration with “EnhancedMark”: `tests/pm_integration.rs`.

## 13. Rationale for major dependencies

* **`frost-secp256k1-tr`**: Taproot/BIP‑340 Schnorr ciphersuite over secp256k1, aligning with Bitcoin’s x‑only public keys and even‑Y normalization. This makes our group key and any optional receipts directly compatible with existing Bitcoin/Taproot stacks and avoids cofactor issues present on some other curves.

* **`k256`**: Pure‑Rust, well‑maintained secp256k1 implementation with **hash‑to‑curve** support (SSWU RO with XMD\:SHA‑256). It provides the group arithmetic we need for both the VRF and DLEQ.

* **`sha2`**: SHA‑256 for key derivation, ratcheting, and transcript hashing (via the ciphersuite’s `H2`).

* **`provenance-mark`**: The canonical data model and invariants (`precedes`, `is_sequence_valid`) we target. We currently keep the proof external; a future `proof` field would embed the VRF/DLEQ directly.

* **`nistrs`**: NIST SP 800‑22 test battery to quantify the statistical quality of the generated key stream.

## 14. Operational guidance

* **Publishing**: Each mark should carry `key_j` and `next_key_j` (as today), plus a new `proof` object containing `(Γ_{j+1}, A, B, z, e, alg-id)`. Our `EnhancedMark` shows an exact, minimal shape.

* **Genesis**: Fix `chain_id` at genesis, record the group key $X$, and commit to algorithm identifiers (`alg-id`: e.g., `"pmvrf-secp256k1-sha256-v1"`).

* **Liveness**: Because any quorum can advance, PM generation tolerates intermittently offline members.

* **Security level**: For cryptographically robust linking, prefer **High** resolution (32 bytes). Lower resolutions are intended for human‑readable linkability or constrained environments.

## 15. Running PM “as‑is” under FROST

You can keep the Provenance Mark format **exactly as‑is** (no new `proof` field), and have a **FROST quorum** control the chain. The only thing that changes from the traditional method is **how `key` and `next_key` are *generated***: instead of a seed/PRNG, they come from a **group‑controlled VRF** under the long‑term FROST key. The on‑chain continuity property: “a new mark can only be generated by revealing the `key` that was previously committed as `next_key`”—remains intact.

What you *do not* get without adding a `proof` field is **public attestability** that a given `key` was produced by the FROST group. That’s the same as the seed/PRNG model: outsiders can check continuity but not who actually produced the key. If that’s acceptable for your use‑case (as you said), you can proceed with PM **unchanged**.

### How to run PM “as‑is” under FROST (no new fields)

#### Fix your public parameters

* **Group public key:** $X = x\cdot G$ from your FROST key (already present if you use FROST).
* **Chain id:** Whatever policy you already have (our tests derive a deterministic one, but PM doesn’t mandate that).
* **Genesis ratchet:** keep the **implicit ratchet** (we do not serialize it). Use a public deterministic rule such as
  $S_0 = \mathrm{SHA256}(\text{"PM‑Genesis"})$
  (that’s exactly what our tests do), or the slightly stronger
  $S_0 = \mathrm{SHA256}(\text{"PM‑Genesis‑v1"} \,\|\, X \,\|\, \text{chain\_id})$.
  Either way, $S_0$ is *public* and *recomputable*.

#### For each step $j$ (what the quorum does)

1. **Build the public message** that fixes this step:

   $$
   m_j \;=\; \text{encode}\big(X,\ \text{chain\_id},\ S_{j-1},\ j\big)
   $$

   (code: `pm_message(...)`). This makes the step depend on the entire prior history via $S_{j-1}$.

2. **Hash to curve**: compute $H_j = H(m_j)$ (code: `hash_to_curve`).

3. **Threshold multiply** (no seed, no PRNG): compute the VRF point

   $$
   \Gamma_j = x\cdot H_j
   $$

   **without reconstructing $x$** by using the **linearity** of scalar multiplication:

   * Let your signing set $R$ be any valid quorum (size $t$).
   * Each participant $i\in R$ locally computes a *weighted share* point

     $$
     \gamma_i \;=\; (\lambda_i \, x_i)\cdot H_j,
     $$

     where $x_i$ is their secret share and $\lambda_i$ is the standard **Lagrange coefficient** for this roster (as in FROST aggregation).
   * The coordinator sums the contributions:

     $$
     \Gamma_j \;=\; \sum_{i\in R}\gamma_i \;=\; \Big(\sum_{i\in R}\lambda_i x_i\Big)\cdot H_j \;=\; x\cdot H_j.
     $$

   This step requires **no new PM fields**, no stored state, and works with *any* quorum; different quorums produce the **same** $\Gamma_j$ because the Lagrange interpolation of $x$ is unique.

4. **Derive the 32‑byte key** for this step from $\Gamma_j$: $\text{key}_j^{(32)} = \mathrm{SHA256}(\text{"PMKEY‑v1"} \,\|\, \text{compress}(\Gamma_j))$ (code: `key_from_gamma`).

5. **Populate the mark fields exactly as PM expects:**

   * `key` for the *current* mark $j$ must equal the **previous** mark’s `next_key` (for genesis, PM already uses `chain_id` as `key_0`, which we keep).
   * `next_key` for the *current* mark is the **truncated** form of $\text{key}_{j+1}^{(32)}$. So in practice:

     * You compute **two** messages: $m_j$ and $m_{j+1}$, therefore two $\Gamma$’s and two 32‑byte keys.
     * `key_j` (stored) = trunc($\text{key}_j^{(32)}$) must match the previous `next_key`.
     * `next_key_j` (stored) = trunc($\text{key}_{j+1}^{(32)}$).

6. **Advance the public ratchet** (internal, not stored in the mark):

   $$
   S_j \;=\; \mathrm{SHA256}\big(\text{"PMSTATE‑v1"} \,\|\, S_{j-1} \,\|\, \text{key}_j^{(32)}\big)
   $$

   (code: `ratchet_state`).
   If you only have the **stored truncated** key in hand (Low/Medium/Quartile), expand it first as our tests show:
   $\text{key}_j^{(32)} = \mathrm{SHA256}(\text{"PM‑KEY32"} \,\|\, \text{key}_j^{(\text{trunc})})$.

> **Important:** Steps 3–6 change *only your internal production process*. The *mark format* remains identical, and the continuity invariant (“`next_key` in $j-1$ equals `key` in $j$”) is unchanged.

#### You **gain**

* **Group control without seed custody:** only a valid $t$-of‑$n$ group can compute $\Gamma_j$ and therefore the next keys. There’s no seed/PRNG to guard or leak.
* **Roster‑invariance:** any quorum produces the *same* sequence (we explicitly test this).
* **Determinism:** same inputs → same keys (also tested).
* **Indistinguishability:** FROST-controlled chains look identical to traditional chains.

#### You **don’t gain**

* **Public attestability that “the group” produced it.**
  Outsiders will still only see that `key` matches the `next_key` that was committed previously—which is *exactly* what they saw in the seed/PRNG design. If you want third parties to verify that the FROST group generated the key (not just that the chain is continuous), you’d include a **DLEQ proof** and $\Gamma$ in an optional `proof` field.

### Practical considerations

* **Participant‑side checks (optional but recommended):**
  Have each signer include a *per‑share DLEQ* proving $\log_G(Y_i) = \log_{H_j}(\gamma_i)$, where $Y_i = x_i\cdot G$ is their verification share. The coordinator verifies these before summing. This guards against a malicious participant sending a bad $\gamma_i$. These per‑share proofs are **off‑chain** and do not alter PM.

* **Coordinator neutrality:**
  The coordinator cannot “bias” the key: once $X$, `chain_id`, $S_{j-1}$ and $j$ are fixed, $\Gamma_j$ is fixed. The only discretionary power is whether to publish the next mark (which is also true in the seed/PRNG model).

* **Genesis and single‑mark verification:**
  Because the ratchet is implicit, verifying a single mark in isolation requires the verifier to (a) know the **genesis rule** $S_0$, and (b) either walk from genesis or be given $S_{j-1}$ out‑of‑band. This is unchanged from your current PM, which also doesn’t store the ratchet.

* **Resolution choice:**
  If you intend to rely on the *stored* `key`/`next_key` as a cryptographic selector, prefer **High** (32 bytes). Lower resolutions are for linkability in compact UIs and increase the chance of accidental collisions over long chains (the chain still verifies, but two unrelated chains could present the same 8‑byte key at some step).

---

## 16. Future work

* **Add FROST group support** to the `provenance-mark` crate as a gated feature without changing the format.

* **Optionally Embed `proof` in `provenance-mark`** (CBOR), with an explicit algorithm tag and compressed points.

* **Threshold VRF without reconstruction**: implement the MPC DLEQ path so signers contribute $A_i$ and $B_i$ shares (or DLEQ shares) and the coordinator aggregates; no party ever forms $x$.

* **Key rotation / resharing**: adopt FROST DKG/resharing to keep $X$ stable while changing roster or re‑randomizing shares.

---

## 17. Conclusion

This construction gives PM chains a **seedless**, **publicly verifiable** ratchet that is **controlled by a FROST group** and **independent of which quorum is live**. It removes a class of operational risk (seed custody), strengthens auditability (per‑step proofs), integrates naturally with existing PM tooling, and aligns with the dominant cryptographic ecosystem (secp256k1/BIP‑340). The code base is small and readable, the tests are comprehensive, and the cryptographic surface area is conservative: standard H2C, standard Schnorr‑style DLEQ, and a widely deployed threshold signature suite.

**Pointers (quick index):**

* VRF & proof: `src/lib.rs :: vrf_gamma_and_proof_for_x`, `vrf_verify_for_x`, `dleq_challenge_x`
* PM binding & ratchet: `src/lib.rs :: pm_message`, `key_from_gamma`, `ratchet_state`
* Encodings & normalization: `src/lib.rs :: point_bytes`, `point_from_bytes`, `normalize_secret_to_pubkey`
* PM integration: `tests/pm_integration.rs :: EnhancedMark`, `run_resolution`
* Determinism/roster invariance: `tests/pm_chain.rs :: pm_chain_deterministic_and_roster_invariant`
* Randomness suite: `tests/pm_chain.rs :: pm_chain_nist_randomness_suite`

---

## Appendix A — Glossary of Symbols and Terms

This glossary is written for non‑cryptographers first, while being precise enough for a cryptographer to verify the construction. Where helpful, we point to the exact functions in this repository that implement or use the concept.

### Symbols (points on the curve and scalars)

* **$G$** — The fixed *generator* of the secp256k1 group. All public keys are multiples of $G$.
  *In code:* `ProjectivePoint::GENERATOR`.

* **$x$** — The group’s secret scalar (threshold‑held by the FROST participants). It satisfies $X = x\cdot G$.
  *In tests we reconstruct it only to exercise the math end‑to‑end.*

* **$X$** — The group’s public key point, $X = x\cdot G$.
  *In code:* `pubkey_pkg.verifying_key().to_element()`.

* **$H(m)$** — The *hash‑to‑curve* of a message $m$: a point on secp256k1 derived from a byte string. It is statistically indistinguishable from a random point.
  *In code:* `hash_to_curve(msg)` in `src/lib.rs`.

* **$\Gamma$** (Gamma) — The VRF output point for a step: $\Gamma = x\cdot H(m)$. It is the group‑controlled, secret‑looking point that only holders of $x$ can compute.
  *In code:* returned as `gamma` by `vrf_gamma_and_proof_for_x`.

* **$k$** — A fresh random *proof nonce* scalar used once per DLEQ proof.
  *In code:* drawn via `Scalar::generate_vartime(&mut OsRng)` inside `vrf_gamma_and_proof_for_x`.

* **$A$, $B$** — The proof commitments on bases $G$ and $H(m)$:
  $A = k\cdot G,\quad B = k\cdot H(m)$.
  *In code:* stored as `a_bytes`, `b_bytes` inside `DleqProof`.

* **$e$** — The Fiat–Shamir challenge scalar for the DLEQ proof, computed by hashing a transcript of $(X,\Gamma,A,B)$ plus a domain tag.
  *In code:* `dleq_challenge_x`.

* **$z$** — The DLEQ response: $z = k + e\cdot x$.
  *In code:* stored as `z` inside `DleqProof`.

* **$j$** — Step (sequence) index in the provenance‑mark chain; starts at 0 for genesis in our tests and increments by 1 each mark.

* **$S_j$** — Public *ratchet state* after step $j$. Anyone can compute it from public data:
  $S_j = \mathrm{SHA256}(\text{"PMSTATE-v1"} \,\|\, S_{j-1} \,\|\, \text{key}_j)$.
  *In code:* `ratchet_state`.

* **$\text{key}_j$** — The PM “key” material for step $j$. We define the full 32‑byte key as
  $\text{key}_j = \mathrm{SHA256}(\text{"PMKEY-v1"} \,\|\, \text{compress}(\Gamma_j))$,
  and *store* it in PM truncated to the *resolution’s* link length (4/8/16/32 bytes).
  *In code:* `key_from_gamma` + truncation in tests.

### Core cryptographic terms

* **VRF (Verifiable Random Function)** — A function producing output that *looks random*, yet is *deterministic* for the holder of a secret key and *publicly verifiable* via a proof. Here the VRF output point is $\Gamma = x\cdot H(m)$, and its proof is a DLEQ (see below).
  *In code:* `vrf_gamma_and_proof_for_x` (prover) / `vrf_verify_for_x` (verifier).

* **DLEQ (Discrete Log Equality) proof** — A Chaum–Pedersen proof that the same secret scalar relates two public points with respect to two known bases. We prove
  $\log_G(X) = \log_{H(m)}(\Gamma)$,
  i.e., the $x$ such that $X = x\cdot G$ also satisfies $\Gamma = x\cdot H(m)$.
  *In code:* `DleqProof` (data structure), `vrf_gamma_and_proof_for_x` (create), `vrf_verify_for_x` (check).

* **Fiat–Shamir transform** — A standard way to make an interactive proof (commit–challenge–response) *non‑interactive* by deriving the challenge $e$ with a cryptographic hash over a transcript.
  *In code:* `dleq_challenge_x`.

* **Hash‑to‑curve (H2C)** — A well‑specified, constant‑time method to map arbitrary bytes to a valid group point that is statistically uniform. We use the RustCrypto implementation for secp256k1 (SSWU with XMD\:SHA‑256) with a dedicated domain tag.
  *In code:* `hash_to_curve` (DST `H2C_DST = "FROST-VRF-secp256k1-SHA256-RO"`).

* **Domain Separation Tag (DST)** — A short string included in hash inputs to keep transcripts distinct across protocols/uses. We use separate DSTs for H2C, DLEQ, the PM key derivation, and the PM state ratchet.
  *In code:* `H2C_DST`, `DLEQ_DST`, and the `"PMKEY-v1"`, `"PMSTATE-v1"` prefixes.

* **Schnorr signature** — A simple signature scheme over groups like secp256k1. FROST produces Schnorr signatures in threshold fashion (not used directly in the final VRF path, but the ciphersuite and parity conventions match BIP‑340).

* **Random oracle model (ROM)** — An analysis heuristic where hash functions are treated as ideal random oracles. H2C and Fiat–Shamir are commonly modeled in the ROM.

### FROST and threshold‑cryptography terms

* **FROST** — A two‑round, efficient threshold Schnorr protocol. Any $t$ of $n$ participants holding *shares* of a secret key can jointly produce a signature as if one party holding the key had signed.
  *We use FROST to define the group key $X$ and to justify that only an authorized quorum can produce VRF proofs tied to $x$.*

* **$t$-of‑$n$ quorum** — Any subset of $t$ participants out of the $n$ enrolled members who are sufficient to run the protocol.

* **Trusted dealer / DKG** — Ways to generate and distribute threshold shares. Our tests use a *trusted dealer* (`keys::generate_with_dealer`) for simplicity; a DKG removes the dealer by jointly generating shares.
  *In code (tests):* `dealer_keygen` helpers.

* **Aggregator / Coordinator** — The party collecting commitments and proof shares and assembling the final proof or signature. In production, this role can be rotated or replicated.

### Provenance‑Mark (PM) terms

* **Provenance Mark (PM)** — A short, linkable record used to create chains of provenance. Each mark carriesa `chain_id`, a `key`, a `hash` that commits to the `nextKey`, a sequence number `seq`, a `date`, and an optional, application-defined `info` field.
  *In code (tests):* we use the `provenance-mark` crate directly.

* **Resolution / Link length** — The stored `key`/`nextKey` length in bytes. The four resolutions are **Low** (4), **Medium** (8), **Quartile** (16), **High** (32).
  *In code (tests):* enforced via `.link_length()` and explicit truncation.

* **`chain_id`** — A public, chain‑wide identifier. In tests, we derive it deterministically from $X$ and a label and truncate it to the resolution’s link length.
  *In code (tests):* `make_chain_id`.

* **Public ratchet** — The evolving public state $S_j$ included in the VRF message, ensuring each step depends on all prior steps. No secrets are stored in the ratchet, and it may be produced from other publicly-available data.
  *In code:* `ratchet_state`.

* **EnhancedMark** — A test‑only wrapper pairing a `ProvenanceMark` with the VRF output $\Gamma$ (compressed) and the DLEQ proof fields. It demonstrates what a future `proof` field in PM might contain.
  *In code (tests):* `tests/pm_integration.rs`.

### Implementation & encoding terms

* **secp256k1** — The elliptic curve used by Bitcoin and Taproot; we use the RustCrypto `k256` implementation.

* **`k256`** — Rust crate providing secp256k1 arithmetic and hash‑to‑curve.
  *In code:* dependency `k256 = { features = ["arithmetic", "hash2curve"] }`.

* **`frost-secp256k1-tr`** — Zcash Foundation’s FROST ciphersuite binding for secp256k1 with *Taproot (BIP‑340) semantics*. We adopt it for compatibility with Bitcoin stacks and to inherit BIP‑340 conventions (x‑only keys, even‑Y normalization).
  *In code:* dependency `frost-secp256k1-tr = "2.2.0"`.

* **Taproot / BIP‑340 even‑Y normalization** — A convention where public keys and public nonces are represented using the x‑coordinate with an *even Y* choice. If a reconstructed scalar $x$ produces $x\cdot G = -X$, we flip the sign $x \leftarrow -x$ to match the published $X$.
  *In code:* `normalize_secret_to_pubkey`.

* **SEC1 (compressed) encoding** — Standard 33‑byte point encoding (prefix 0x02 or 0x03 + x‑coordinate).
  *In code:* `point_bytes`, `point_from_bytes`, and ciphersuite `Group::serialize`.

* **ProjectivePoint / AffinePoint** — Two coordinate representations of points on the curve; projective is used for efficient arithmetic, affine for encoding/decoding.
  *In code:* `k256::{ProjectivePoint, AffinePoint}`.

* **SHA‑256** — The 256‑bit cryptographic hash function we use for key derivation, ratcheting, and (via the ciphersuite) challenges.

* **CSPRNG** — Cryptographically secure random number generator; we use the OS RNG (`OsRng`) to sample $k$ in DLEQ proofs.
  *In code:* `rand_core::OsRng`.

* **DST (Domain Separation Tag)** — See above; our constants are `H2C_DST`, `DLEQ_DST`, `"PMKEY-v1"`, `"PMSTATE-v1"`, and the message prefix `"PMVRF-secp256k1-v1"`.

---

### Testing & analysis terms

* **Determinism** — Same inputs ⇒ same outputs. Because $m_j$ depends only on public values and $x$ is fixed, the sequence is reproducible across runs.
  *In code (tests):* `pm_chain_deterministic_and_roster_invariant`.

* **Roster‑invariance** — Any valid $t$-of‑$n$ quorum for the same group key $X$ yields the same next key.
  *In code (tests):* same test as above compares different quorums.

* **NIST SP 800‑22 test suite** — A battery of statistical tests for (pseudo)random bitstreams. We apply it to \~2 M bits generated solely by the seedless VRF ratchet.
  *In code (tests):* `pm_chain_nist_randomness_suite` using the `nistrs` crate.

* **Random Excursions (and Variant)** — Two SP 800‑22 tests that run only if the cumulative ±1 random walk returns to zero often enough (“sufficient cycles”). If preconditions are not met, tests are *skipped*, which is normal and not a failure.

* **Non‑overlapping template test (pass‑rate)** — A family of many subtests; NIST evaluates the *proportion* of passes. Our test allows a small fraction (≤ 2%) of subtests to fall below the α‑threshold to avoid false positives due to multiple testing.

---

### High‑level protocol terms

* **Seedless / PRNG‑free** — There is no per‑chain secret seed and no secret PRNG state. The only secret is the longstanding FROST group key $x$; all per‑step state used to build $m_j$ and ratchet $S_j$ is public and deterministic.

* **Public verifiability** — Anyone can recompute $m_j$ from public inputs $(X, \text{chain\_id}, S_{j-1}, j)$, derive $H(m_j)$, and verify the DLEQ proof over $(X, \Gamma_j)$. No trust in the coordinator is required.

* **Coordinator / Aggregator** — A node that collects participants’ contributions and assembles a proof or signature. The role can be changed or duplicated; it does not need special trust.

* **Genesis** — The initial step (sequence 0). In tests we use a deterministic genesis state $S_0 = \mathrm{SHA256}(\text{"PM‑Genesis"})$ and set `key_0 = chain_id`.

---

### Pointers to code (quick index)

* **VRF + DLEQ (prover/verifier):** `vrf_gamma_and_proof_for_x`, `vrf_verify_for_x` — `src/lib.rs`
* **H2C:** `hash_to_curve` — `src/lib.rs`
* **PM binding & ratchet:** `pm_message`, `key_from_gamma`, `ratchet_state` — `src/lib.rs`
* **Encodings & parity helper:** `point_bytes`, `point_from_bytes`, `normalize_secret_to_pubkey` — `src/lib.rs`
* **PM integration demo:** `EnhancedMark`, `run_resolution` — `tests/pm_integration.rs`
* **Determinism/roster tests:** `pm_chain_deterministic_and_roster_invariant` — `tests/pm_chain.rs`
* **NIST randomness battery:** `pm_chain_nist_randomness_suite` — `tests/pm_chain.rs`
