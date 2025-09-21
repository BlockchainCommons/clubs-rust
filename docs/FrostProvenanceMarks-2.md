# FROST-Controlled Provenance Marks — A Fresh Look

_Updating and expanding on the original “FrostProvenanceMarks” memo, this
document explains how Blockchain Commons’ Gordian Clubs use threshold VRFs to
publish seedless, verifiable provenance mark (PM) chains. We aim to serve two
audiences simultaneously:_

- _Builders and editors who want an intuitive story they can relay to
  colleagues and stakeholders._
- _Cryptographers and protocol implementers who need a crisp description of the
  math, the trust model, and the new Rust implementation inside `clubs/`._

## 1. Executive Summary

Provenance marks are append-only chains of short secrets. Each mark publishes:

1. the **previous link’s secret**, proving you really knew it;
2. the **next link’s secret**, which only the legitimate controller can know in
   advance; and
3. human-friendly metadata (timestamp, sequence number, resolution).

Traditionally, a single “seedholder” owns a private seed and derives each new
secret by running a PRNG. FROST-controlled marks replace that single point of
control with a **threshold Schnorr** group that collectively evaluates a
verifiable random function (VRF) on public data. Any quorum of size _t_ out of
_n_ can advance the chain, and every observer can still check that the new link
came from the registered group key.

## 2. Why Replace Seeds With FROST?

### 2.1 Problems With Seeds

- **Custody friction**: one person must guard the PRNG seed; hardware security
  modules and backups complicate operations.
- **Single point of failure**: compromise or loss of the seed means the entire
  chain is suspect.
- **Poor group dynamics**: coordinating multiple editors requires out-of-band
  trust models, e.g., signing a mark and hoping teammates accept it.

### 2.2 Threshold VRF Advantages

- **Roster invariance**: as long as a quorum is live, you get the *same* next
  key, no matter which specific members sign.
- **Public verifiability**: outsiders can watch the chain advance without
  contacting the group or believing anecdotes.
- **Seedless operations**: the only long-term secret is the FROST signing key
  material, already managed for other edition-signing duties.

## 3. Intuition for Non-Cryptographers

A provenance mark is like a club ledger where each entry reveals the password
for the previous entry and slips a new sealed password for the next one. If you
trust entry `N`, you immediately trust `N+1` because it reveals the password you
were expecting.

With FROST, instead of having one person hold the password generator, a quorum
of members pushes a **collective button**. They all see the same public message
(which includes the chain identifier, a “ratchet” of prior history, and the next
counter). Each member contributes a share; the combination produces a new secret
password and an optional receipt that anyone can check.

Verifiers keep a copy of the chain state. When they receive a candidate new mark
they ask three questions:

1. Does this mark reveal the previous password exactly?
2. Is its metadata (sequence, date) non-conflicting with what I already know?
3. If a proof is attached (or the mark is co-signed), does it validate against
   the group’s public key?

If the answers are “yes,” the verifier updates their local state—now trusting
the new link.

## 4. Formal Construction

We use the FROST ciphersuite `frost-secp256k1-tr` and RustCrypto’s `k256`
implementation. The following notation echoes the original paper but adapts it
to our module layout:

- Let `G` be the generator of secp256k1 and `x` the group’s aggregated private
  scalar (`X = x·G` the public key).
- Each step `j` builds a public message `m_j = pm_message(X, chain_id, S_{j-1},
  j)`. Internally we SHA-256 domain-separate the tuple and hash `m_j` onto the
  curve with SSWU (`H_j = H2C(m_j)`).
- The group runs a two-round FROST ceremony to obtain:
  - commitments (`R_i`) for each participant,
  - the aggregated nonce `R`,
  - the VRF output `Γ_j = x · H_j`,
  - and the DLEQ proof `π_j` (Chaum–Pedersen variant) tying `(X, Γ_j)`.
- The next link appears as `key_j = SHA256(compress(Γ_j))`, truncated to the
  configured resolution (4/8/16/32 bytes). We call the untruncated 32-byte hash
  the **expanded key**.
- The ratchet state updates deterministically: `S_j = SHA256(S_{j-1} ||
  expand(key_j))`.

Publishing the mark involves serialising the metadata, the revealed previous
link (which equals `key_{j-1}`), and the newly derived `key_j`. Optionally we
attach `Γ_j` and `π_j`—see §6.

## 5. Implementation in `clubs`

The new code lives under `clubs/src/frost/pm/` and reuses the existing FROST
infrastructure under `clubs/src/frost/signing/`.

### 5.1 Key Types

- `FrostGroup` wraps the FROST public key package, identifier map, and helper
  methods such as `lagrange_coefficients`.
- `FrostPmParticipant` (in `pm/participant.rs`) extends a participant core with
  VRF-specific rounds (`round1_commit`, `round2_emit_gamma`, `finalize_response`).
- `FrostPmCoordinator` (in `pm/coordinator.rs`) orchestrates commitments,
  gamma shares, challenges, and responses before emitting `(Γ, π)`.
- `FrostProvenanceChain` (in `pm/state.rs`) maintains local chain state and
  performs verification through `verify_advance`.

### 5.2 Ceremony Workflow

1. **Next message**: the publisher asks `FrostProvenanceChain::next_message()`
   for `(step, message_bytes, H_j)`.
2. **Round 1**: each participating member calls
   `FrostPmParticipant::round1_commit()` to send commitments to the coordinator.
3. **Round 2 (Gamma)**: after constructing a signing package, participants emit
   `GammaShare`s via `round2_emit_gamma()`.
4. **Challenge & response**: the coordinator aggregates the shares, derives the
   challenge, and participants answer with `finalize_response()`.
5. **Finalize**: the coordinator returns `(Γ_j, π_j)`. The publisher hashes to
   `key_j`, constructs a `ProvenanceMark`, and (optionally) ships the proof
   alongside the mark.
6. **Verification**: any observer calls `FrostProvenanceChain::verify_advance()`
   with the candidate mark, gamma bytes, and proof. Passing this check updates
   the chain state locally.

### 5.3 Integration Pointers

- The signing (write) path now exports `FrostSigningCoordinator` from
  `frost/signing/`, leaving provenance logic fully decoupled.
- Tests live in `clubs/tests/frost_provenance.rs` and build an end-to-end story
  (Alice/Bob/Charlie) across multiple quorums.

## 6. Publishing Options: Proofs, Signatures, and Minimal Marks

Our design recognises three disclosure strategies, each with different trust and
bandwidth trade-offs:

1. **Minimal marks (no proof/signature)**: You publish only the traditional
   fields. This keeps the format byte-for-byte identical to the seed-based
   version and hides the presence of a threshold ceremony. Readers must trust
   the channel that delivers the marks or rely on reputational sampling across
   nodes.
2. **Marks + threshold signature**: The FROST quorum also signs the mark using
   the existing signing pipeline. This authenticates the mark but doesn’t prove
   the VRF derived from the same key material. Suitable when the mark will be
   embedded in larger signed artifacts (editions, minutes, etc.).
3. **Marks + DLEQ proof (`Γ`, `π`)**: Full public verifiability. Any observer
   can confirm the mark’s key matches the VRF output tied to the group public
  key—no extra infrastructure required.

Because each mark already reveals the previous key, attaching a proof is not
strictly necessary for internal operations. It becomes valuable when you want
third parties (auditors, mirrored ledgers, future historians) to validate the
chain without trusting today’s distributor.

## 7. Security Considerations

- **Quorum compromise**: FROST security reduces to the assumption that fewer
  than _t_ participants are compromised at any time. A compromised quorum can
  advance the chain arbitrarily, just like a leaked seed in the traditional
  model.
- **Replay / fork attacks**: Without proofs or signatures, adversaries could
  replay previously published keys with altered metadata. Verifiers should
  either require a proof/signature or validate the mark through multiple trusted
  gossip peers.
- **Ratchet continuity**: The `ratchet_state` binds each step to all previous
  steps. Verifiers that skip ahead can always recompute the ratchet by replaying
  the marks in order.
- **Confidentiality**: The VRF output is pseudorandom; the truncated keys
  disclose nothing beyond the resolution needed for linking marks.

## 8. Operational Models

### 8.1 Decentralised Mirrors

Clubs or councils may appoint independent observers to mirror chains. Each
observer runs `FrostProvenanceChain::verify_advance()` upon receiving a new mark
plus its proof/signature. Sampling a few mirrors provides high confidence the
chain hasn’t forked.

### 8.2 Real-Time Consensus

For low-latency or resource-constrained settings, the quorum can omit proofs and
simply publish minimal marks, relying on synchronous communication among trusted
participants. Later, they may publish aggregated proofs or signatures for audit
purposes.

### 8.3 Hybrid Seed and Threshold Deployments

Some groups may operate both seeded and FROST-controlled chains. Because our
minimal mark format is unchanged, they can keep the chains indistinguishable when
desired. When public verifiability matters, they add either signatures or proofs
per section §6.

## 9. Appendix: Function Map

- `pm/primitives.rs` — hash-to-curve (`hash_to_curve`), proof helpers
  (`vrf_verify_for_x`, `key_from_gamma`, `ratchet_state`, `point_bytes`).
- `pm/participant.rs` — participant rounds for the VRF ceremony.
- `pm/coordinator.rs` — aggregator logic producing `(Γ, π)`.
- `pm/state.rs` — `FrostProvenanceChain` bookkeeping and verification.
- `tests/frost_provenance.rs` — integration tests demonstrating determinism and
  quorum-agnostic operation.

## 10. Further Work

- **Verifier utilities**: expose standalone helpers so external tools can check
  marks without instantiating `FrostProvenanceChain`.
- **Edition adapters**: integrate FROST-controlled marks into the edition
  publishing workflow while retaining backward compatibility.
- **Seeded VRF proofs**: explore optional proofs for classic seedholders to
  make seeded and threshold chains uniform from a verifier’s perspective.

---

_Feedback welcome. File issues or PRs in the `bc-rust` repository and tag the
clubs maintainers if you’d like to refine this document further._
