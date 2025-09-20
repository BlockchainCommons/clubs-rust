# Overview

For minimal context, read these files:

- clubs/docs/XanaduToReality.md
- clubs/docs/PublicKeyPermits.md
- clubs/docs/FrostProvenanceMarks.md
- clubs/docs/dcbor-draft.md
- clubs/docs/envelope-links.md

Also you will want to explore the APIs in these workspace crates:

- dcbor/
- bc-envelope/
- bc-xid/
- bc-components/
- bc-ur/
- known-values/
- provenance-mark/

Guidelines:

- Run `cargo clippy` and fix any lints before you end each turn.
- DO NOT run `cargo fmt` on the whole workspace. Only format the files you edit.
  - Run `cargo +nightly fmt` only in the crates you are working on.

# Current Task

Finish implementing FROST-controlled provenance marks in the `clubs` crate.

- Make sure you read `clubs/docs/FrostProvenanceMarks.md` for context.
- The reference implementation is in the `frost-vrf-dleq-secp` crate in this workspace.
- We do *not* want to merely copy-paste the code from `frost-vrf-dleq-secp`: this is a new implementation.
- We must use the FROST types already in the `clubs` crate, in `clubs/src/frost/`.
- We are *not* going to use the `EnhancedMark` type: we are implementing FROST-controlled provenance marks that use the existing `ProvenanceMark` type.
- The `info` field of the `ProvenanceMark` will remain unused.
- The `clubs` implementation of FROST-controlled provenance marks will be placed in a new module at `clubs/src/frost/pm/`.
- Write your detailed implementation plan below.

## Implementation Plan for FROST-controlled Provenance Marks

### ✅ Completed
1. **Dependencies & Feature Flags** – Added `k256`, `sha2`, and `rand_core` to `clubs/Cargo.toml` so VRF primitives can live inside the crate.
2. **Module Scaffold** – Created `clubs/src/frost/pm/` with `mod.rs`, `primitives.rs`, `coordinator.rs`, `participant.rs`, and `state.rs`; re-exported the key APIs.
3. **Cryptographic Primitives** – Implemented hash-to-curve, DLEQ proof helpers, key derivation, ratchet, and Taproot parity normalization in `primitives.rs`.
4. **FROST Share Capabilities** – Extended `FrostParticipant` with VRF commitment/response storage and helper methods (`pm_round1_commit`, `pm_round2_emit_gamma`, `pm_finalize_response`).
5. **Coordinator for Provenance Marks** – Added `FrostPmCoordinator` orchestrating commitments, lambda coefficients, aggregated Γ, and challenge/response aggregation.
6. **Chain State & Mark Construction** – Implemented `FrostProvenanceChain` to track chain id, ratchet state, and drive ceremonies via the coordinator, returning `FrostProvenanceAdvance` bundles.

### 🛠️ In Progress / To Do (kept separate from Editions)
7. **Standalone API Surface** – Expose ergonomic wrappers and examples for driving FROST-controlled provenance mark chains as an independent feature (similar to `tests/frost_envelope.rs`), without wiring into Editions yet.
8. **Verification Utilities** – Provide helpers (`verify_mark`, `verify_chain_step`) that consumers can call to validate marks/proofs in this standalone workflow.
9. **Edition Integration (Deferred)** – When ready, bridge the chain output into Edition construction paths; for now, explicitly keep Editions using the existing generator-based provenance until this backlog item is prioritized.
10. **Testing & Documentation** – Author dedicated tests (determinism, roster invariance, VRF proof checks) and write Rustdoc/usage notes for the standalone API once the above pieces are stable.

### 🗂️ Deferred / Backlog
- **Proof-carrying Provenance Marks** – Postpone defining an alternate provenance mark type that stores DLEQ proofs alongside `ProvenanceMark`; revisit once the standalone workflow and Edition integration have settled.

### 🔮 Proposed Next Steps
- `#1` Implement the verification utilities for `FrostProvenanceAdvance` and document sample usage.
- `#2` Add standalone tests mirroring the reference implementation to prove determinism and roster invariance across resolutions.
- `#3` Prepare optional adapters for Edition integration (guarded or feature-flagged) once stakeholders decide to merge the workflows.
- `#4` Expand documentation with end-to-end examples showing how to run a ceremony using `FrostProvenanceChain` in isolation.
