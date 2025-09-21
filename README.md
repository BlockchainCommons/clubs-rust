# Gordian Clubs (`clubs`)

by Wolf McNally\
Blockchain Commons

The `clubs` crate is the Rust implementation of Blockchain Commons' Gordian Clubs concept. It provides the tooling needed to publish collaborative, cryptographically verifiable editions of club content while keeping read access under the club's control. The crate currently demonstrates three key building blocks:

1. **Edition publishing with multiple permits** - Construct, seal, and sign envelopes that carry encrypted content plus any combination of public-key permits and SSKR share bundles, so different readers can recover the symmetric key for an edition without contacting a server.
2. **FROST group-signed envelopes** - Use the threshold Schnorr implementation under `src/frost/` to orchestrate multi-party signatures over wrapped envelopes, allowing a quorum of club custodians to jointly approve releases.
3. **FROST-controlled provenance mark chains** - Drive verifiable random function ceremonies that advance a provenance-mark ratchet without any single seed holder, ensuring deterministic, roster-invariant audit trails.

The next phase of development will combine these tracks so clubs themselves are controlled by FROST groups, the group-managed provenance chain is embedded in each edition, and the established permit system continues to offer multiple access variants.

## Repository layout

```
clubs/
|-- src/
|   |-- edition.rs           # Edition data model and sealing helpers
|   |-- public_key_permit.rs # Permit encoding/decoding logic
|   `-- frost/               # FROST signing and provenance mark modules
|-- tests/
|   |-- basic_scenario.rs    # End-to-end example with permits and SSKR
|   |-- frost_provenance.rs
|   `-- frost_provenance_randomness.rs
`-- docs/                    # Design notes and background material
```

Key supporting crates live at the workspace root (`bc-envelope`, `bc-xid`, `provenance-mark`, etc.) and are referenced throughout the code.

## Building and testing

```bash
# Format only the files you edit (nightly rustfmt is required for envelope CST)
cargo +nightly fmt -- src/edition.rs tests/basic_scenario.rs

# Lint the crate
cargo clippy -p clubs

# Run targeted tests
cargo test -p clubs basic_scenario
# (Optional) run the full test suite for provenance mark workflows
cargo test -p clubs --tests
```

The `basic_scenario` test is a good starting point: it assembles a club edition, generates public-key permits for three members, adds an SSKR 2-of-3 share set, signs the envelope, and proves the edition can be unsealed, decrypted, and round-tripped.

## Usage highlights

- **Edition sealing** (`Edition::seal_with_permits`) produces a signed envelope whose subject is the wrapped or encrypted content. It asserts the club's XID and provenance mark, then adds any recipient permits (public keys or SSKR).
- **Edition unsealing** (`Edition::unseal`) verifies the club's signature and converts the envelope back into an `Edition` struct.
- **Provenance chains** (`frost::pm`) expose `FrostProvenanceChain` for driving ceremonies and helpers for verifying VRF outputs and DLEQ proofs.
- **FROST signing** (`frost::signing`) includes coordinator and participant logic for general-purpose threshold Schnorr signatures.

## Roadmap

The crate already proves out each subsystem independently. Ongoing work will focus on integrating them into a cohesive workflow:

1. **FROST-controlled clubs** - Require a quorum of club members to sign every edition via the existing threshold infrastructure.
2. **Embedded provenance** - Advance the provenance mark ratchet with the same FROST ceremony and bind the resulting mark into each edition.
3. **Unified permit issuance** - Ensure all reader permit styles continue to work seamlessly after the FROST integration, including future variants such as time-delayed or capability-based permits.

## Further reading

- [FrostProvenanceMarks](docs/FrostProvenanceMarks.md) and [FrostProvenanceMarks-2](docs/FrostProvenanceMarks-2.md) - deep dives into the VRF-based provenance design.
- [PublicKeyPermits](docs/PublicKeyPermits.md) - the permit workflow for sharing per-edition symmetric keys.
- [XanaduToReality](docs/XanaduToReality.md) - historical and architectural context for Gordian Clubs.

Questions, issues, or contributions are welcome via the Blockchain Commons repositories. Please follow the coding guidelines in `AGENTS.md` when working on this crate.
