# Gordian Clubs (`clubs`)

`clubs` is the Rust implementation of Blockchain Commons’ Gordian Clubs. It defines the data structures and helpers used to compose, seal, and verify club editions that are distributed as [Gordian Envelopes][env]. The crate is developed inside the broader [`bc-rust` workspace][bc-rust] and has **not** been published to crates.io. To experiment with it you must build from this repository (or a fork) directly.

## Status & scope

- ✳️ **Crate availability** – unpublished; intended for consumers that check out the workspace via git.
- 🧱 **Core focus** – single-publisher clubs that ship encrypted content to members using public-key permits and/or SSKR shards.
- 🧪 **Experimental FROST support** – the `frost/` module contains utilities for threshold Schnorr ceremonies used during provenance and signing research. The APIs will evolve.

## Building & testing

```bash
# Run clippy on just this crate
cargo clippy -p clubs --all-targets

# Execute the edition-focused tests
cargo test -p clubs
```

## Relationship to `clubs-cli`

The companion `clubs-cli` crate (also unpublished) consumes these APIs to provide a command line interface. The CLI scripts in that directory serve as living examples for how to assemble editions, advance provenance, and validate continuity using the types defined here.

## Getting started

1. Clone the [`bc-rust` workspace][bc-rust] (or ensure it is available as a sibling directory when working inside other repositories).
2. Explore the tests under `clubs/tests/` for end-to-end examples combining permits, SSKR, and provenance.

Feedback, bug reports, and contributions are welcome via GitHub issues and pull requests. When contributing code please follow the instructions in the repository’s `AGENTS.md` files.
