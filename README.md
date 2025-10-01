# Gordian Clubs

`club## Getting started

Add `clubs` to your `Cargo.toml`:

```toml
[dependencies]
clubs = "0.1.0"
```

Explore the tests under `clubs/tests/` in the [source repository](https://github.com/BlockchainCommons/clubs-rust.git) for end-to-end examples combining permits, SSKR, and provenance.

## Version history

- **0.1.0** (October 1, 2025) – Initial release with support for single-publisher clubs, public-key permits, SSKR shards, and experimental FROST utilities.

Feedback, bug reports, and contributions are welcome via GitHub issues and pull requests. When contributing code please follow the instructions in the repository's `AGENTS.md` files.

[bc-rust]: https://github.com/BlockchainCommons/bc-rust
[env]: https://github.com/BlockchainCommons/bc-envelopethe Rust implementation of Blockchain Commons' Gordian Clubs. It defines the data structures and helpers used to compose, seal, and verify club editions that are distributed as [Gordian Envelopes][env].

## Status & scope

- ✳️ **Crate availability** – published on [crates.io](https://crates.io/crates/clubs).
- 🧱 **Core focus** – single-publisher clubs that ship encrypted content to members using public-key permits and/or SSKR shards.
- 🧪 **Experimental FROST support** – the `frost/` module contains utilities for threshold Schnorr ceremonies used during provenance and signing research. The APIs will evolve. Clubs

`clubs` is the Rust implementation of Blockchain Commons’ Gordian Clubs. It defines the data structures and helpers used to compose, seal, and verify club editions that are distributed as [Gordian Envelopes][env]. The crate has **not** yet been published to crates.io. To experiment with it you must build from the repo directly.

## Status & scope

- ✳️ **Crate availability** – unpublished; intended for consumers that check out the workspace via git.
- 🧱 **Core focus** – single-publisher clubs that ship encrypted content to members using public-key permits and/or SSKR shards.
- 🧪 **Experimental FROST support** – the `frost/` module contains utilities for threshold Schnorr ceremonies used during provenance and signing research. The APIs will evolve.

## Relationship to `clubs-cli`

The companion `clubs-cli` crate (also unpublished) consumes these APIs to provide a command line interface. The CLI scripts in that directory serve as living examples for how to assemble editions, advance provenance, and validate continuity using the types defined here.

## Getting started

1. Clone the [`bc-rust` workspace][bc-rust] (or ensure it is available as a sibling directory when working inside other repositories).
2. Explore the tests under `clubs/tests/` for end-to-end examples combining permits, SSKR, and provenance.

Feedback, bug reports, and contributions are welcome via GitHub issues and pull requests. When contributing code please follow the instructions in the repository’s `AGENTS.md` files.
