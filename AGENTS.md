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

## Current Task

Plan the new `clubs-cli` tool. Write your detailed plan below these specs.

- The tool will first focus on single-publisher clubs.
- XID documents needed for clubs can be created using the `envelope-cli` tool, so we do not need to duplicate that functionality.
- The tool will allow anyone with a XID document to initialize a club by creating a first `Edition` containing a genesis `ProvenanceMark`.
- The `provenance-mark-cli` tool will be used to generate the next marks in the chain, so we do not need to duplicate that functionality.
- The `envelope-cli` tool will be used to create the `content` envelope that will be the subject of the next `Edition`, so we do not need to duplicate that functionality.
- The `clubs-cli` tool will compose the next `Edition` by optionally encrypting the `content` envelope, creating the `Edition` struct, adding permits as specified (public key permits and SSKR permits), and signing it with the publisher's private key contained in the XID document.
- All inputs and outputs will be URs. See the `bc-ur` crate and the numerous types in this workspace including `Envelope` that support UR encoding and decoding.

Explore the workspace thoroughly, including our CLI, tools so you understand our existing capabilities and style.

## `clubs-cli` Development Plan

The CLI development roadmap now lives in `../clubs-cli/AGENTS.md`.
