---
title: "Musings of a Trust Architect: Gordian Clubs - From Xanadu's Dream to Cryptographic Reality"
date: 2025-08-22
draft: true
tags:
  - Musings
  - Trust Architecture
  - Cryptography
  - Decentralization
  - Xanadu
  - Gordian Envelope
  - History
  - Access Control
  - Collaboration
categories:
  - article
author: "Christopher Allen"
author_profile: true
excerpt: "A 32-year journey from Ted Nelson's administrative clubs to cryptographic reality - how modern cryptography finally enables the decentralized access control we've dreamed of since Xanadu."
---

# Musings of a Trust Architect: Gordian Clubs - From Xanadu's Dream to Cryptographic Reality

> _**Musings of a Trust Architect** is my occasional blog series where I share deeper thoughts about digital trust, human dignity, and the architecture of collaboration. These posts reflect my evolving understanding of how we can build systems that enhance rather than diminish human agency._

## From Administrative Fiat to Cryptographic Proof

In the early 1990s, I encountered Ted Nelson's Xanadu project and its innovative "Club System" for managing permissions in a global hypertext network. The concept was revolutionary: groups  could own access rights, manage their own membership, and even include other clubs as members.

It was elegant, recursive, and... ultimately doomed by its reliance on administrative controls and trusted servers.

I was not a member of the Xanadu core architecture team, but I remember proposing at the time that we could transform this system to use pure cryptography instead of centralized administrative controls. The admins' response was positive, but they ultimately passed on the idea: RSA was too slow, the patents were too restrictive, and some of the cryptographic primitives didn't exist yet. They were right - in 1993.

But I couldn't let go of the idea. I spent years tracking the evolution of cryptographic primitives, watching patents expire, and waiting for the technology to catch up to the vision. When I first saw [Schnorr signatures finally escape patent purgatory](https://www.blockchaincommons.com/musings/Schnorr-Intro/), I knew the time was approaching. Advance—hash trees (fundamental to Gordian Envelope), elliptic curves, and multi-party threshold schemes all brought us even closer.

What I didn't fully grasp in 1993 was that the real innovation wouldn't just be replacing administrators with cryptography, it would be creating truly autonomous systems that need no infrastructure at all. No delay by slow servers. No vulnerability to shutdowns or denial. No phone home. No dependence on continued corporate existence. No censorship. Just pure mathematical objects that encode permissions in their very structure.

Today, 32 years later, that vision is finally achievable. And ironically, it's more necessary than ever.

## The Original Vision: Xanadu's Club System

Ted Nelson's Xanadu, often described as the hypertext system that predated (and arguably inspired) the World Wide Web, faced a fundamental challenge: how do you manage permissions in a global information network?

The Xanadu team's solution came from Mark S. Miller, who invented the Club System as part of his early pioneering work that later led to capability-based security architectures. This system introduced several revolutionary concepts:

- **Clubs as first-class permission holders** - Not just users, but groups themselves could hold and grant access rights
- **Self-referential membership** - Clubs could manage their own membership, creating truly autonomous organizations
- **Inverted hierarchy** - Starting with a "public club" at the root made openness the default, with privacy as the exception
- **Recursive structure** - Clubs could contain other clubs, creating natural hierarchies without requiring delegation chains

This was profound thinking for its time. It modeled how human organizations actually work - through groups, delegation, and collective decision-making. But it had a fatal flaw: it still required trusted administrators and servers.

Miller later came to see an even deeper flaw: despite its innovative structure, it was "in the end still an ACL [access control list] system." Why? Because it checked permissions against identity at access time. You had to prove who you were, then the system checked if "you" were allowed.

True capability security requires that identity be proved through the possession of an unforgeable token. The token IS the permission; no identity check needed. This distinction would prove crucial to my cryptographic reimagining.

## The Missing Pieces Fall Into Place

Xanadu passed on my 1993 vision because we lacked crucial technologies:

* **Fast Public Key Operations**: RSA was too computationally expensive for widespread use. We needed efficient public key schemes.
* **Flexible Cryptographic Tools**: We needed data structures that could support multiple access methods to the same content.
* **Signature Aggregation**: Multiple signatures meant growing data structures. We needed compact proofs of group authorization.
* **Threshold Cryptography**: Single keys create single points of failure. We needed ways for groups to share control.

Over the past decade, the core pieces have  emerged:

- **Mature Encryption** (IETF ChaCha20-Poly1305) offers best practice symmetric encryption
- **Mature Password Derivation Functions** (like Argon2) improve the security of password-based access
- **Schnorr Signatures** (finally unencumbered by patents in 2009) enable efficient signature aggregation and Schnorr adaptor signatures (aka "tweaks")
- **FROST** and **MuSig2** (2019) provide practical aggregated signing, indistinguishable from single-party signatures
- **Gordian Envelope** (2022) offers a flexible structure for nested encryption with multiple access paths

The architecture also supports future enhancements: Bitcoin Taproot demonstrates commitment to Merkle trees using Schnorr adaptor signatures (what Bitcoin calls a "tweak"), suggesting how signatures could commit to envelope hashes. Therefore, the layered Gordian design can support zero-knowledge proofs and scriptless scripts as these technologies mature.

## How Modern Cryptographic Clubs Work

A cryptographic club in 2025 is fundamentally different from Xanadu's administrative version. It's a self-contained digital object with sophisticated access control built in through cryptography rather than policy.

At Blockchain Commons, we've implemented our vision of cryptographic clubs as the **Gordian Club System** - building on our Gordian Envelope specification to create a complete decentralized access control system. While the underlying cryptographic primitives are battle-tested, our specific application to capability-based access control is a proof of concept requiring formal security audit before production use.

## Why Cryptography Changes Everything

In traditional systems, accessing a file means:

1. You send credentials to a server.
2. Server checks its database.
3. Server decides if you're allowed.
4. Server grants or denies access.

These traditional access control lists (ACLs) suffer from a number of fundamental problems:
- No way to prove you have permission without contacting a server
- Administrators with "god mode" who can override any permission
- Ambient authority that grants broad permissions based on who you are, not what you need to do
- Single points of failure when essential servers go down
- Difficulty modeling real-world authorization patterns

But What if permissions weren't stored in a database. What if the capability itself could be the complete proof, requiring no external validation whatsoever?

With cryptographic ("Gordian") clubs:

1. You receive the encrypted club.
2. You apply your cryptographic proof.
3. Math determines if you can decrypt.
4. There is no server, no database, no "asking", no "phone home", just proving.

This transforms the fundamental security model.  In Xanadu's Club System, you authenticated your identity, then the system checked if that identity had permission. In Gordian Clubs, your cryptographic proof, whether a private key or SSKR shares, IS your permission. There's no separate identity to verify, no database to consult. The capability to decrypt is inseparable from the right to access.

The difference between traditional administrative and cryptographic access control is the difference between asking permission and proving permission. It's the difference between "Mother may I?" and mathematical certainty. This finally achieves true capability-based security, addressing Miller's core critique of his original system.

### How Gordian Clubs Differ From Existing Approaches

Existing frameworks such as decentralized identifiers (DIDs), Verifiable Credentials (VCs), and threshold multisig wallets already address parts of the identity and access-control problem space. Gordian Clubs are not meant to replace these systems, but to complement them by occupying a different design point. Their distinguishing feature is autonomy: cryptographic objects that require no infrastructure, servers, or platforms to function.

This design choice ensures resilience in adversarial conditions. Where multisig wallets rely on blockchains, or DIDs often depend on registries, Gordian Clubs continue to function offline, during outages, or across decades of archival. They represent a minimal, infrastructure-free foundation on which richer systems can still be layered if needed.

## The Philosophy of Autonomous Objects

Autonomy is a fundamental design choice in Gordian Clubs: they are **autonomous cryptographic objects** that operate without any external infrastructure. This isn't just a technical decision, it's a philosophical stance that shapes everything about how they work.

Unlike traditional access control systems that require servers, databases, and network connectivity, Gordian Clubs are self-contained. They can be emailed, stored on USB drives, or even printed as QR codes. They work with air-gapped connections, during internet outages, or in censorship-heavy or adversarial environments.

This autonomy comes with trade-offs. You can't have time-based expiration without a trusted time source. You can't check external conditions without oracles. You can't track usage without infrastructure. But what you gain is something more profound: mathematical certainty that doesn't depend on any third party's continued existence, honesty, or availability.

### The Autonomy Balance

Because autonomy is one of the most important design principles of Gordian Clubs, every new feature must be weighed against the risk of introducing external dependencies. Optional infrastructure such as blockchain timestamps or oracles may serve certain use cases, but the core system must remain functional without any outside services. The challenge is knowing when to decline features that would compromise this principle.

This autonomy creates both unique capabilities and inherent constraints:

**What Autonomy Enables:**
- **Unstoppable Access**: No server can be taken down to block access
- **Perfect Privacy**: No logs, no tracking, no surveillance possible
- **Disaster Resilience**: Works during internet outages or infrastructure failures
- **Censorship Resistance**: No authority can revoke mathematical proofs
- **True Ownership**: Control rests with keyholders, not platform operators

**What Autonomy Precludes:**
- **No retroactive revocation**: Cannot revoke access to editions already distributed. Old capabilities still decrypt old content, though new editions can exclude them
- **No time-based expiration**: Without trusted time sources, calendar deadlines cannot be enforced (though VRF-style time delays may eventually help)
- **No external conditions**: "If account balance > X" checks require optional oracles
- **No usage analytics**: Privacy means not knowing who accessed what when
- **Static permissions**: Each edition's rules are immutable once created

For some governance or compliance contexts, these constraints may be unacceptable. Where revocation, expirations, or condition-based access are legally mandated, Gordian Clubs may need to be complemented with optional infrastructure or hybrid models. But for adversarial, archival, or censorship-resistant scenarios, these limitations are in fact strengths.

## Other Features of Gordian Clubs

Gordian Clubs include a number of other innovative features, including progressive trust, differentiated access, and recursive designs.

### The Power of Progressive Trust

Each layer of a Gordian Club tells you just enough to understand what's available and how to gain deeper access. This [Progressive Trust](https://www.lifewithalacrity.com/article/progressive-trust/) design is implemented through Gordian Envelope's elision capabilities:

Consider a collaborative project:
- **Public layer**: "This is the design document for Project Titan. Contact 2 of the 5 committee members for access."
- **Member layer**: Full design specifications and discussion
- **Committee layer**: Security considerations and implementation details

You always know what exists and how to request access, but can't see content you're not authorized for. It's like seeing folder names without being able to open them.

## The Distinction of Read vs Write

One of the most important design decisions for Gordian Clubs is the separation read and write access:

**Read Access** is simply the ability to decrypt and view content. It can be granted through any permit and doesn't require changing the club object itself.

**Write Access** requires additional cryptographic mechanisms:
- A "provenance mark" that provides cryptographic ordering of updates.
- Signatures from the previous edition's write group that prove authorization for the update.
   - An immutable audit trail of all changes created by the provenance marks and signatures.
- Threshold signatures from multiple members to validate new editions.
   - Assurance that content modifications were the result of collective agreement, not just individual access.

This mirrors how collaboration actually works: many people can view a document, but only a few can modify it.

## The Recursive Power of Clubs Within Clubs

The true elegance emerges when clubs reference other clubs. A write club's permissions might itself be defined by another club, creating natural hierarchies without central control. Imagine:

- A **Project Club** whose write access is controlled by a **Governance Club**
- A **Governance Club** whose membership is managed by a **Stakeholder Club**
- A **Stakeholder Club** whose rules are defined by the **Project Charter Club**

Each layer maintains its own access rules, audit trails, and membership criteria. Changes cascade through the system following cryptographic proofs, not administrative fiat. This recursive structure mirrors how real organizations work: through delegation, committees, and hierarchical decision-making, but enforced through mathematics rather than bureaucracy.

## The Anatomy of a Gordian Club

Each club object contains:

1. **Public Metadata**: Information visible to everyone
   - **Always included:**
     - Globally unique identifier (e.g., a decentralized [XID](https://developer.blockchaincommons.com/xid/))
     - Last modification timestamp and provenance proofs
     - Digital signatures proving authenticity
   - **Optionally visible:**
     - The club's name and purpose
     - Instructions for requesting access

2. **Encrypted Content**: The actual data, protected by strong symmetric encryption

3. **Multiple Permits**: Different ways to access the same symmetric decryption key

These permits range from simple (passwords) to sophisticated (threshold schemes), allowing clubs to match security requirements to use cases. New forms of permits continue to emerge as cryptographic capabilities advance.

- **Simple access methods:**
  - "Knock" access — the key is public
  - Shared passwords for the simplest restricted access (valid only for the current edition of a club)
  - Individual member public keys (may grant ongoing access to future editions if not revoked)

- **Intermediate complexity:**
  - Social recovery shares allowing a quorum to offer access to the key to decrypt (valid only for the current edition)

- **Advanced methods:**
  - Aggregated signature schemes (FROST and MuSig2)
  - Thresholds requiring M-of-N members (FROST or MuSig2 with merkle trees)

- **Capability-Based Permits** (emerging):
  - Cryptographic ocaps that delegate specific operations without sharing secrets or keys
  - Members can create sub-capabilities with restricted permissions
  - Capabilities can be threshold-based or conditional on cryptographic proofs
  - Example: "Read this club's content" without granting write access or membership
  - Threshold integration remains an area for future cryptographic research, though single-key prototypes exist today

- **Longer Term:**
  - Future cryptographic zk-proofs, scriptless scripts, VRF timelocks, oracles, business logic, etc.

4. **Flexible Structure**: Clubs can be nested (clubs within clubs with their own access rules) or referenced externally via their unique identifiers, enabling complex organizational structures without rigid hierarchies.

## From Vision to Reality: A 32-Year Journey

The path from Xanadu's administrative clubs to working cryptographic implementations took over three decades and required:

- Advances in cryptographic primitives (Schnorr, threshold signatures)
- The cypherpunk movement's philosophical groundwork
- Practical experience with blockchain systems
- Understanding of real-world collaboration patterns

What started as a hypertext permission system has evolved into a fundamental building block for decentralized digital collaboration. It's a new paradigm that mirrors how human organizations actually function, enforced by mathematics rather than authority.

## A Tool for Human Dignity

At its core, the evolution from administrative to cryptographic clubs is about human dignity. It's about replacing "Mother may I?" with "I can prove I belong." It's about groups making decisions without requiring permission from a higher authority. It's about mathematical certainty replacing administrative whim.

But it's also about choosing resilience over convenience. Every "limitation" of autonomous objects is actually a freedom: freedom from platform lock-in, freedom from surveillance, freedom from censorship. When a dissident's Gmail is shut down, their OAuth tokens become worthless. When a company goes bankrupt, its access control servers go dark. But mathematical proofs endure.

Gordian Clubs embody a radical proposition: that communities can self-organize and self-govern through cryptography alone, without asking permission, without trusted third parties, without infrastructure that can be attacked, corrupted, or shut down. They trade the convenience of centralized control for the dignity of true autonomy.

Ted Nelson's vision of clubs for Xanadu was profound but ahead of its time. Today, we finally have the cryptographic tools to realize that vision - not as Ted imagined it, but perhaps as it was always meant to be: decentralized, resilient, and controlled by communities rather than administrators.

The 32-year journey from vision to reality teaches us patience. Some ideas are worth waiting for. Some dreams just need the right tools to become real.

What follows are appendices that turn some of these generalities into specifics, including some lists of real-world use cases and some more in-depth looks at the Gordian Club technology. Please note that the latter is still raw, and could be based on naïve assumptions. I'm looking for cryptographers to help stress-test some of the ideas and make sure they make sense.

## Appendix I: Real-World Applications

Gordian Clubs aren't just theoretical - they enable new models of collaboration:

### Open Source Projects
- Public documentation with contributor-only design discussions
- Security disclosures that require maintainer consensus to access
- Community decisions enforced by cryptography, not GitHub permissions

### Decentralized Organizations
- Board decisions that require cryptographic quorum
- Treasury access controlled by threshold signatures
- Membership that can't be revoked by any single administrator

### Progressive Trust Networks
- Information revealed in layers as relationships deepen
- Each layer provides instructions for earning deeper access
- Natural progression from public to private information

### When Autonomy Matters Most

The autonomous nature of Gordian Clubs makes them ideal for scenarios where infrastructure can't be trusted:

**Dissidents and Journalists**
- Clubs continue working even if servers are seized
- No access logs for authorities to subpoena
- Can be distributed via sneakernet in censored regions

**Disaster Response**
- Emergency plans accessible without internet
- Medical records available during infrastructure failures
- Coordination documents that survive system outages

**Long-term Archival**
- Academic research accessible decades later
- Legal documents that outlive companies
- Cultural preservation independent of platforms

## Appendix II: Technical Deep Dive

### Two Types of Thresholds for Different Needs

Gordian Clubs support two distinct types of thresholds with different capabilities:

**Secret Sharing Quorums (SSKR - Sharded Secret Key Reconstruction)**: A Blockchain Commons specification where club members hold shards of a symmetric key specific to each edition of the encrypted object. To grant access, existing members simply share their shards with new members. Once a new member collects enough shards (meeting the threshold), they can decrypt that edition using the SSKR permit. This provides flexible, temporary access without changing the club object.

**Signing Threshold Quorums (FROST or MuSig2)**: A club that uses threshold signatures to validate changes and new editions. When updating the club's content or membership rules, a threshold of members must cryptographically sign the new version in a signing ceremony. This ensures no single member can unilaterally modify the club. (A signing ceremony is a coordinated process where multiple parties contribute their signatures to create a valid threshold signature.) XID Documents can include secure communication endpoints, enabling participants to coordinate these ceremonies without revealing their identities or relying on centralized infrastructure.

This dual-threshold design separates access control (who can read) from governance (who can write), making the system both flexible and secure. Each edition of a club has its own symmetric key. Permits provide different ways to access this key - SSKR shards grant one-time access to a specific edition, while public key permits enable ongoing access to future editions as the club evolves.

* **When to use SSKR**: One-time access grants, emergency responses, delegated permissions
* **When to use FROST or MuSig2**: Permanent membership changes, content updates, governance decisions

### Cryptographic Capabilities: Beyond Static Permissions

While SSKR and threshold signatures handle basic access and governance, cryptographic object capabilities (ocaps) add a third dimension: dynamic, delegatable permissions that don't require key sharing or modifying the club.

*Important note: Schnorr adaptor signatures are a mature cryptographic primitive already deployed in production systems like Bitcoin’s Taproot and Lightning Network. Their use for capability-based access control with single-holder keys is a novel but reasonable application that now requires formal security audit before production use. Extending adaptor signatures to multi-party computation protocols such as FROST or MuSig2, or to new key agreement protocols that leverage shared signing material, remains an open research direction. While these threshold-based capabilities are promising, they should be treated as experimental concepts rather than production-ready mechanisms. The discussion here presents them as plausible future directions, not as proven technology.*

**The Two Types of Capabilities**:

1. **Read Capabilities**: Grant access to decrypt and view content
   - Alice can share her decryption ability without sharing keys
   - Uses adaptor signatures to conditionally reveal decryption keys
   - Works only for specific editions
   - Cannot be escalated to write access

  **How Read Capabilities Work (conceptually)** :
    - Alice has access to a club's symmetric secret
    - She creates a mathematical "capability" that locks that secret to Bob's public key
    - Bob proves he owns his private key by solving a cryptographic puzzle
    - Solving it directly enables access to the decryption key without Alice ever sharing it

2. **Write Capabilities**: Grant ability to sign/create new editions
   - Alice can delegate her write authority to Bob temporarily
   - Bob proves he owns his key to exercise the delegated authority
   - The signature proves both Bob's identity AND Alice's delegation
   - Must integrate with the club's provenance chain

  **How Write Capabilities Work (conceptually)**:
    - Alice has write access to a club
    - She creates an adaptor signature that says "whoever completes this can sign on my behalf"
    - The adaptor is locked to Bob's public key - only he can complete it
    - When Bob wants to create a new edition:
      - He completes Alice's adaptor signature (proving he's Bob)
      - This gives him a valid signature from Alice authorizing the new edition
    - The completed signature proves both Bob's identity AND Alice's authorization

This enables powerful patterns:
- **Temporary authority**: Grant contractors write access for specific tasks
- **Audit access**: Give auditors read-only access that can't become write
- **Delegation chains**: Bob can sub-delegate to Carol with further restrictions
- **Cross-system keys**: Use existing SSH/GPG keys (Ed25519 or secp256k1-based) for club access

The beauty is that capabilities work with existing keys—the same SSH key Bob uses for server access can now access Gordian Clubs through capabilities. These aren't theoretical constructs: they build on the same proven Schnorr adaptor signatures used in Bitcoin's Lightning Network and Taproot. _(Note: While Ed25519 keys work, the adaptor protocol overrides their deterministic signature behavior with required randomness.)

### How Capabilities Work (Technical Detail)

For readers familiar with cryptography, here's how both types of capabilities function:

#### Write Capabilities (Delegation of Authority)

**The Concept**:
- Alice has write access (can create new editions)
- She wants to temporarily delegate this to Bob
- Uses adaptor signatures for conditional delegation

**The Mechanism**:
1. Alice creates an adaptor signature:
   - It's an incomplete signature for creating a new edition
   - Cryptographically: Alice creates a Schnorr signature but adds a "tweak" locked to Bob's public key
   - The signature equation is modified: s = r + tweak + H(m)·a where only Bob can derive the tweak
   - Can only be completed by someone who knows private key `b` (Bob)
   - When completed, produces a valid signature from Alice

2. Bob exercises the write capability:
   - Uses his private key `b` to complete Alice's adaptor
   - This produces a valid signature from Alice
   - Attaches this to the new edition he creates

3. Verification:
   - Verifiers see Alice's signature on the new edition
   - The signature is valid, proving Alice authorized it
   - Only Bob could have completed the adaptor to produce this signature

**Why This Works**: The adaptor signature acts as a "conditional signature" - Alice pre-signs the action, but only Bob can complete it. It's simpler than read capabilities because it doesn't need to hide/reveal a secret.

#### Read Capabilities (Delegation of Decryption)

**The Setup**:
- Alice has read access to a Gordian Club (knows symmetric key `k` for current edition)
- Bob has an existing keypair: private key `b`, public key `B = b·G`
- Alice wants to delegate read access to Bob for this edition only

**Creating the Read Capability**:
1. Alice generates a random "adaptor secret" `t`
   - _Note: This randomness is critical. Even when using Ed25519 keys (which normally use deterministic signatures), the adaptor protocol requires fresh randomness for security. This requires overriding Ed25519's deterministic behavior. No changes are required for BIP340 secp256k1 signatures._
2. Alice encrypts the symmetric key: `k_encrypted = k ⊕ hash(t, B, edition_id)`
   - The hash includes Bob's public key and edition ID for binding
3. Alice creates an adaptor signature that:
   - Uses the Schnorr signature structure to hide the secret `t` in the signature completion
   - The incomplete signature is: (R + T, s') where s' = r + H(m)·a (missing the `t` component)
   - Bob completes it by adding: s = s' + t·H(B || R || m)·b
   - Can only be completed by someone who knows private key `b`
   - When completed, reveals the secret `t`
4. The read capability contains: adaptor signature, `k_encrypted`, `T = t·G`, edition_id

**Using the Read Capability**:
1. Bob receives the read capability from Alice
2. Bob completes the adaptor signature using his private key `b`
3. This reveals the secret `t` to Bob (and only Bob)
4. Bob computes: `k = k_encrypted ⊕ hash(t, B, edition_id)`
5. Bob can now decrypt that edition of the club using `k`

**Why Read Capabilities Are More Complex**:
- Write capabilities just need to prove delegation (two signatures)
- Read capabilities must conditionally reveal a secret (the decryption key)
- Adaptor signatures provide this "conditional revelation" property
- This same technique is mature, already enables atomic swaps and Lightning payments

Both types demonstrate the power of capabilities: they transform static permissions into dynamic, delegatable authorities using only cryptographic proofs.

### Dynamic Access Patterns

Cryptographic capabilities enable fluid collaboration patterns impossible with static permissions:

- **Document review**: Reviewers receive read-only capabilities, authors retain write control
- **Medical records**: Patients create capabilities for specific providers without granting permanent access
- **Supply chain**: Each handler gets capabilities for their stage only, creating natural compartmentalization
- **Conditional access**: Capabilities that require multiple parties to activate (threshold capabilities)

#### Cryptographic Maturity Levels

It's important to distinguish between the maturity of different cryptographic components:

**Production Ready**
- **SSKR** for secret sharing (formal security proofs, audited implementations)
- **FROST and MuSig2** for threshold signatures (formal security proofs, audited implementations)

**Requires Formal Security Audit**
- **Gordian Envelope** uses proven implementations for basic cryptography, but requires code audit of its unique elision and permit primitives
- **Schnorr adaptor signatures for single-key capabilities**: a novel application of proven primitives, already mature in Bitcoin contexts (Taproot, Lightning), but not yet audited for use in access control
- **Integration with Gordian Clubs** for read/write access control
- **Delegation constructions** that adapt adaptor signatures to capability-based permissions
- **Combinations of adaptor signatures with FROST/MuSig2**: promising but unproven and awaiting formal security audit

**Research Phase**
- **Threshold-based capability delegation**: plausible extensions of adaptor signatures to multi-party settings, but still unproven
- **Key agreement protocols leveraging FROST/MuSig2 shared key material**: emerging but early, requires formal proofs and audits

**Why This Matters**
Adaptor signatures themselves are well-established and production-tested in Bitcoin systems. However, each new application requires careful analysis. The leap from single-key capabilities (ready for audit) to threshold-based capabilities (still research) is particularly significant and should be treated as experimental until formal security proofs and audits exist.

### Members as XIDs: Decentralized Identity Infrastructure

A critical component of the Gordian Club System is how we identify and manage members. Rather than relying on traditional usernames or static public keys, we leverage eXtensible IDentifiers (XIDs) - another Blockchain Commons specification that provides decentralized, self-sovereign identity management.

XIDs are 32-byte identifiers derived from an "inception key" that serve as the foundation for member identity. But they're much more than just an ID - they resolve to XID Documents (built on Gordian Envelope) that can contain:
- Multiple public keys with different purposes (signing, encryption, authentication)
- Key rotation history
- Delegation capabilities
- Service endpoints (for instance for communications)

Crucially, XID Documents support elision - you can redact parts of the document while still proving its integrity. This means a club member can:
- Reveal only their public key when requesting read access
- Share their signing key only when participating in governance
- Keep communication endpoints private until needed
- Rotate compromised keys without losing their identity or club membership

This integration of XIDs with Gordian Clubs creates a complete decentralized identity and access system where both identities and permissions are cryptographic objects, not database entries.

### Privacy-Preserving Governance

Gordian Clubs offer a choice between privacy and accountability:
- **Privacy-first (FROST)**: Threshold signatures hide which specific members participated - you know a quorum acted, but not who
- **Accountability-first (MuSig2)**: Aggregated signatures can reveal individual participants when needed
- **Collective action** without central coordination either way

*Technical note: The privacy distinction between FROST and MuSig2 lies in their construction. Both create a single signature indistinguishable from any other Schnorr signature, but with FROST you can't identify who signed from the quorum, while MuSig2's key aggregation can be designed to maintain or reveal participant information.*

### Example: A Security Disclosure Club

Imagine a security researcher discovers a vulnerability. They create a Gordian Club containing:
- **Public layer**: "Critical vulnerability in Protocol X. Contact maintainers for access."
- **Encrypted details**: The full vulnerability report
- **Permits**:
  - SSKR permit: 2-of-5 threshold where maintainers hold shards
  - Individual permits: Each maintainer's public key (for direct access)
  - Future permit types: VDF-based time delays (when cryptographically verifiable delays become practical)
  - **Capability permit**: Delegated read access from any maintainer (single-key version)
    - Maintainer creates: "Security researcher's existing SSH key can read"
    - No SSKR shards to share, no permanent membership granted
    - Revocation requires a new edition (see limitations)
    - Future: Threshold capability where k-of-n maintainers must cooperate to create capability

**Granting emergency access**: If an incident responder needs immediate access, any 2 maintainers can share their SSKR shards. The responder gains access without waiting for a new edition.

**Publishing updates**: To add new information or change the disclosure timeline, 4-of-5 maintainers must sign the new edition using FROST. This prevents any single maintainer from suppressing or altering the disclosure.

## Where We Stand Today

The Gordian Club System has implemented the core cryptographic club functionality as a proof of concept, with working code:
- Reference libraries in Rust and Swift with CLI apps to demonstrate functionality
- Nested structures with progressive disclosure
- Multi-permit encryption including passwords, SSKR and public keys for flexible access sharing
- XIDs for decentralized member identity with key rotation
- Separation of read access (via revelation of symmetric secret via a permit) from write authority (via signatures)

What we're building now:
- Single-key cryptographic capabilities using Schnorr adaptor signatures (proof of concept complete, preparing for formal security audit)
- FROST threshold signing for Gordian Envelope (building on our Bitcoin FROST demonstrations)
- User-friendly interfaces for non-technical users
- Integration with existing decentralized identity systems
- Standardization through IETF drafts.

Future research:
- Threshold-based capabilities combining FROST/MuSig2 with adaptor signatures
- Key agreement protocols leveraging shared material from threshold signing ceremonies
- Scriptless scripts for complex authorization logic
- Optional infrastructure for oracles to enable dynamic conditions

As noted above, real-world cryptographic expertise is needed to ensure that many of the ideas make sense. Please drop [me a line](mailto:team@blockchaincommons.com) if you can help.

---

*For deeper technical details on implementing cryptographic clubs using Gordian Envelope, see [link]. For the historical context of Xanadu and hypertext systems, Ted Nelson's "Literary Machines" remains the definitive source.*

---

## Author's Note

*This post synthesizes ideas from multiple sources and decades of work. Special recognition goes to Ted Nelson for inspiring the Xanadu project, Mark S. Miller for the original Club System concept, the cypherpunk community for the ethos and cryptographic foundations, and the Blockchain Commons team for making Gordian Envelope a reality. Any errors in interpretation are mine alone.*

*For technical readers: Key specifications include BCR-2022-002 (Gordian Envelope), BCR-2024-010 (XIDs), BCR-2020-011 (SSKR), and [additional BCRs].*

*Technical note: Cryptographic capabilities leverage Schnorr signature linearity to create delegatable permissions. A capability is essentially a Schnorr adaptor signature that proves the holder owns a specific key without revealing it. This enables permission delegation using existing Ed25519/secp256k1 keys without requiring new infrastructure.*

*Technical note for Ed25519 users: While Ed25519's deterministic signatures are a security feature for normal signing, adaptor signatures require fresh randomness. When using Ed25519 keys with Gordian Clubs, this modification sacrifices one of Ed25519’s primary design benefits (deterministic signing). As such, BIP340-based keys (Schnorr on secp256k1) may be more naturally suited for early implementations, while Ed25519 support should be treated as experimental until carefully audited.*

## Related Musings
- [A Layperson’s Intro to Schnorr](https://www.blockchaincommons.com/musings/Schnorr-Intro/)
- [Previous posts on threshold cryptography]
- [Previous posts on Gordian Envelope]

## Join the Conversation
*How do you see cryptographic clubs being used? What applications am I missing? Find me on [social media] or [community forum].*

## Get Involved

The Gordian Club System is no longer just a vision—it's becoming reality. If you're interested in:
- **Using them**: Try our command-line demo and explore the reference implementation at [link]
- **Building with them**: See our developer guide and join the community at [link]
- **Standardizing them**: Participate in our IETF drafts and specification work at [link]
- **Funding them**: Support Blockchain Commons' ongoing development at [link]

The next 32 years don't have to be about waiting. They can be about building.
