Here’s the workflow that’s implied for **public key permits** in Gordian Clubs:

### 1. Create/Update a Club Edition

* Generate a **fresh symmetric content key** `k` for this edition (each edition rekeys).
* Prepare public metadata (XID, provenance mark/timestamp, signatures) and the encrypted payload (with `k`).

### 2. Resolve Who Should Have Ongoing Read Access

* For each intended reader, **resolve their XID** to obtain the current **public key(s)** appropriate for read access (XIDs can hold multiple keys and rotation history).
* Record the member reference (XID and key fingerprint/ID).

### 3. Make Public-Key Permits (Hybrid Wraps of `k`)

* For each authorized public key, **encrypt/wrap `k` to that key** (standard hybrid/asymmetric wrapping).
* Include each resulting ciphertext as a **public-key permit** in the Envelope, bound to:

  * the member’s XID (identity handle),
  * the specific public key used (fingerprint/ID),
  * the current **edition identifier** (so the wrap is unambiguous to this edition’s `k`).

### 4. Seal the Edition

* The **write club/quorum** signs the new edition (provenance mark + threshold signature, per the “write” path).
* Publish/distribute the self-contained Envelope (no servers, no phone-home).

### 5. Reader Consumption Path

* A recipient opens the Envelope, locates **their** public-key permit (by XID/key ID).
* They use their **private key** to unwrap `k`, then **decrypt** the edition’s content.
* No identity or ACL lookup is required; possession of the private key **is** the capability.

### 6. Ongoing Access Across Editions

* For members who should keep reading **future editions**, **repeat** Step 3 for each new edition:

  * Wrap the new `k` to their (possibly rotated) current public key from their **XID**.
* This yields **ongoing access** “if not revoked,” because each new edition includes a fresh permit for them.

### 7. Revocation & Key Rotation

* **Revocation**: when publishing a **new edition**, simply **omit** a member’s public-key permit; they can’t read the new edition. (Old editions remain readable—no retroactive revocation.)
* **Key rotation**: the member updates keys in their **XID document**; the next edition’s permits target the new key(s). Past editions aren’t migrated unless you republish/rekey.

### 8. Scope & Positioning

* Public-key permits are one of multiple **permit types** (alongside passwords/SSKR/etc.), all of which are just different ways to reveal the same per-edition symmetric key `k`.
* They’re distinct from **capabilities** (adaptor-signature schemes); public-key permits are the straightforward, production-friendly path for ongoing read access without infrastructure.

### 9. Autonomy Constraints (Acknowledged in the Design)

* No server checks, logs, or revocation calls; all proof is **in the object**.
* Time-based expiry or condition-based access require optional, non-core infrastructure; the **core** public-key permit flow stays offline and self-contained.
