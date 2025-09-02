//! Edition: a signed, per-revision package of a Club's content.
//!
//! This file provides a sketch of an Edition type and helpers to
//! construct an edition envelope with:
//! - Public metadata: club XID, provenance mark
//! - Encrypted content: symmetric key per-edition
//! - Public-key permits: a `hasRecipient: SealedMessage` for each reader, optionally
//!   annotated with the member XID
//!
//! Notes
//! - This is a sketch: error paths, validation, and parsing are intentionally
//!   minimal and will evolve with the Club model.
//! - Permit types beyond public-key (password, SSKR, etc.) are not modeled yet.
//! - Write-group/threshold signing is represented via simple add-signature helpers.

use anyhow::Result;
use bc_components::{Digest, DigestProvider, PublicKeys, SymmetricKey};
use bc_envelope::prelude::*;
use bc_components::XID;
use known_values::{CONTENT, HOLDER, PROVENANCE};
use provenance_mark::ProvenanceMark;

/// Minimal metadata for a public-key permit (reader).
///
/// The `sealed` message encrypts this edition's content key `k` to the
/// recipient's public key. We optionally annotate the assertion with
/// the member's XID and the public key reference to aid discovery.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicKeyPermitMeta {
    /// The member's XID (identity handle).
    pub member_xid: Option<XID>,
    // Additional annotations can be added in the future (YAGNI for key_ref)
}

impl PublicKeyPermitMeta {
    pub fn new(member_xid: Option<XID>) -> Self {
        Self { member_xid }
    }
}

/// A single edition (revision) of a Club's content.
#[derive(Clone, Debug)]
pub struct Edition {
    /// The Club this edition belongs to.
    pub club: XID,
    /// Provenance mark for ordering and human-readable proof.
    pub provenance: ProvenanceMark,
    /// Plaintext content to be sealed into this edition.
    pub content: Envelope,
}

impl Edition {
    /// Create a new Edition for a Club with plaintext content and a provenance mark.
    pub fn new(club: XID, provenance: ProvenanceMark, content: Envelope) -> Self {
        Self { club, provenance, content }
    }

    /// Build the unsigned, unsealed public metadata envelope for this edition.
    ///
    /// Subject: Club `XID`
    /// Assertions: `provenance` and `content` (plaintext)
    pub fn to_unsigned_envelope(&self) -> Envelope {
        let mut e = Envelope::new(self.club);

        e = e.add_assertion(PROVENANCE, self.provenance.clone());

        // Include plaintext content (helpful for pre-seal transforms). Consumers
        // should use the sealed variant for distribution.
        e.add_assertion(CONTENT, self.content.clone())
    }

    /// Compute a stable digest for identifying this edition's public metadata
    /// before sealing content. Useful for binding permits (AAD).
    pub fn provisional_id(&self) -> Digest {
        self.to_unsigned_envelope().digest().into_owned()
    }

    /// Seal the content with a fresh per-edition symmetric key `k`, and attach
    /// public-key permits for each intended reader.
    ///
    /// - Binds permits to this edition via Additional Authenticated Data (AAD)
    ///   when constructing the `SealedMessage`.
    /// - Each permit can optionally carry `member_xid` annotation.
    pub fn seal_with_public_key_permits(
        &self,
        recipients: &[(PublicKeys, PublicKeyPermitMeta)],
    ) -> Result<Envelope> {
        // Fresh content key per edition.
        let content_key = SymmetricKey::new();

        // Encrypt the entire content envelope (wrap + encrypt).
        let encrypted_content = self.content.encrypt(&content_key);

        // Prepare the unsigned public metadata (club, provenance, etc.).
        // Replace plaintext with encrypted content.
        let mut edition = Envelope::new(self.club)
            .add_assertion(PROVENANCE, self.provenance.clone())
            .add_assertion(CONTENT, encrypted_content);

        // Compute an edition-id for AAD binding of permits.
        let edition_id = edition.digest().into_owned();
        let edition_id_aad: Vec<u8> = edition_id.data().to_vec();

        // Attach a permit for each recipient.
        for (pubkeys, meta) in recipients {
            // Bind AAD to edition id to unambiguously tie the wrap to this edition.
            let sealed = bc_components::SealedMessage::new_with_aad(
                content_key.to_cbor_data(),
                pubkeys,
                Some(edition_id_aad.as_slice()),
            );

            // Compose the assertion envelope: 'hasRecipient': SealedMessage
            let mut assertion = Envelope::new_assertion(known_values::HAS_RECIPIENT, sealed);

            // Optional annotations: 'holder': XID
            if let Some(xid) = meta.member_xid {
                assertion = assertion.add_assertion(HOLDER, xid);
            }

            edition = edition.add_assertion_envelope(assertion)?;
        }

        Ok(edition)
    }

    /// Convenience: seal with permits and then add a signature from the write group key.
    pub fn seal_and_sign(
        &self,
        recipients: &[(PublicKeys, PublicKeyPermitMeta)],
        signer: &dyn bc_components::Signer,
        signing_options: Option<bc_components::SigningOptions>,
    ) -> Result<Envelope> {
        let sealed = self.seal_with_public_key_permits(recipients)?;
        Ok(sealed.add_signature_opt(signer, signing_options, None))
    }
}

/// Helpers to construct typical permit metadata entries.
pub mod permit {
    use super::*;

    /// Build metadata using member XID.
    pub fn meta_for(member_xid: XID, _public_keys: &PublicKeys) -> PublicKeyPermitMeta {
        let _ = _public_keys; // placeholder; kept for call-site symmetry
        PublicKeyPermitMeta::new(Some(member_xid))
    }

    /// Build metadata using only member XID.
    pub fn meta_with_member(member_xid: XID) -> PublicKeyPermitMeta {
        PublicKeyPermitMeta::new(Some(member_xid))
    }
}
