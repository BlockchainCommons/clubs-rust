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

use anyhow::{anyhow, bail, Result};
use bc_components::{
    Digest, DigestProvider, PublicKeys, SSKRSpec, Signature, SymmetricKey,
};
use bc_envelope::prelude::*;
use bc_components::XID;
use known_values::{
    CONTENT, CONTENT_RAW, HAS_RECIPIENT_RAW, HOLDER, PROVENANCE, PROVENANCE_RAW,
    SIGNED, SIGNED_RAW,
};
use provenance_mark::ProvenanceMark;

/// A public-key permit designating an intended reader and optional annotation.
///
/// The `recipient` receives the wrapped content key for this edition.
#[derive(Clone, Debug, PartialEq)]
pub enum PublicKeyPermit {
    /// Encode variant: used when creating a new edition.
    Encode { recipient: PublicKeys, member_xid: Option<XID> },
    /// Decode variant: used when round-tripping from an existing envelope.
    Decode { sealed: bc_components::SealedMessage, member_xid: Option<XID> },
}

impl PublicKeyPermit {
    pub fn new(recipient: PublicKeys) -> Self {
        PublicKeyPermit::Encode { recipient, member_xid: None }
    }

    pub fn with_member_xid(self, member_xid: XID) -> Self {
        match self {
            PublicKeyPermit::Encode { recipient, .. } => {
                PublicKeyPermit::Encode { recipient, member_xid: Some(member_xid) }
            }
            PublicKeyPermit::Decode { sealed, .. } => {
                PublicKeyPermit::Decode { sealed, member_xid: Some(member_xid) }
            }
        }
    }
}


/// A single edition (revision) of a Club's content.
#[derive(Clone, Debug, PartialEq)]
pub struct Edition {
    /// The Club this edition belongs to.
    pub club: XID,
    /// Provenance mark for ordering and human-readable proof.
    pub provenance: ProvenanceMark,
    /// Plaintext content to be sealed into this edition.
    pub content: Envelope,
    /// Collected signatures on this edition (subject-level signatures by default).
    pub signatures: Vec<Signature>,
    /// Public-key permits attached to the edition.
    pub permits: Vec<PublicKeyPermit>,
}

impl Edition {
    /// Create a new Edition for a Club with plaintext content and a provenance mark.
    pub fn new(club: XID, provenance: ProvenanceMark, content: Envelope) -> Self {
        Self { club, provenance, content, signatures: Vec::new(), permits: Vec::new() }
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
        let mut e = e.add_assertion(CONTENT, self.content.clone());
        // Include any stored signatures.
        for sig in &self.signatures {
            e = e.add_assertion(SIGNED, sig.clone());
        }
        // Include decode-variant permits to maintain idempotence.
        for permit in &self.permits {
            if let PublicKeyPermit::Decode { sealed, member_xid } = permit {
                let mut assertion = Envelope::new_assertion(known_values::HAS_RECIPIENT, sealed.clone());
                if let Some(xid) = member_xid {
                    assertion = assertion.add_assertion(HOLDER, *xid);
                }
                e = e.add_assertion_envelope(assertion).unwrap();
            }
        }
        e
    }

    /// Compute a stable digest for identifying this edition's public metadata
    /// before sealing content. Useful for binding permits (AAD).
    pub fn provisional_id(&self) -> Digest {
        self.to_unsigned_envelope().digest().into_owned()
    }

    /// Seal the content with optional permits (public-key and/or SSKR), and sign.
    ///
    /// - If no permits are provided, the content remains plaintext but the
    ///   edition is still signed.
    /// - If public-key recipients are provided, wraps+encrypts the content and
    ///   adds `hasRecipient` assertions bound to the edition digest via AAD.
    /// - If `sskr_spec` is provided, splits the same content key and returns
    ///   share envelopes.
    pub fn seal_with_permits(
        &self,
        recipients: &[PublicKeyPermit],
        sskr_spec: Option<SSKRSpec>,
        signer: &dyn bc_components::Signer,
        signing_options: Option<bc_components::SigningOptions>,
    ) -> Result<(Envelope, Option<Vec<Vec<Envelope>>>)> {
        // Fresh content key per edition.
        let content_key = SymmetricKey::new();
        let do_encrypt = !recipients.is_empty() || sskr_spec.is_some();

        // Build base envelope with provenance.
        let mut edition = Envelope::new(self.club)
            .add_assertion(PROVENANCE, self.provenance.clone());

        let mut sskr_shares: Option<Vec<Vec<Envelope>>> = None;

        if do_encrypt {
            let encrypted_content = self.content.encrypt(&content_key);
            edition = edition.add_assertion(CONTENT, encrypted_content.clone());

            // Compute edition-id for AAD binding of permits.
            let edition_id_aad: Vec<u8> = edition.digest().data().to_vec();

            for pkp in recipients {
                match pkp {
                    PublicKeyPermit::Encode { recipient, member_xid } => {
                        let sealed = bc_components::SealedMessage::new_with_aad(
                            content_key.to_cbor_data(),
                            recipient,
                            Some(edition_id_aad.as_slice()),
                        );
                        let mut assertion =
                            Envelope::new_assertion(known_values::HAS_RECIPIENT, sealed);
                        if let Some(xid) = member_xid {
                            assertion = assertion.add_assertion(HOLDER, *xid);
                        }
                        edition = edition.add_assertion_envelope(assertion)?;
                    }
                    PublicKeyPermit::Decode { .. } => {
                        bail!("Cannot use decode permit when sealing a new edition");
                    }
                }
            }

            if let Some(spec) = sskr_spec.as_ref() {
                sskr_shares = Some(encrypted_content.sskr_split(spec, &content_key)?);
            }
        } else {
            // Leave content plaintext.
            edition = edition.add_assertion(CONTENT, self.content.clone());
        }

        let signed = edition.add_signature_opt(signer, signing_options, None);
        Ok((signed, sskr_shares))
    }
}

/// Helpers to construct typical permit metadata entries.
pub mod permit {
    use super::*;

    /// Build a permit for a recipient with optional member XID annotation.
    pub fn for_member(member_xid: XID, public_keys: &PublicKeys) -> PublicKeyPermit {
        PublicKeyPermit::new(public_keys.clone()).with_member_xid(member_xid)
    }

    /// Build a permit for a recipient without annotation.
    pub fn for_recipient(public_keys: &PublicKeys) -> PublicKeyPermit {
        PublicKeyPermit::new(public_keys.clone())
    }
}

// EnvelopeEncodable via Into<Envelope>
impl From<Edition> for Envelope {
    fn from(value: Edition) -> Self { value.to_unsigned_envelope() }
}

// EnvelopeDecodable via TryFrom<Envelope>
impl TryFrom<Envelope> for Edition {
    type Error = anyhow::Error;

    fn try_from(envelope: Envelope) -> Result<Self> {
        // Subject must be the club XID
        let club: XID = envelope.subject().try_leaf()?.try_into()?;

        let mut provenance: Option<ProvenanceMark> = None;
        let mut content: Option<Envelope> = None;
        let mut signatures: Vec<Signature> = Vec::new();
        let mut permits: Vec<PublicKeyPermit> = Vec::new();

        for assertion in envelope.assertions() {
            let pred = assertion.try_predicate()?.try_known_value()?.value();
            let obj = assertion.try_object()?;
            match pred {
                PROVENANCE_RAW => {
                    if provenance.is_some() {
                        return Err(anyhow!("Multiple provenance marks"));
                    }
                    provenance = Some(ProvenanceMark::try_from(obj.clone())?);
                }
                CONTENT_RAW => {
                    if content.is_some() {
                        return Err(anyhow!("Multiple content assertions"));
                    }
                    // Object is an Envelope; clone it.
                    content = Some(obj.clone());
                }
                SIGNED_RAW => {
                    if !obj.is_obscured() {
                        let sig = obj.extract_subject::<Signature>()?;
                        signatures.push(sig);
                    }
                }
                HAS_RECIPIENT_RAW => {
                    // Decode permit: extract sealed message and optional holder XID.
                    if !obj.is_obscured() {
                        let sealed = obj.extract_subject::<bc_components::SealedMessage>()?;
                        // Find optional holder assertion(s) on the permit assertion envelope.
                        let holder_xid: Option<XID> = match assertion
                            .optional_assertion_with_predicate(HOLDER)?
                        {
                            Some(holder_assertion) => {
                                let holder_obj = holder_assertion.try_object()?;
                                let xid: XID = holder_obj.try_leaf()?.try_into()?;
                                Some(xid)
                            }
                            None => None,
                        };
                        // Push permit with optional holder
                        let p = PublicKeyPermit::Decode { sealed, member_xid: holder_xid };
                        permits.push(p);
                    }
                }
                _ => return Err(anyhow!("Unexpected predicate in Edition envelope")),
            }
        }

        let provenance = provenance.ok_or_else(|| anyhow!("Missing provenance"))?;
        let content = content.ok_or_else(|| anyhow!("Missing content"))?;

        Ok(Edition { club, provenance, content, signatures, permits })
    }
}
