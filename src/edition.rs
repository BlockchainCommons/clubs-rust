//! Edition: a signed, per-revision package of a Club's content.
//!
//! This file provides a sketch of an Edition type and helpers to
//! construct an edition envelope with:
//! - Public metadata: club XID, provenance mark
//! - Encrypted content: symmetric key per-edition
//! - Public-key permits: a `hasRecipient: SealedMessage` for each reader,
//!   optionally annotated with the member XID
//!
//! Notes
//! - This is a sketch: error paths, validation, and parsing are intentionally
//!   minimal and will evolve with the Club model.
//! - Permit types beyond public-key (password, SSKR, etc.) are not modeled yet.
//! - Write-group/threshold signing is represented via simple add-signature
//!   helpers.

use crate::public_key_permit::PublicKeyPermit;
use crate::{Error, Result};
use bc_components::{
    Digest, DigestProvider, SSKRSpec, SealedMessage, Signature, Signer,
    SymmetricKey, XID,
};
use bc_envelope::prelude::*;
use known_values::{
    CONTENT, CONTENT_RAW, HAS_RECIPIENT_RAW, HOLDER, IS_A_RAW, PROVENANCE,
    PROVENANCE_RAW, SIGNED, SIGNED_RAW,
};
use provenance_mark::ProvenanceMark;

/// A single edition (revision) of a Club's content.
#[derive(Clone, Debug, PartialEq)]
pub struct Edition {
    /// The Club this edition belongs to.
    pub club_id: XID,
    /// Provenance mark for ordering and human-readable proof.
    pub provenance: ProvenanceMark,
    /// Plaintext content to be sealed into this edition.
    pub content: Envelope,
    /// Collected signatures on this edition (subject-level signatures by
    /// default).
    pub signatures: Vec<Signature>,
    /// Public-key permits attached to the edition.
    pub permits: Vec<PublicKeyPermit>,
}

impl Edition {
    /// Create a new Edition for a Club with plaintext content and a provenance
    /// mark.
    pub fn new(
        club_id: XID,
        provenance: ProvenanceMark,
        content: Envelope,
    ) -> Self {
        Self {
            club_id,
            provenance,
            content,
            signatures: Vec::new(),
            permits: Vec::new(),
        }
    }

    /// Build the unsigned, unsealed public metadata envelope for this edition.
    ///
    /// Subject: Club `XID`
    /// Assertions: `provenance` and `content` (plaintext)
    pub fn to_unsigned_envelope(&self) -> Envelope {
        let mut e = Envelope::new(self.club_id);
        e = e.add_type("Edition");

        e = e.add_assertion(PROVENANCE, self.provenance.clone());

        // Include plaintext content (helpful for pre-seal transforms).
        // Consumers should use the sealed variant for distribution.
        let mut e = e.add_assertion(CONTENT, self.content.clone());
        // Include any stored signatures.
        for sig in &self.signatures {
            e = e.add_assertion(SIGNED, sig.clone());
        }
        // Include decode-variant permits to maintain idempotence.
        for permit in &self.permits {
            if let PublicKeyPermit::Decode { sealed, member_xid } = permit {
                let mut assertion = Envelope::new_assertion(
                    known_values::HAS_RECIPIENT,
                    sealed.clone(),
                );
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

    /// Seal the content with optional permits (public-key and/or SSKR), and
    /// sign.
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
        signer: &dyn Signer,
        signing_options: Option<SigningOptions>,
    ) -> Result<(Envelope, Option<Vec<Vec<Envelope>>>)> {
        // Fresh content key per edition.
        let content_key = SymmetricKey::new();
        let do_encrypt = !recipients.is_empty() || sskr_spec.is_some();

        // Build base envelope with provenance.
        let mut edition = Envelope::new(self.club_id)
            .add_type("Edition")
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
                        let sealed = SealedMessage::new_with_aad(
                            content_key.to_cbor_data(),
                            recipient,
                            Some(edition_id_aad.as_slice()),
                        );
                        let mut assertion = Envelope::new_assertion(
                            known_values::HAS_RECIPIENT,
                            sealed,
                        );
                        if let Some(xid) = member_xid {
                            assertion = assertion.add_assertion(HOLDER, *xid);
                        }
                        edition = edition.add_assertion_envelope(assertion)?;
                    }
                    PublicKeyPermit::Decode { .. } => {
                        return Err(Error::msg(
                            "Cannot use decode permit when sealing a new edition",
                        ));
                    }
                }
            }

            if let Some(spec) = sskr_spec.as_ref() {
                sskr_shares =
                    Some(encrypted_content.sskr_split(spec, &content_key)?);
            }
        } else {
            // Leave content plaintext.
            edition = edition.add_assertion(CONTENT, self.content.clone());
        }

        let signed = edition.add_signature_opt(signer, signing_options, None);
        Ok((signed, sskr_shares))
    }
}

// EnvelopeEncodable via Into<Envelope>
impl From<Edition> for Envelope {
    fn from(value: Edition) -> Self {
        value.to_unsigned_envelope()
    }
}

// EnvelopeDecodable via TryFrom<Envelope>
impl TryFrom<Envelope> for Edition {
    type Error = Error;

    fn try_from(envelope: Envelope) -> Result<Self> {
        envelope.check_type_envelope("Edition")?;

        // Subject must be the club XID
        let club: XID = envelope.extract_subject()?;

        let mut provenance: Option<ProvenanceMark> = None;
        let mut content: Option<Envelope> = None;
        let mut signatures: Vec<Signature> = Vec::new();
        let mut permits: Vec<PublicKeyPermit> = Vec::new();

        for assertion in envelope.assertions() {
            let pred = assertion.try_predicate()?.try_known_value()?.value();
            let obj = assertion.try_object()?;
            match pred {
                IS_A_RAW => {
                    // Already checked above.
                }
                PROVENANCE_RAW => {
                    if provenance.is_some() {
                        return Err(Error::msg("Multiple provenance marks"));
                    }
                    provenance = Some(ProvenanceMark::try_from(obj.clone())?);
                }
                CONTENT_RAW => {
                    if content.is_some() {
                        return Err(Error::msg("Multiple content assertions"));
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
                    // Decode permit: extract sealed message and optional holder
                    // XID.
                    if !obj.is_obscured() {
                        let sealed = obj.extract_subject::<SealedMessage>()?;
                        // Find optional holder assertion(s) on the permit
                        // assertion envelope.
                        let holder_xid: Option<XID> = match assertion
                            .optional_assertion_with_predicate(HOLDER)?
                        {
                            Some(holder_assertion) => {
                                Some(holder_assertion.extract_object::<XID>()?)
                            }
                            None => None,
                        };
                        // Push permit with optional holder
                        let p = PublicKeyPermit::Decode {
                            sealed,
                            member_xid: holder_xid,
                        };
                        permits.push(p);
                    }
                }
                _ => {
                    return Err(Error::msg(
                        "Unexpected predicate in Edition envelope",
                    ));
                }
            }
        }

        let provenance =
            provenance.ok_or_else(|| Error::msg("Missing provenance"))?;
        let content = content.ok_or_else(|| Error::msg("Missing content"))?;

        Ok(Edition {
            club_id: club,
            provenance,
            content,
            signatures,
            permits,
        })
    }
}
