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

use bc_components::{
    Digest, DigestProvider, SSKRSpec, SealedMessage, Signer, SymmetricKey,
    Verifier, XID,
};
use bc_envelope::prelude::*;
use known_values::{
    HAS_RECIPIENT_RAW, HOLDER, IS_A_RAW, PROVENANCE, PROVENANCE_RAW, SIGNED_RAW,
};
use provenance_mark::ProvenanceMark;

use crate::{
    Error, Result, provenance_mark_provider::ProvenanceMarkProvider,
    public_key_permit::PublicKeyPermit,
};

/// A single edition (revision) of a Club's content.
#[derive(Clone, Debug, PartialEq)]
pub struct Edition {
    /// The Club this edition belongs to.
    pub club_id: XID,
    /// Provenance mark for ordering and human-readable proof.
    pub provenance: ProvenanceMark,
    /// Plaintext content to be sealed into this edition.
    pub content: Envelope,
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
        Self { club_id, provenance, content, permits: Vec::new() }
    }

    /// Build the unsigned, unsealed public metadata envelope for this edition.
    ///
    /// Subject: Content (plaintext wrapped or encrypted)
    /// Assertions: club XID and provenance mark
    pub fn to_unsigned_envelope(&self) -> Envelope {
        let subject =
            if self.content.is_encrypted() || self.content.is_wrapped() {
                self.content.clone()
            } else {
                self.content.clone().wrap()
            };

        let mut e = subject.add_type("Edition");
        e = e.add_assertion("club", self.club_id);
        e = e.add_assertion(PROVENANCE, self.provenance.clone());
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
    ) -> Result<(Envelope, Option<Vec<Vec<Envelope>>>)> {
        // Fresh content key per edition.
        let content_key = SymmetricKey::new();
        let do_encrypt = !recipients.is_empty() || sskr_spec.is_some();

        // Build base envelope with content as the subject.
        let mut base_subject =
            if self.content.is_encrypted() || self.content.is_wrapped() {
                self.content.clone()
            } else {
                self.content.clone().wrap()
            };

        if do_encrypt {
            base_subject = self.content.encrypt(&content_key);
        }

        let mut edition = base_subject
            .add_type("Edition")
            .add_assertion("club", self.club_id)
            .add_assertion(PROVENANCE, self.provenance.clone());

        let mut sskr_shares: Option<Vec<Vec<Envelope>>> = None;

        if do_encrypt {
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
                    Some(base_subject.sskr_split(spec, &content_key)?);
            }
        }

        let signed = edition.sign(signer);
        Ok((signed, sskr_shares))
    }

    /// Verify a signed edition envelope, unwrap it, and decode into an
    /// `Edition`.
    pub fn unseal(sealed: Envelope, verifier: &dyn Verifier) -> Result<Self> {
        let verified = sealed.verify(verifier)?;
        Edition::try_from(verified)
    }
}

impl ProvenanceMarkProvider for Edition {
    fn provenance_mark(&self) -> &ProvenanceMark { &self.provenance }
}

// EnvelopeEncodable via Into<Envelope>
impl From<Edition> for Envelope {
    fn from(value: Edition) -> Self { value.to_unsigned_envelope() }
}

// EnvelopeDecodable via TryFrom<Envelope>
impl TryFrom<Envelope> for Edition {
    type Error = Error;

    fn try_from(envelope: Envelope) -> Result<Self> {
        envelope.check_type_envelope("Edition")?;

        let subject = envelope.subject();
        let content: Option<Envelope> = if subject.is_wrapped() {
            Some(subject.try_unwrap()?)
        } else {
            Some(subject.clone())
        };
        let mut provenance: Option<ProvenanceMark> = None;
        let mut permits: Vec<PublicKeyPermit> = Vec::new();
        let mut club_id: Option<XID> = None;

        for assertion in envelope.assertions() {
            let predicate = assertion.try_predicate()?;

            if let Ok(kv) = predicate.try_known_value() {
                let obj = assertion.try_object()?;
                match kv.value() {
                    IS_A_RAW => {
                        // Already checked above.
                    }
                    PROVENANCE_RAW => {
                        if provenance.is_some() {
                            return Err(Error::msg(
                                "Multiple provenance marks",
                            ));
                        }
                        provenance =
                            Some(ProvenanceMark::try_from(obj.clone())?);
                    }
                    SIGNED_RAW => {}
                    HAS_RECIPIENT_RAW => {
                        // Decode permit: extract sealed message and optional
                        // holder XID.
                        if !obj.is_obscured() {
                            let sealed =
                                obj.extract_subject::<SealedMessage>()?;
                            // Find optional holder assertion(s) on the permit
                            // assertion envelope.
                            let holder_xid: Option<XID> = match assertion
                                .optional_assertion_with_predicate(HOLDER)?
                            {
                                Some(holder_assertion) => Some(
                                    holder_assertion.extract_object::<XID>()?,
                                ),
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
            } else if predicate == Envelope::new("club") {
                if club_id.is_some() {
                    return Err(Error::msg("Multiple club assertions"));
                }
                let obj = assertion.try_object()?;
                if obj.is_obscured() {
                    return Err(Error::msg("Club assertion is obscured"));
                }
                club_id = Some(obj.extract_subject::<XID>()?);
            } else {
                return Err(Error::msg(
                    "Unexpected predicate in Edition envelope",
                ));
            }
        }

        let provenance =
            provenance.ok_or_else(|| Error::msg("Missing provenance"))?;
        let content = content.ok_or_else(|| Error::msg("Missing content"))?;
        let club = club_id.ok_or_else(|| Error::msg("Missing club"))?;

        Ok(Edition { club_id: club, provenance, content, permits })
    }
}
