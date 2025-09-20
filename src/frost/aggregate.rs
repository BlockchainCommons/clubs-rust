use std::collections::BTreeMap;

use crate::{Error, Result};
use bc_components::DigestProvider;
use bc_components::Signature;
use bc_envelope::prelude::*;
use frost_secp256k1_tr::round1::{NonceCommitment, SigningCommitments};

use super::{
    group::FrostGroup,
    signing::{FrostSignatureShares, FrostSigningPackage},
};

/// Attach a pre-aggregated BIP-340 signature to the envelope and verify with
/// the group's public key.
pub fn attach_preaggregated_signature(
    envelope: &Envelope,
    group: &FrostGroup,
    schnorr_sig64: &[u8; 64],
) -> Result<Envelope> {
    // Signatures attach as assertions on the subject; derive message
    let subj = envelope.subject();
    let subject_digest = subj.digest();
    let _message: &[u8] = subject_digest.as_ref().as_ref();

    // Convert signature
    let signature = Signature::schnorr_from_data(*schnorr_sig64);

    // Verify using the group's SigningPublicKey
    let signed =
        envelope.add_assertion(known_values::SIGNED, signature.clone());
    signed
        .verify_signature_from(&group.verifying_signing_key())
        .map_err(|e| Error::msg(format!("envelope signature verification failed: {e}")))?;

    Ok(signed)
}

pub fn aggregate_and_attach_signature(
    envelope: &Envelope,
    group: &FrostGroup,
    signing_package_g: &FrostSigningPackage,
    shares_g: &FrostSignatureShares,
) -> Result<Envelope> {
    // Validate session consistency
    if signing_package_g.session != shares_g.session {
        return Err(Error::msg("signing package and shares belong to different sessions"));
    }
    // Convert group public key package
    let frost_pkg = group.to_frost_public_key_package()?;
    // Convert signing package
    let mut frost_commitments: BTreeMap<
        frost_secp256k1_tr::Identifier,
        frost_secp256k1_tr::round1::SigningCommitments,
    > = BTreeMap::new();
    for c in &signing_package_g.commitments {
        let id = group.id_for_xid(&c.xid)?;
        let hiding = NonceCommitment::deserialize(c.hiding.as_ref())
            .map_err(|e| Error::msg(format!("deserialize hiding commitment: {e}")))?;
        let binding = NonceCommitment::deserialize(c.binding.as_ref())
            .map_err(|e| Error::msg(format!("deserialize binding commitment: {e}")))?;
        let comm = SigningCommitments::new(hiding, binding);
        frost_commitments.insert(id, comm);
    }
    // Derive message digest from the package's message Envelope subject
    let subj_env = signing_package_g.message.subject();
    let msg_digest = subj_env.digest();
    let msg_bytes: &[u8] = msg_digest.as_ref().as_ref();
    let signing_package =
        frost_secp256k1_tr::SigningPackage::new(frost_commitments, msg_bytes);
    // Convert shares
    let mut frost_shares: BTreeMap<
        frost_secp256k1_tr::Identifier,
        frost_secp256k1_tr::round2::SignatureShare,
    > = BTreeMap::new();
    for share in &shares_g.shares {
        if share.session != signing_package_g.session {
            return Err(Error::msg("signature share session mismatch"));
        }
        let id = group.id_for_xid(&share.xid)?;
        let share = frost_secp256k1_tr::round2::SignatureShare::deserialize(
            &share.share,
        )
        .map_err(|e| Error::msg(format!("deserialize signature share: {e}")))?;
        frost_shares.insert(id, share);
    }

    let group_sig = frost_secp256k1_tr::aggregate(
        &signing_package,
        &frost_shares,
        &frost_pkg,
    )
    .map_err(|e| Error::msg(format!("aggregate group signature failed: {e}")))?;

    // Convert aggregated signature to BIP-340 bytes
    let sig_vec = group_sig
        .serialize()
        .map_err(|e| Error::msg(format!("serialize group signature failed: {e}")))?;
    if sig_vec.len() != 64 {
        return Err(Error::msg(format!("unexpected Schnorr signature length: {}", sig_vec.len())));
    }
    let mut sig_bytes = [0u8; 64];
    sig_bytes.copy_from_slice(&sig_vec);

    // Use generic attach helper to affix the signature to the envelope and
    // verify via Gordian stack
    attach_preaggregated_signature(envelope, group, &sig_bytes)
}
