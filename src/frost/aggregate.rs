use anyhow::{anyhow, bail, Result as AnyResult};
use std::collections::BTreeMap;

use bc_components::{Signature, SigningPublicKey};
use bc_envelope::prelude::*;
use frost_secp256k1_tr::round1::{NonceCommitment, SigningCommitments};

use super::group::FrostGroup;
use super::signing::{FrostSignatureSharesG, FrostSigningPackageG};

/// Attach a pre-aggregated BIP-340 signature to the envelope and verify with the group's public key.
pub fn attach_preaggregated_signature(
    envelope: &Envelope,
    group: &FrostGroup,
    schnorr_sig64: &[u8; 64],
) -> AnyResult<(Envelope, SigningPublicKey)> {
    // Signatures attach as assertions on the subject; derive message
    let subj = envelope.subject();
    let subject_digest = subj.digest();
    let _message: &[u8] = subject_digest.as_ref().as_ref();

    // Convert signature
    let signature = Signature::schnorr_from_data(*schnorr_sig64);

    // Verify using the group's SigningPublicKey
    let signed = envelope.add_assertion(known_values::SIGNED, signature.clone());
    signed
        .verify_signature_from(&group.verifying_signing_key())
        .map_err(|e| anyhow!("envelope signature verification failed: {e}"))?;

    Ok((signed, group.verifying_signing_key()))
}

pub fn aggregate_and_attach_signature(
    envelope: &Envelope,
    group: &FrostGroup,
    signing_package_g: &FrostSigningPackageG,
    shares_g: &FrostSignatureSharesG,
) -> AnyResult<(Envelope, SigningPublicKey)> {
    // Convert group public key package
    let frost_pkg = group.to_frost_public_key_package()?;
    // Convert signing package
    let mut frost_commitments: BTreeMap<
        frost_secp256k1_tr::Identifier,
        frost_secp256k1_tr::round1::SigningCommitments,
    > = BTreeMap::new();
    for (xid, c) in &signing_package_g.commitments {
        let id = group.id_for_xid(xid)?;
        let hiding = NonceCommitment::deserialize(&c.hiding)
            .map_err(|e| anyhow!("deserialize hiding commitment: {e}"))?;
        let binding = NonceCommitment::deserialize(&c.binding)
            .map_err(|e| anyhow!("deserialize binding commitment: {e}"))?;
        let comm = SigningCommitments::new(hiding, binding);
        frost_commitments.insert(id, comm);
    }
    let signing_package = frost_secp256k1_tr::SigningPackage::new(
        frost_commitments,
        &signing_package_g.message,
    );
    // Convert shares
    let mut frost_shares: BTreeMap<
        frost_secp256k1_tr::Identifier,
        frost_secp256k1_tr::round2::SignatureShare,
    > = BTreeMap::new();
    for (xid, sbytes) in &shares_g.shares {
        let id = group.id_for_xid(xid)?;
        let share = frost_secp256k1_tr::round2::SignatureShare::deserialize(sbytes)
            .map_err(|e| anyhow!("deserialize signature share: {e}"))?;
        frost_shares.insert(id, share);
    }

    let group_sig = frost_secp256k1_tr::aggregate(&signing_package, &frost_shares, &frost_pkg)
        .map_err(|e| anyhow!("aggregate group signature failed: {e}"))?;

    // Convert aggregated signature to BIP-340 bytes
    let sig_vec = group_sig
        .serialize()
        .map_err(|e| anyhow!("serialize group signature failed: {e}"))?;
    if sig_vec.len() != 64 {
        bail!("unexpected Schnorr signature length: {}", sig_vec.len());
    }
    let mut sig_bytes = [0u8; 64];
    sig_bytes.copy_from_slice(&sig_vec);

    // Use generic attach helper to affix the signature to the envelope and verify via Gordian stack
    attach_preaggregated_signature(envelope, group, &sig_bytes)
}
