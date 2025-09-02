use anyhow::{anyhow, bail, Result as AnyResult};
use std::collections::BTreeMap;

use bc_components::{Signature, SigningPublicKey, XID};
use bc_envelope::prelude::*;
// (XID already imported above)

/// A participant in a FROST group: maps an `XID` to a FROST identifier
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct FrostSigner {
    pub xid: XID,
    pub identifier: u16,
}

/// The Gordian-friendly group definition and verifying key.
/// - `threshold`: Minimum number of signers required.
/// - `signers`: The participants with their `XID` and FROST identifier mapping.
/// - `verifying_key`: Group verifying key (BIP-340 x-only Schnorr).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FROSTGroup {
    pub threshold: usize,
    pub signers: Vec<FrostSigner>,
    pub verifying_key: SigningPublicKey,
}

impl FROSTGroup {
    pub fn new(threshold: usize, signers: Vec<FrostSigner>, verifying_key: SigningPublicKey) -> Self {
        Self { threshold, signers, verifying_key }
    }
}

/// Attach a pre-aggregated BIP-340 signature to the envelope and verify with the group's public key.
/// This helper does not reference `frost-secp256k1-tr` types and can be used by callers
/// who only have the final 64-byte signature and the group verifying key.
pub fn attach_preaggregated_signature(
    envelope: &Envelope,
    group: &FROSTGroup,
    schnorr_sig64: &[u8; 64],
) -> AnyResult<(Envelope, SigningPublicKey)> {
    // Signatures attach as assertions on the subject; derive message
    let subj = envelope.subject();
    let subject_digest = subj.digest();
    let message: &[u8] = subject_digest.as_ref().as_ref();

    // Convert signature
    let signature = Signature::schnorr_from_data(*schnorr_sig64);

    // Verify using the group's SigningPublicKey
    // Note: bc-envelope verification helpers will both verify and return the envelope on success
    let signed = envelope.add_assertion(known_values::SIGNED, signature.clone());
    signed
        .verify_signature_from(&group.verifying_key)
        .map_err(|e| anyhow!("envelope signature verification failed: {e}"))?;

    Ok((signed, group.verifying_key.clone()))
}

// A bridging helper that aggregates with `frost-secp256k1-tr` then attaches and verifies.
// Note: This function takes FROST structures, but callers can keep usage isolated here.
pub fn aggregate_and_attach_signature(
    envelope: &Envelope,
    group: &FROSTGroup,
    signing_package: &frost_secp256k1_tr::SigningPackage,
    shares: &BTreeMap<frost_secp256k1_tr::Identifier, frost_secp256k1_tr::round2::SignatureShare>,
    public_key_package: &frost_secp256k1_tr::keys::PublicKeyPackage,
) -> AnyResult<(Envelope, SigningPublicKey)> {
    // Aggregate with FROST
    let group_sig = frost_secp256k1_tr::aggregate(signing_package, shares, public_key_package)
        .map_err(|e| anyhow!("aggregate group signature failed: {e}"))?;

    // Derive message from subject digest
    let subject = envelope.subject();
    let subject_digest = subject.digest();
    let message: &[u8] = subject_digest.as_ref().as_ref();
    public_key_package
        .verifying_key()
        .verify(message, &group_sig)
        .map_err(|e| anyhow!("group signature verification failed: {e}"))?;

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
