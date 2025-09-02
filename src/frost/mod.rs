use anyhow::{anyhow, bail, Result as AnyResult};
use std::collections::BTreeMap;

use bc_components::{Signature, SigningPublicKey, XID};
use bc_envelope::prelude::*;
use frost_secp256k1_tr::keys::{PublicKeyPackage as FrostPk, VerifyingShare};
use frost_secp256k1_tr::round1::{NonceCommitment, SigningCommitments};
use frost_secp256k1_tr::VerifyingKey;

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
pub struct FrostPublicKeyPackage {
    pub verifying_key_sec1: [u8; 33],
    // Map serialized Identifier bytes -> VerifyingShare (SEC1 33 bytes)
    pub verifying_shares_sec1: BTreeMap<Vec<u8>, [u8; 33]>,
}

impl FrostPublicKeyPackage {
    pub fn verifying_signing_key(&self) -> SigningPublicKey {
        let mut xonly = [0u8; 32];
        xonly.copy_from_slice(&self.verifying_key_sec1[1..]);
        let schnorr_pk = bc_components::SchnorrPublicKey::from_data(xonly);
        SigningPublicKey::from_schnorr(schnorr_pk)
    }

    pub fn from_frost(pkg: &frost_secp256k1_tr::keys::PublicKeyPackage) -> AnyResult<Self> {
        let vkey = pkg
            .verifying_key()
            .serialize()
            .map_err(|e| anyhow!("serialize verifying key: {e}"))?;
        if vkey.len() != 33 { bail!("invalid verifying key length"); }
        let mut verifying_key_sec1 = [0u8; 33];
        verifying_key_sec1.copy_from_slice(&vkey);

        let mut verifying_shares_sec1: BTreeMap<Vec<u8>, [u8; 33]> = BTreeMap::new();
        for (id, vs) in pkg.verifying_shares().iter() {
            let id_bytes = id.serialize();
            let vs_bytes = vs
                .serialize()
                .map_err(|e| anyhow!("serialize verifying share: {e}"))?;
            if vs_bytes.len() != 33 { bail!("invalid verifying share size"); }
            let mut arr = [0u8; 33];
            arr.copy_from_slice(&vs_bytes);
            verifying_shares_sec1.insert(id_bytes, arr);
        }
        Ok(Self { verifying_key_sec1, verifying_shares_sec1 })
    }

    pub fn to_frost(&self) -> AnyResult<frost_secp256k1_tr::keys::PublicKeyPackage> {
        // Build verifying key
        let verifying_key = VerifyingKey::deserialize(&self.verifying_key_sec1)
            .map_err(|e| anyhow!("deserialize verifying key: {e}"))?;

        // Build verifying shares map (may be empty)
        let mut vshares: BTreeMap<frost_secp256k1_tr::Identifier, VerifyingShare> = BTreeMap::new();
        for (id_bytes, sec1) in &self.verifying_shares_sec1 {
            let id = frost_secp256k1_tr::Identifier::deserialize(id_bytes)
                .map_err(|e| anyhow!("deserialize identifier: {e}"))?;
            let vs = VerifyingShare::deserialize(sec1)
                .map_err(|e| anyhow!("deserialize verifying share: {e}"))?;
            vshares.insert(id, vs);
        }

        Ok(FrostPk::new(vshares, verifying_key))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FROSTGroup {
    pub threshold: usize,
    pub signers: Vec<FrostSigner>,
    pub pubkey_package: FrostPublicKeyPackage,
}

impl FROSTGroup {
    pub fn new(threshold: usize, signers: Vec<FrostSigner>, pubkey_package: FrostPublicKeyPackage) -> Self {
        Self { threshold, signers, pubkey_package }
    }

    pub fn verifying_signing_key(&self) -> SigningPublicKey { self.pubkey_package.verifying_signing_key() }

    pub fn from_frost(
        threshold: usize,
        signers: Vec<FrostSigner>,
        pkg: &frost_secp256k1_tr::keys::PublicKeyPackage,
    ) -> AnyResult<Self> {
        Ok(Self { threshold, signers, pubkey_package: FrostPublicKeyPackage::from_frost(pkg)? })
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
    let _message: &[u8] = subject_digest.as_ref().as_ref();

    // Convert signature
    let signature = Signature::schnorr_from_data(*schnorr_sig64);

    // Verify using the group's SigningPublicKey
    // Note: bc-envelope verification helpers will both verify and return the envelope on success
    let signed = envelope.add_assertion(known_values::SIGNED, signature.clone());
    signed
        .verify_signature_from(&group.verifying_signing_key())
        .map_err(|e| anyhow!("envelope signature verification failed: {e}"))?;

    Ok((signed, group.verifying_signing_key()))
}

// A bridging helper that aggregates with `frost-secp256k1-tr` then attaches and verifies.
// Note: This function takes FROST structures, but callers can keep usage isolated here.
// Gordian-level analogs for signing package and signature shares.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FrostSigningCommitmentSec1 {
    pub hiding: [u8; 33],
    pub binding: [u8; 33],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FrostSigningPackageG {
    pub message: Vec<u8>,
    pub commitments: BTreeMap<u16, FrostSigningCommitmentSec1>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FrostSignatureSharesG {
    pub shares: BTreeMap<u16, Vec<u8>>, // serialized scalar shares
}

pub fn aggregate_and_attach_signature(
    envelope: &Envelope,
    group: &FROSTGroup,
    signing_package_g: &FrostSigningPackageG,
    shares_g: &FrostSignatureSharesG,
) -> AnyResult<(Envelope, SigningPublicKey)> {
    // Aggregate with FROST
    // Convert group public key package
    let frost_pkg = group.pubkey_package.to_frost()?;
    // Convert signing package
    let mut frost_commitments: BTreeMap<
        frost_secp256k1_tr::Identifier,
        frost_secp256k1_tr::round1::SigningCommitments,
    > = BTreeMap::new();
    for (id_u16, c) in &signing_package_g.commitments {
        let id = frost_secp256k1_tr::Identifier::try_from(*id_u16)
            .map_err(|_| anyhow!("invalid identifier: {}", id_u16))?;
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
    for (id_u16, sbytes) in &shares_g.shares {
        let id = frost_secp256k1_tr::Identifier::try_from(*id_u16)
            .map_err(|_| anyhow!("invalid identifier: {}", id_u16))?;
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
