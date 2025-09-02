use anyhow::{anyhow, bail, Result as AnyResult};
use std::collections::BTreeMap;

use bc_components::{Signature, SigningPublicKey, XID};
use bc_envelope::prelude::*;
use frost_secp256k1_tr::keys::{PublicKeyPackage as FrostPk, VerifyingShare};
use frost_secp256k1_tr::round1::{NonceCommitment, SigningCommitments};
use frost_secp256k1_tr::VerifyingKey;
use frost_secp256k1_tr::{self as frost, Identifier};
use rand::rngs::OsRng;

/// The Gordian-friendly group definition and verifying key.
/// - `threshold`: Minimum number of signers required.
/// - `members`: The participants' XIDs (identifiers are internal-only).
/// - `verifying_key`: Group verifying key (BIP-340 x-only Schnorr).
#[derive(Clone, Debug, PartialEq, Eq)]
struct FrostPublicKeyPackage {
    verifying_key_sec1: [u8; 33],
    // Map serialized Identifier bytes -> VerifyingShare (SEC1 33 bytes)
    verifying_shares_sec1: BTreeMap<Vec<u8>, [u8; 33]>,
}

impl FrostPublicKeyPackage {
    fn verifying_signing_key(&self) -> SigningPublicKey {
        let mut xonly = [0u8; 32];
        xonly.copy_from_slice(&self.verifying_key_sec1[1..]);
        let schnorr_pk = bc_components::SchnorrPublicKey::from_data(xonly);
        SigningPublicKey::from_schnorr(schnorr_pk)
    }

    fn from_frost(pkg: &frost_secp256k1_tr::keys::PublicKeyPackage) -> AnyResult<Self> {
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

    fn to_frost(&self) -> AnyResult<frost_secp256k1_tr::keys::PublicKeyPackage> {
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
    pub members: Vec<XID>,
    pubkey_package: FrostPublicKeyPackage,
    // Internal: mapping from member XIDs to frost Identifiers
    id_map: BTreeMap<XID, Identifier>,
}

impl FROSTGroup {
    fn new(
        threshold: usize,
        members: Vec<XID>,
        pubkey_package: FrostPublicKeyPackage,
        id_map: BTreeMap<XID, Identifier>,
    ) -> Self {
        Self { threshold, members, pubkey_package, id_map }
    }

    pub fn verifying_signing_key(&self) -> SigningPublicKey { self.pubkey_package.verifying_signing_key() }

    fn id_for_xid(&self, xid: &XID) -> AnyResult<Identifier> {
        self.id_map
            .get(xid)
            .cloned()
            .ok_or_else(|| anyhow!("unknown member XID in group: {}", xid))
    }

    /// Create a FROST group with a trusted dealer and return signer contexts.
    /// Returns the group and a map of XID -> FrostParticipant (each holding its secret share).
    pub fn new_with_trusted_dealer(
        threshold: usize,
        members: Vec<XID>,
    ) -> AnyResult<(Self, BTreeMap<XID, FrostParticipant>)> {
        let max = members.len() as u16;
        let min = threshold as u16;
        // Assign Identifiers internally in order 1..=n
        let ids: Vec<Identifier> = (1..=max)
            .map(|u| Identifier::try_from(u).expect("u16 range"))
            .collect();
        let mut id_map: BTreeMap<XID, Identifier> = BTreeMap::new();
        for (xid, id) in members.iter().cloned().zip(ids.iter().cloned()) {
            id_map.insert(xid, id);
        }

        // Dealer generates key shares and a public key package
        let (secret_shares, public_key_package) = frost::keys::generate_with_dealer(
            max,
            min,
            frost::keys::IdentifierList::Custom(&ids),
            &mut OsRng,
        )?;

        // Build participant contexts (each with its own secret share)
        let mut participants: BTreeMap<XID, FrostParticipant> = BTreeMap::new();
        // Reverse map Identifier -> XID
        let mut rev: BTreeMap<Identifier, XID> = BTreeMap::new();
        for (x, i) in &id_map { rev.insert(*i, *x); }
        for (id, ss) in &secret_shares {
            let kp = frost::keys::KeyPackage::try_from(ss.clone())?;
            let xid = *rev.get(id).ok_or_else(|| anyhow!("unknown identifier from dealer"))?;
            participants.insert(xid, FrostParticipant::new(xid, *id, kp));
        }

        let pubkey_pkg = FrostPublicKeyPackage::from_frost(&public_key_package)?;
        let group = FROSTGroup::new(threshold, members, pubkey_pkg, id_map);

        Ok((group, participants))
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
    hiding: [u8; 33],
    binding: [u8; 33],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FrostSigningPackageG {
    message: Vec<u8>,
    commitments: BTreeMap<XID, FrostSigningCommitmentSec1>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FrostSignatureSharesG {
    shares: BTreeMap<XID, Vec<u8>>, // serialized scalar shares
}

impl FrostSignatureSharesG {
    pub fn new(shares: BTreeMap<XID, Vec<u8>>) -> Self { Self { shares } }
}

/// Build a Gordian signing package from an envelope and a set of commitments.
pub fn build_signing_package(
    envelope: &Envelope,
    commitments: BTreeMap<XID, FrostSigningCommitmentSec1>,
) -> FrostSigningPackageG {
    let subj = envelope.subject();
    let d = subj.digest();
    let message = d.as_ref().data().to_vec();
    FrostSigningPackageG { message, commitments }
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

// FrostDealer removed; use FROSTGroup::new_with_trusted_dealer.

/// A participant-side context that performs the signing rounds locally.
/// Holds the secret key package and ephemeral nonces for a session.
pub struct FrostParticipant {
    xid: XID,
    _identifier: Identifier,
    key_package: frost::keys::KeyPackage,
    nonces: Option<frost::round1::SigningNonces>,
}

impl FrostParticipant {
    pub fn new(xid: XID, identifier: Identifier, key_package: frost::keys::KeyPackage) -> Self {
        Self { xid, _identifier: identifier, key_package, nonces: None }
    }

    pub fn xid(&self) -> XID { self.xid }

    /// Perform Round-1 locally: generate nonces and commitments. Stores nonces for Round-2.
    pub fn round1_commit(&mut self) -> AnyResult<FrostSigningCommitmentSec1> {
        let (nonces, comms) = frost::round1::commit(self.key_package.signing_share(), &mut OsRng);
        self.nonces = Some(nonces);
        let hid = comms
            .hiding()
            .serialize()
            .map_err(|e| anyhow!("serialize hiding commitment: {e}"))?;
        let bind = comms
            .binding()
            .serialize()
            .map_err(|e| anyhow!("serialize binding commitment: {e}"))?;
        let mut h = [0u8; 33];
        h.copy_from_slice(&hid);
        let mut b = [0u8; 33];
        b.copy_from_slice(&bind);
        Ok(FrostSigningCommitmentSec1 { hiding: h, binding: b })
    }

    /// Perform Round-2 locally: produce a signature share using stored nonces.
    pub fn round2_sign(&self, group: &FROSTGroup, signing_pkg: &FrostSigningPackageG) -> AnyResult<Vec<u8>> {
        let nonces = self
            .nonces
            .as_ref()
            .ok_or_else(|| anyhow!("round1_commit must be called before round2_sign for signer {}", self.xid))?;

        // Convert commitments to frost SigningPackage
        let mut frost_commitments: BTreeMap<Identifier, SigningCommitments> = BTreeMap::new();
        for (xid, comm) in &signing_pkg.commitments {
            let id = group.id_for_xid(xid)?;
            let hiding = NonceCommitment::deserialize(&comm.hiding)
                .map_err(|e| anyhow!("deserialize hiding: {e}"))?;
            let binding = NonceCommitment::deserialize(&comm.binding)
                .map_err(|e| anyhow!("deserialize binding: {e}"))?;
            frost_commitments.insert(id, SigningCommitments::new(hiding, binding));
        }
        let frost_sp = frost::SigningPackage::new(frost_commitments, &signing_pkg.message);

        let share = frost::round2::sign(&frost_sp, nonces, &self.key_package)
            .map_err(|e| anyhow!("round2 sign failed for {}: {e}", self.xid))?;
        Ok(share.serialize())
    }
}
