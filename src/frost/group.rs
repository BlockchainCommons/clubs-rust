use std::collections::BTreeMap;

use anyhow::{Result, anyhow, bail};
use bc_components::{SigningPublicKey, XID};
use frost_secp256k1_tr::{self as frost, Identifier};
use rand::rngs::OsRng;
use dcbor::prelude::*; // ByteString

use crate::frost::participant::FrostParticipant;

// Internal public key package used by the group; not exposed outside this
// module tree.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct FrostPublicKeyPackage {
    pub(super) verifying_key_sec1: ByteString,
    pub(super) verifying_shares_sec1: BTreeMap<ByteString, ByteString>,
}

impl FrostPublicKeyPackage {
    pub(super) fn verifying_signing_key(&self) -> SigningPublicKey {
        let sec1 = self.verifying_key_sec1.as_ref();
        debug_assert_eq!(sec1.len(), 33);
        let mut xonly = [0u8; 32];
        xonly.copy_from_slice(&sec1[1..]);
        let schnorr_pk = bc_components::SchnorrPublicKey::from_data(xonly);
        SigningPublicKey::from_schnorr(schnorr_pk)
    }

    pub(super) fn from_frost(
        pkg: &frost_secp256k1_tr::keys::PublicKeyPackage,
    ) -> Result<Self> {
        let vkey = pkg
            .verifying_key()
            .serialize()
            .map_err(|e| anyhow!("serialize verifying key: {e}"))?;
        if vkey.len() != 33 { bail!("invalid verifying key length"); }
        let verifying_key_sec1: ByteString = vkey.into();

        let mut verifying_shares_sec1: BTreeMap<ByteString, ByteString> =
            BTreeMap::new();
        for (id, vs) in pkg.verifying_shares().iter() {
            let id_bytes = ByteString::from(id.serialize());
            let vs_bytes = vs
                .serialize()
                .map_err(|e| anyhow!("serialize verifying share: {e}"))?;
            if vs_bytes.len() != 33 { bail!("invalid verifying share size"); }
            verifying_shares_sec1.insert(id_bytes, vs_bytes.into());
        }
        Ok(Self { verifying_key_sec1, verifying_shares_sec1 })
    }

    pub(super) fn to_frost(
        &self,
    ) -> Result<frost_secp256k1_tr::keys::PublicKeyPackage> {
        use anyhow::anyhow;
        use frost_secp256k1_tr::{VerifyingKey, keys::VerifyingShare};

        let verifying_key = VerifyingKey::deserialize(self.verifying_key_sec1.as_ref())
            .map_err(|e| anyhow!("deserialize verifying key: {e}"))?;

        let mut vshares: BTreeMap<
            frost_secp256k1_tr::Identifier,
            VerifyingShare,
        > = BTreeMap::new();
        for (id_bytes, sec1) in &self.verifying_shares_sec1 {
            let id = frost_secp256k1_tr::Identifier::deserialize(id_bytes.as_ref())
                .map_err(|e| anyhow!("deserialize identifier: {e}"))?;
            let vs = VerifyingShare::deserialize(sec1.as_ref())
                .map_err(|e| anyhow!("deserialize verifying share: {e}"))?;
            vshares.insert(id, vs);
        }

        Ok(frost_secp256k1_tr::keys::PublicKeyPackage::new(
            vshares,
            verifying_key,
        ))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FrostGroup {
    pub threshold: usize,
    pub members: Vec<XID>,
    verifying_key: SigningPublicKey,
    pub(super) pubkey_package: FrostPublicKeyPackage,
    id_map: BTreeMap<XID, Identifier>,
    participant_keys: BTreeMap<XID, SigningPublicKey>,
}

impl FrostGroup {
    pub(super) fn new(
        threshold: usize,
        members: Vec<XID>,
        pubkey_package: FrostPublicKeyPackage,
        id_map: BTreeMap<XID, Identifier>,
    ) -> Self {
        let verifying_key = pubkey_package.verifying_signing_key();
        // Precompute per-member signing public keys from verifying shares
        let mut participant_keys: BTreeMap<XID, SigningPublicKey> = BTreeMap::new();
        for (xid, ident) in &id_map {
            let id_bytes = ByteString::from(ident.serialize());
            if let Some(sec1) = pubkey_package.verifying_shares_sec1.get(&id_bytes) {
                let sec1 = sec1.as_ref();
                debug_assert_eq!(sec1.len(), 33);
                let mut xonly = [0u8; 32];
                xonly.copy_from_slice(&sec1[1..]);
                let schnorr_pk = bc_components::SchnorrPublicKey::from_data(xonly);
                participant_keys.insert(*xid, SigningPublicKey::from_schnorr(schnorr_pk));
            }
        }
        Self { threshold, members, verifying_key, pubkey_package, id_map, participant_keys }
    }

    pub fn verifying_signing_key(&self) -> SigningPublicKey { self.verifying_key.clone() }

    pub fn member_verifying_signing_key(&self, xid: &XID) -> Result<SigningPublicKey> {
        self.participant_keys
            .get(xid)
            .cloned()
            .ok_or_else(|| anyhow!("unknown member XID in group: {}", xid))
    }

    pub(super) fn id_for_xid(&self, xid: &XID) -> Result<Identifier> {
        self.id_map
            .get(xid)
            .cloned()
            .ok_or_else(|| anyhow!("unknown member XID in group: {}", xid))
    }

    pub(super) fn to_frost_public_key_package(
        &self,
    ) -> Result<frost_secp256k1_tr::keys::PublicKeyPackage> {
        self.pubkey_package.to_frost()
    }

    /// Create a FROST group with a trusted dealer and return signer contexts.
    /// Returns the group and a map of XID -> FrostParticipant (each holding its
    /// secret share).
    pub fn new_with_trusted_dealer(
        threshold: usize,
        members: Vec<XID>,
    ) -> Result<(Self, BTreeMap<XID, FrostParticipant>)> {
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
        let (secret_shares, public_key_package) =
            frost::keys::generate_with_dealer(
                max,
                min,
                frost::keys::IdentifierList::Custom(&ids),
                OsRng,
            )?;

        // Build participant contexts (each with its own secret share)
        let mut participants: BTreeMap<XID, FrostParticipant> = BTreeMap::new();
        // Reverse map Identifier -> XID
        let mut rev: BTreeMap<Identifier, XID> = BTreeMap::new();
        for (x, i) in &id_map {
            rev.insert(*i, *x);
        }
        for (id, ss) in &secret_shares {
            let kp = frost::keys::KeyPackage::try_from(ss.clone())?;
            let xid = *rev
                .get(id)
                .ok_or_else(|| anyhow!("unknown identifier from dealer"))?;
            participants.insert(xid, FrostParticipant::new(xid, kp));
        }

        let pubkey_pkg =
            FrostPublicKeyPackage::from_frost(&public_key_package)?;
        let group = FrostGroup::new(threshold, members, pubkey_pkg, id_map);

        Ok((group, participants))
    }
}
