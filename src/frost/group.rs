use std::collections::BTreeMap;

use anyhow::{Result as AnyResult, anyhow};
use bc_components::{SigningPublicKey, XID};
use frost_secp256k1_tr::{self as frost, Identifier};
use rand::rngs::OsRng;

use crate::frost::participant::FrostParticipant;

// Internal public key package used by the group; not exposed outside this
// module tree.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct FrostPublicKeyPackage {
    pub(super) verifying_key_sec1: [u8; 33],
    pub(super) verifying_shares_sec1: BTreeMap<Vec<u8>, [u8; 33]>,
}

impl FrostPublicKeyPackage {
    pub(super) fn verifying_signing_key(&self) -> SigningPublicKey {
        let mut xonly = [0u8; 32];
        xonly.copy_from_slice(&self.verifying_key_sec1[1..]);
        let schnorr_pk = bc_components::SchnorrPublicKey::from_data(xonly);
        SigningPublicKey::from_schnorr(schnorr_pk)
    }

    pub(super) fn from_frost(
        pkg: &frost_secp256k1_tr::keys::PublicKeyPackage,
    ) -> AnyResult<Self> {
        use anyhow::{anyhow, bail};

        let vkey = pkg
            .verifying_key()
            .serialize()
            .map_err(|e| anyhow!("serialize verifying key: {e}"))?;
        if vkey.len() != 33 {
            bail!("invalid verifying key length");
        }
        let mut verifying_key_sec1 = [0u8; 33];
        verifying_key_sec1.copy_from_slice(&vkey);

        let mut verifying_shares_sec1: BTreeMap<Vec<u8>, [u8; 33]> =
            BTreeMap::new();
        for (id, vs) in pkg.verifying_shares().iter() {
            let id_bytes = id.serialize();
            let vs_bytes = vs
                .serialize()
                .map_err(|e| anyhow!("serialize verifying share: {e}"))?;
            if vs_bytes.len() != 33 {
                bail!("invalid verifying share size");
            }
            let mut arr = [0u8; 33];
            arr.copy_from_slice(&vs_bytes);
            verifying_shares_sec1.insert(id_bytes, arr);
        }
        Ok(Self { verifying_key_sec1, verifying_shares_sec1 })
    }

    pub(super) fn to_frost(
        &self,
    ) -> AnyResult<frost_secp256k1_tr::keys::PublicKeyPackage> {
        use anyhow::anyhow;
        use frost_secp256k1_tr::{VerifyingKey, keys::VerifyingShare};

        let verifying_key = VerifyingKey::deserialize(&self.verifying_key_sec1)
            .map_err(|e| anyhow!("deserialize verifying key: {e}"))?;

        let mut vshares: BTreeMap<
            frost_secp256k1_tr::Identifier,
            VerifyingShare,
        > = BTreeMap::new();
        for (id_bytes, sec1) in &self.verifying_shares_sec1 {
            let id = frost_secp256k1_tr::Identifier::deserialize(id_bytes)
                .map_err(|e| anyhow!("deserialize identifier: {e}"))?;
            let vs = VerifyingShare::deserialize(sec1)
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
    pub(super) pubkey_package: FrostPublicKeyPackage,
    id_map: BTreeMap<XID, Identifier>,
}

impl FrostGroup {
    pub(super) fn new(
        threshold: usize,
        members: Vec<XID>,
        pubkey_package: FrostPublicKeyPackage,
        id_map: BTreeMap<XID, Identifier>,
    ) -> Self {
        Self { threshold, members, pubkey_package, id_map }
    }

    pub fn verifying_signing_key(&self) -> SigningPublicKey {
        self.pubkey_package.verifying_signing_key()
    }

    pub(super) fn id_for_xid(&self, xid: &XID) -> AnyResult<Identifier> {
        self.id_map
            .get(xid)
            .cloned()
            .ok_or_else(|| anyhow!("unknown member XID in group: {}", xid))
    }

    pub(super) fn to_frost_public_key_package(
        &self,
    ) -> AnyResult<frost_secp256k1_tr::keys::PublicKeyPackage> {
        self.pubkey_package.to_frost()
    }

    /// Create a FROST group with a trusted dealer and return signer contexts.
    /// Returns the group and a map of XID -> FrostParticipant (each holding its
    /// secret share).
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
            participants.insert(xid, FrostParticipant::new(xid, *id, kp));
        }

        let pubkey_pkg =
            FrostPublicKeyPackage::from_frost(&public_key_package)?;
        let group = FrostGroup::new(threshold, members, pubkey_pkg, id_map);

        Ok((group, participants))
    }
}
