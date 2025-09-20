use std::collections::BTreeMap;

use crate::{Error, Result};
use bc_components::{ARID, DigestProvider, XID};
use frost_secp256k1_tr::{
    self as frost, Identifier,
    round1::{NonceCommitment, SigningCommitments},
};
use rand::rngs::OsRng;

use super::{
    group::FrostGroup,
    signing::{
        FrostSignatureShare, FrostSigningCommitment, FrostSigningPackage,
    },
};

pub struct FrostParticipant {
    xid: XID,
    key_package: frost::keys::KeyPackage,
    nonces: Option<frost::round1::SigningNonces>,
}

impl FrostParticipant {
    pub fn new(xid: XID, key_package: frost::keys::KeyPackage) -> Self {
        Self { xid, key_package, nonces: None }
    }

    pub fn xid(&self) -> XID {
        self.xid
    }

    /// Perform Round-1 locally: generate nonces and commitments. Stores nonces
    /// for Round-2. Binds to a specific session.
    pub fn round1_commit(
        &mut self,
        session: ARID,
    ) -> Result<FrostSigningCommitment> {
        let (nonces, comms) =
            frost::round1::commit(self.key_package.signing_share(), &mut OsRng);
        self.nonces = Some(nonces);
        let hid = comms.hiding().serialize().map_err(|e| {
            Error::msg(format!("serialize hiding commitment: {e}"))
        })?;
        let bind = comms.binding().serialize().map_err(|e| {
            Error::msg(format!("serialize binding commitment: {e}"))
        })?;
        FrostSigningCommitment::new(self.xid, session, &hid, &bind)
    }

    /// Perform Round-2 locally: produce a signature share using stored nonces.
    pub fn round2_sign(
        &self,
        group: &FrostGroup,
        signing_pkg: &FrostSigningPackage,
    ) -> Result<FrostSignatureShare> {
        let nonces = self.nonces.as_ref().ok_or_else(|| {
            Error::msg(format!(
                "round1_commit must be called before round2_sign for signer {}",
                self.xid
            ))
        })?;

        // Convert commitments to frost SigningPackage
        let mut frost_commitments: BTreeMap<Identifier, SigningCommitments> =
            BTreeMap::new();
        for comm in &signing_pkg.commitments {
            let id = group.id_for_xid(&comm.xid)?;
            let hiding = NonceCommitment::deserialize(comm.hiding.as_ref())
                .map_err(|e| Error::msg(format!("deserialize hiding: {e}")))?;
            let binding = NonceCommitment::deserialize(comm.binding.as_ref())
                .map_err(|e| {
                Error::msg(format!("deserialize binding: {e}"))
            })?;
            frost_commitments
                .insert(id, SigningCommitments::new(hiding, binding));
        }
        // Derive message digest from the package's message Envelope subject
        let subj_env = signing_pkg.message.subject();
        let msg_digest = subj_env.digest();
        let msg_bytes: &[u8] = msg_digest.as_ref().as_ref();
        let frost_sp = frost::SigningPackage::new(frost_commitments, msg_bytes);

        let share = frost::round2::sign(&frost_sp, nonces, &self.key_package)
            .map_err(|e| {
            Error::msg(format!("round2 sign failed for {}: {e}", self.xid))
        })?;
        Ok(FrostSignatureShare {
            xid: self.xid,
            session: signing_pkg.session,
            share: share.serialize(),
        })
    }
}
