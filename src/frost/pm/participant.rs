use bc_components::{ARID, XID};
use k256::{ProjectivePoint, Scalar};
use rand_core::OsRng;

use crate::frost::{
    group::FrostGroup,
    signing::participant::FrostSigningParticipant,
};
use crate::{Error, Result};
use frost_secp256k1_tr as frost;

use crate::frost::pm::{
    commitment::FrostPmCommitment,
    gamma_share::FrostPmGammaShare,
    primitives::point_bytes,
    response_share::{
        FrostPmResponseShare, response_share_scalar_from_bytes,
    },
    signing_package::FrostPmSigningPackage,
};

#[derive(Clone)]
pub struct FrostPmParticipant {
    xid: XID,
    key_package: frost::keys::KeyPackage,
    session: Option<ARID>,
    nonce: Option<Scalar>,
    lambda_share: Option<Scalar>,
}

impl FrostPmParticipant {
    pub fn new(xid: XID, key_package: frost::keys::KeyPackage) -> Self {
        Self { xid, key_package, session: None, nonce: None, lambda_share: None }
    }

    pub fn from_signing(participant: &FrostSigningParticipant) -> Self {
        Self::new(participant.xid(), participant.key_package().clone())
    }

    pub fn xid(&self) -> XID { self.xid }

    fn key_package(&self) -> &frost::keys::KeyPackage { &self.key_package }

    /// Round-1: generate per-signer commitments A=k·G and B=k·H for the provided hash point H.
    pub fn pm_round1_commit(
        &mut self,
        session: ARID,
        h_point: &ProjectivePoint,
    ) -> Result<FrostPmCommitment> {
        if let Some(existing) = self.session {
            if existing != session {
                return Err(Error::msg(
                    "participant active in different pm session",
                ));
            }
        }

        let mut rng = OsRng;
        let nonce = Scalar::generate_vartime(&mut rng);
        let g_commitment = point_bytes(&(ProjectivePoint::GENERATOR * nonce))?;
        let h_commitment = point_bytes(&((*h_point) * nonce))?;

        self.session = Some(session);
        self.nonce = Some(nonce);
        self.lambda_share = None;

        Ok(FrostPmCommitment {
            xid: self.xid,
            session,
            g_commitment,
            h_commitment,
        })
    }

    /// Round-2a: given the coordinator package, emit the participant's contribution to Γ.
    pub fn pm_round2_emit_gamma(
        &mut self,
        _group: &FrostGroup,
        package: &FrostPmSigningPackage,
    ) -> Result<FrostPmGammaShare> {
        let session = self.session.ok_or_else(|| {
            Error::msg("pm_round1_commit must be called first")
        })?;
        if package.session != session {
            return Err(Error::msg("signing package session mismatch"));
        }

        let lambda = package
            .lambda_for(&self.xid)
            .ok_or_else(|| Error::msg("missing lambda for participant"))?;

        let share_bytes = self.key_package().signing_share().serialize();
        let signing_share = response_share_scalar_from_bytes(&share_bytes)?;
        let lambda_share = lambda * signing_share;

        let gamma_point = package.h_point * lambda_share;
        let gamma_bytes = point_bytes(&gamma_point)?;

        self.lambda_share = Some(lambda_share);

        Ok(FrostPmGammaShare { xid: self.xid, session, gamma_bytes })
    }

    /// Round-2b: after receiving the challenge, emit the participant's partial `z` response.
    pub fn pm_finalize_response(
        &mut self,
        challenge: &Scalar,
    ) -> Result<FrostPmResponseShare> {
        let session = self.session.ok_or_else(|| {
            Error::msg("pm_round1_commit must be called first")
        })?;
        let nonce = self.nonce.ok_or_else(|| {
            Error::msg("pm_round2_emit_gamma must be called first")
        })?;
        let lambda_share = self.lambda_share.ok_or_else(|| {
            Error::msg("pm_round2_emit_gamma must be called first")
        })?;

        let z_share = nonce + (*challenge * lambda_share);

        // Clear state to avoid nonce reuse in future ceremonies.
        self.session = None;
        self.nonce = None;
        self.lambda_share = None;
        Ok(FrostPmResponseShare::from_scalar(self.xid, session, &z_share))
    }
}
