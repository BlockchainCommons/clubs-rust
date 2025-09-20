use bc_components::ARID;
use k256::{ProjectivePoint, Scalar};
use rand_core::OsRng;

use crate::frost::{
    group::FrostGroup,
    participant::FrostParticipant,
    pm::{
        commitment::FrostPmCommitment,
        gamma_share::FrostPmGammaShare,
        primitives::point_bytes,
        response_share::{FrostPmResponseShare, response_share_scalar_from_bytes},
        signing_package::FrostPmSigningPackage,
    },
};
use crate::{Error, Result};

impl FrostParticipant {
    /// Round-1: generate per-signer commitments A=k·G and B=k·H for the provided hash point H.
    pub fn pm_round1_commit(
        &mut self,
        session: ARID,
        h_point: &ProjectivePoint,
    ) -> Result<FrostPmCommitment> {
        if let Some(existing) = self.pm_session {
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

        self.pm_session = Some(session);
        self.pm_nonce = Some(nonce);
        self.pm_lambda_share = None;

        Ok(FrostPmCommitment {
            xid: self.xid(),
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
        let session = self.pm_session.ok_or_else(|| {
            Error::msg("pm_round1_commit must be called first")
        })?;
        if package.session != session {
            return Err(Error::msg("signing package session mismatch"));
        }

        let lambda = package
            .lambda_for(&self.xid())
            .ok_or_else(|| Error::msg("missing lambda for participant"))?;

        let share_bytes = self.key_package().signing_share().serialize();
        let signing_share = response_share_scalar_from_bytes(&share_bytes)?;
        let lambda_share = lambda * signing_share;

        let gamma_point = package.h_point * lambda_share;
        let gamma_bytes = point_bytes(&gamma_point)?;

        self.pm_lambda_share = Some(lambda_share);

        Ok(FrostPmGammaShare { xid: self.xid(), session, gamma_bytes })
    }

    /// Round-2b: after receiving the challenge, emit the participant's partial `z` response.
    pub fn pm_finalize_response(
        &mut self,
        challenge: &Scalar,
    ) -> Result<FrostPmResponseShare> {
        let session = self.pm_session.ok_or_else(|| {
            Error::msg("pm_round1_commit must be called first")
        })?;
        let nonce = self.pm_nonce.ok_or_else(|| {
            Error::msg("pm_round2_emit_gamma must be called first")
        })?;
        let lambda_share = self.pm_lambda_share.ok_or_else(|| {
            Error::msg("pm_round2_emit_gamma must be called first")
        })?;

        let z_share = nonce + (*challenge * lambda_share);

        // Clear state to avoid nonce reuse in future ceremonies.
        self.pm_session = None;
        self.pm_nonce = None;
        self.pm_lambda_share = None;
        Ok(FrostPmResponseShare::from_scalar(self.xid(), session, &z_share))
    }
}
