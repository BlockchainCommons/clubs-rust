use std::collections::BTreeMap;

use bc_components::{ARID, XID};
use k256::elliptic_curve::PrimeField;
use k256::{FieldBytes, ProjectivePoint, Scalar};
use rand_core::OsRng;

use crate::frost::{
    group::FrostGroup,
    participant::FrostParticipant,
    pm::primitives::{point_bytes, point_from_bytes},
};
use crate::{Error, Result};

/// Round-1 commitment for a provenance-mark VRF ceremony.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FrostPmCommitment {
    pub xid: XID,
    pub session: ARID,
    pub g_commitment: [u8; 33],
    pub h_commitment: [u8; 33],
}

/// Signing package distributed by the coordinator prior to computing VRF shares.
#[derive(Clone, Debug)]
pub struct FrostPmSigningPackage {
    pub session: ARID,
    pub h_point: ProjectivePoint,
    pub lambda_factors: BTreeMap<XID, Scalar>,
}

impl FrostPmSigningPackage {
    pub fn lambda_for(&self, xid: &XID) -> Option<Scalar> {
        self.lambda_factors.get(xid).copied()
    }
}

/// Participant contribution to the VRF output Γ.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FrostPmGammaShare {
    pub xid: XID,
    pub session: ARID,
    pub gamma_bytes: [u8; 33],
}

/// Participant response share for the DLEQ proof (partial `z`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FrostPmResponseShare {
    pub xid: XID,
    pub session: ARID,
    pub z_bytes: [u8; 32],
}

fn scalar_from_be_bytes(bytes: &[u8]) -> Result<Scalar> {
    let array: [u8; 32] = bytes
        .try_into()
        .map_err(|_| Error::msg("invalid scalar length"))?;
    let field_bytes = FieldBytes::from(array);
    Option::<Scalar>::from(Scalar::from_repr(field_bytes))
        .ok_or_else(|| Error::msg("scalar out of range"))
}

fn scalar_to_be_bytes(scalar: &Scalar) -> [u8; 32] {
    scalar.to_bytes().into()
}

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
        let signing_share = scalar_from_be_bytes(&share_bytes)?;
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
        let z_bytes = scalar_to_be_bytes(&z_share);

        // Clear state to avoid nonce reuse in future ceremonies.
        self.pm_session = None;
        self.pm_nonce = None;
        self.pm_lambda_share = None;
        Ok(FrostPmResponseShare { xid: self.xid(), session, z_bytes })
    }
}

impl FrostPmGammaShare {
    pub fn to_point(&self) -> Result<ProjectivePoint> {
        point_from_bytes(&self.gamma_bytes).map_err(Into::into)
    }
}

impl FrostPmCommitment {
    pub fn g_point(&self) -> Result<ProjectivePoint> {
        point_from_bytes(&self.g_commitment).map_err(Into::into)
    }

    pub fn h_point(&self) -> Result<ProjectivePoint> {
        point_from_bytes(&self.h_commitment).map_err(Into::into)
    }
}

impl FrostPmResponseShare {
    pub fn to_scalar(&self) -> Result<Scalar> {
        scalar_from_be_bytes(&self.z_bytes)
    }
}

impl FrostPmSigningPackage {
    pub fn roster(&self) -> impl Iterator<Item = (&XID, &Scalar)> {
        self.lambda_factors.iter()
    }
}
