use bc_components::{ARID, XID};
use k256::ProjectivePoint;

use crate::frost::pm::primitives::point_from_bytes;
use crate::Result;

/// Round-1 commitment for a provenance-mark VRF ceremony.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FrostPmCommitment {
    pub xid: XID,
    pub session: ARID,
    pub g_commitment: [u8; 33],
    pub h_commitment: [u8; 33],
}

impl FrostPmCommitment {
    pub fn g_point(&self) -> Result<ProjectivePoint> {
        point_from_bytes(&self.g_commitment).map_err(Into::into)
    }

    pub fn h_point(&self) -> Result<ProjectivePoint> {
        point_from_bytes(&self.h_commitment).map_err(Into::into)
    }
}
