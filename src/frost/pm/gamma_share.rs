use bc_components::{ARID, XID};
use k256::ProjectivePoint;

use crate::{Result, frost::pm::primitives::point_from_bytes};

/// Participant contribution to the VRF output Γ.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FrostPmGammaShare {
    pub xid: XID,
    pub session: ARID,
    pub gamma_bytes: [u8; 33],
}

impl FrostPmGammaShare {
    pub fn to_point(&self) -> Result<ProjectivePoint> {
        point_from_bytes(&self.gamma_bytes).map_err(Into::into)
    }
}
