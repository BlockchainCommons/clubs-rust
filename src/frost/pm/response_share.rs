use bc_components::{ARID, XID};
use k256::Scalar;

use crate::{
    Result,
    frost::pm::{scalar_from_be_bytes, scalar_to_be_bytes},
};

/// Participant response share for the DLEQ proof (partial `z`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FrostPmResponseShare {
    pub xid: XID,
    pub session: ARID,
    pub z_bytes: [u8; 32],
}

impl FrostPmResponseShare {
    pub fn to_scalar(&self) -> Result<Scalar> {
        scalar_from_be_bytes(&self.z_bytes)
    }

    pub fn from_scalar(xid: XID, session: ARID, scalar: &Scalar) -> Self {
        Self { xid, session, z_bytes: scalar_to_be_bytes(scalar) }
    }
}

pub(crate) fn response_share_scalar_from_bytes(bytes: &[u8]) -> Result<Scalar> {
    scalar_from_be_bytes(bytes)
}
