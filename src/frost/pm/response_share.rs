use bc_components::{ARID, XID};
use k256::{FieldBytes, Scalar, elliptic_curve::PrimeField};

use crate::{Error, Result};

fn scalar_from_be_bytes(bytes: &[u8]) -> Result<Scalar> {
    let array: [u8; 32] = bytes
        .try_into()
        .map_err(|_| Error::msg("invalid scalar length"))?;
    let field_bytes = FieldBytes::from(array);
    Option::<Scalar>::from(Scalar::from_repr(field_bytes))
        .ok_or_else(|| Error::msg("scalar out of range"))
}

fn scalar_to_be_bytes(scalar: &Scalar) -> [u8; 32] { scalar.to_bytes().into() }

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
