use std::collections::BTreeMap;

use bc_components::{ARID, XID};
use k256::{ProjectivePoint, Scalar};

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

    pub fn roster(&self) -> impl Iterator<Item = (&XID, &Scalar)> {
        self.lambda_factors.iter()
    }
}
