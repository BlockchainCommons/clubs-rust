use bc_components::XID;
use bc_envelope::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FrostSigningCommitment {
    pub xid: XID,
    pub(crate) hiding: [u8; 33],
    pub(crate) binding: [u8; 33],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FrostSigningPackageG {
    pub(crate) message: Vec<u8>,
    pub(crate) commitments: Vec<FrostSigningCommitment>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FrostSignatureShare {
    pub xid: XID,
    pub(crate) share: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FrostSignatureSharesG {
    pub(crate) shares: Vec<FrostSignatureShare>,
}

impl FrostSignatureSharesG {
    pub fn new(shares: Vec<FrostSignatureShare>) -> Self { Self { shares } }
}

pub fn build_signing_package(
    envelope: &Envelope,
    commitments: Vec<FrostSigningCommitment>,
) -> FrostSigningPackageG {
    let subj = envelope.subject();
    let d = subj.digest();
    let message = d.as_ref().data().to_vec();
    FrostSigningPackageG { message, commitments }
}
