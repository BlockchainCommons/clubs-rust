use std::collections::BTreeMap;

use bc_components::XID;
use bc_envelope::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FrostSigningCommitmentSec1 {
    pub(crate) hiding: [u8; 33],
    pub(crate) binding: [u8; 33],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FrostSigningPackageG {
    pub(crate) message: Vec<u8>,
    pub(crate) commitments: BTreeMap<XID, FrostSigningCommitmentSec1>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FrostSignatureSharesG {
    pub(crate) shares: BTreeMap<XID, Vec<u8>>, // serialized scalar shares
}

impl FrostSignatureSharesG {
    pub fn new(shares: BTreeMap<XID, Vec<u8>>) -> Self { Self { shares } }
}

pub fn build_signing_package(
    envelope: &Envelope,
    commitments: BTreeMap<XID, FrostSigningCommitmentSec1>,
) -> FrostSigningPackageG {
    let subj = envelope.subject();
    let d = subj.digest();
    let message = d.as_ref().data().to_vec();
    FrostSigningPackageG { message, commitments }
}

