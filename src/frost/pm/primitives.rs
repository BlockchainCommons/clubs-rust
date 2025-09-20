//! Low-level cryptographic primitives for FROST-controlled provenance marks.

use core::ops::Add;

use frost_secp256k1_tr as frost;
use frost_secp256k1_tr::Group;
use k256::{
    AffinePoint, EncodedPoint, ProjectivePoint, Scalar, Secp256k1,
    elliptic_curve::{
        hash2curve::{ExpandMsgXmd, GroupDigest},
        sec1::{FromEncodedPoint, ToEncodedPoint},
    },
};
use rand_core::OsRng;
use sha2::{Digest, Sha256};
use thiserror::Error;

/// Domain separator for the hash-to-curve operation.
pub const H2C_DST: &[u8] = b"FROST-VRF-secp256k1-SHA256-RO";
/// Domain separator used when computing the DLEQ challenge scalar.
pub const DLEQ_DST: &[u8] = b"FROST-VRF-DLEQ-2025";
/// Domain separation tag for deriving provenance mark keys from VRF outputs.
pub const PM_KEY_DST: &[u8] = b"PMKEY-v1";
/// Domain separation tag for the ratchet state updates.
pub const PM_STATE_DST: &[u8] = b"PMSTATE-v1";
/// Prefix used when constructing the provenance mark VRF message.
pub const PM_MESSAGE_PREFIX: &[u8] = b"PMVRF-secp256k1-v1";
/// Domain separation tag for expanding truncated keys.
pub const PM_KEY32_DST: &[u8] = b"PM-KEY32";

/// Errors encountered while operating on the VRF / DLEQ primitives.
#[derive(Debug, Error)]
pub enum FrostPmError {
    #[error("malformed SEC1 encoding")]
    PointEncoding,
    #[error("group point serialization failure: {0}")]
    Serialization(&'static str),
    #[error("hash-to-curve failure")]
    HashToCurve,
    #[error("dleq challenge mismatch")]
    ChallengeMismatch,
    #[error("dleq relation failed for {0}")]
    Relation(&'static str),
}

pub type Result<T> = std::result::Result<T, FrostPmError>;

impl From<FrostPmError> for crate::Error {
    fn from(err: FrostPmError) -> Self {
        crate::Error::msg(err.to_string())
    }
}

/// Compact DLEQ proof that `log_G(X) = log_H(Gamma)`.
#[derive(Clone, Debug)]
pub struct DleqProof {
    /// `A = k·G` encoded as compressed SEC1 bytes.
    pub a_bytes: [u8; 33],
    /// `B = k·H` encoded as compressed SEC1 bytes.
    pub b_bytes: [u8; 33],
    /// Fiat–Shamir challenge scalar.
    pub e: Scalar,
    /// Schnorr response `z = k + e·x`.
    pub z: Scalar,
}

/// Return the compressed 33-byte SEC1 encoding for a projective point.
pub fn point_bytes(point: &ProjectivePoint) -> Result<[u8; 33]> {
    let affine: AffinePoint = (*point).to_affine();
    let encoded = affine.to_encoded_point(true);
    let bytes = encoded.as_bytes();
    if bytes.len() != 33 {
        return Err(FrostPmError::Serialization("point_bytes-length"));
    }
    let mut out = [0u8; 33];
    out.copy_from_slice(bytes);
    Ok(out)
}

/// Deserialize a compressed 33-byte SEC1 encoding into a projective point.
pub fn point_from_bytes(bytes: &[u8; 33]) -> Result<ProjectivePoint> {
    let encoded = EncodedPoint::from_bytes(bytes)
        .map_err(|_| FrostPmError::PointEncoding)?;
    let opt_affine = AffinePoint::from_encoded_point(&encoded);
    let affine = Option::<AffinePoint>::from(opt_affine)
        .ok_or(FrostPmError::PointEncoding)?;
    Ok(ProjectivePoint::from(affine))
}

/// Hash arbitrary data onto the secp256k1 curve using the random oracle map.
pub fn hash_to_curve(msg: &[u8]) -> Result<ProjectivePoint> {
    <Secp256k1 as GroupDigest>::hash_from_bytes::<ExpandMsgXmd<Sha256>>(
        &[msg],
        &[H2C_DST],
    )
    .map_err(|_| FrostPmError::HashToCurve)
}

fn serialize_for_transcript(
    point: &ProjectivePoint,
    label: &'static str,
) -> Result<[u8; 33]> {
    let bytes =
        <frost::Secp256K1Sha256TR as frost::Ciphersuite>::Group::serialize(
            point,
        )
        .map_err(|_| FrostPmError::Serialization(label))?;
    if bytes.len() != 33 {
        return Err(FrostPmError::Serialization(label));
    }
    let mut arr = [0u8; 33];
    arr.copy_from_slice(&bytes);
    Ok(arr)
}

fn dleq_challenge_x(
    x_point: &ProjectivePoint,
    gamma: &ProjectivePoint,
    a: &ProjectivePoint,
    b: &ProjectivePoint,
) -> Result<Scalar> {
    let xb = serialize_for_transcript(x_point, "challenge-X")?;
    let gb = serialize_for_transcript(gamma, "challenge-Gamma")?;
    let ab = serialize_for_transcript(a, "challenge-A")?;
    let bb = serialize_for_transcript(b, "challenge-B")?;

    let mut input = Vec::with_capacity(4 * 33 + DLEQ_DST.len());
    input.extend_from_slice(&xb);
    input.extend_from_slice(&gb);
    input.extend_from_slice(&ab);
    input.extend_from_slice(&bb);
    input.extend_from_slice(DLEQ_DST);

    Ok(<frost::Secp256K1Sha256TR as frost::Ciphersuite>::H2(&input))
}

/// Compute the VRF output `Gamma = x·H` and return it together with a DLEQ proof.
pub fn vrf_gamma_and_proof_for_x(
    x: &Scalar,
    x_point: &ProjectivePoint,
    h_point: &ProjectivePoint,
) -> Result<(ProjectivePoint, DleqProof)> {
    let gamma = (*h_point) * (*x);

    let k = Scalar::generate_vartime(&mut OsRng);
    let a = ProjectivePoint::GENERATOR * k;
    let b = (*h_point) * k;

    let e = dleq_challenge_x(x_point, &gamma, &a, &b)?;
    let z = k + e * (*x);

    let a_bytes = point_bytes(&a)?;
    let b_bytes = point_bytes(&b)?;

    Ok((gamma, DleqProof { a_bytes, b_bytes, e, z }))
}

/// Verify a DLEQ proof tying the group public key to a VRF output.
pub fn vrf_verify_for_x(
    x_point: &ProjectivePoint,
    h_point: &ProjectivePoint,
    gamma: &ProjectivePoint,
    proof: &DleqProof,
) -> Result<()> {
    let a = point_from_bytes(&proof.a_bytes)?;
    let b = point_from_bytes(&proof.b_bytes)?;

    let e_chk = dleq_challenge_x(x_point, gamma, &a, &b)?;
    if e_chk != proof.e {
        return Err(FrostPmError::ChallengeMismatch);
    }

    let lhs_g = ProjectivePoint::GENERATOR * proof.z;
    let rhs_g = a.add((*x_point) * proof.e);
    if lhs_g != rhs_g {
        return Err(FrostPmError::Relation("generator"));
    }

    let lhs_h = (*h_point) * proof.z;
    let rhs_h = b.add((*gamma) * proof.e);
    if lhs_h != rhs_h {
        return Err(FrostPmError::Relation("hash point"));
    }

    Ok(())
}

/// Expose the DLEQ challenge computation for coordinators aggregating proofs.
pub fn dleq_challenge(
    x_point: &ProjectivePoint,
    gamma: &ProjectivePoint,
    a: &ProjectivePoint,
    b: &ProjectivePoint,
) -> Result<Scalar> {
    dleq_challenge_x(x_point, gamma, a, b)
}

/// Build the provenance mark VRF message for a given step index.
pub fn pm_message(
    x_point: &ProjectivePoint,
    chain_id: &[u8],
    state_prev: &[u8; 32],
    step: u64,
) -> Result<Vec<u8>> {
    let x_bytes = serialize_for_transcript(x_point, "pm_message-X")?;
    let mut msg = Vec::with_capacity(
        PM_MESSAGE_PREFIX.len()
            + x_bytes.len()
            + chain_id.len()
            + state_prev.len()
            + 8,
    );
    msg.extend_from_slice(PM_MESSAGE_PREFIX);
    msg.extend_from_slice(&x_bytes);
    msg.extend_from_slice(chain_id);
    msg.extend_from_slice(state_prev);
    msg.extend_from_slice(&step.to_be_bytes());
    Ok(msg)
}

/// Derive a 32-byte provenance mark key from a VRF output point.
pub fn key_from_gamma(gamma: &ProjectivePoint) -> Result<[u8; 32]> {
    let gamma_bytes = serialize_for_transcript(gamma, "key_from_gamma")?;
    let mut hasher = Sha256::new();
    hasher.update(PM_KEY_DST);
    hasher.update(gamma_bytes);
    let digest = hasher.finalize();
    let mut key = [0u8; 32];
    key.copy_from_slice(&digest);
    Ok(key)
}

/// Update the public ratchet state: `S_j = H(PMSTATE || S_{j-1} || key_j)`.
pub fn ratchet_state(state_prev: &[u8; 32], key_j: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(PM_STATE_DST);
    hasher.update(state_prev);
    hasher.update(key_j);
    let digest = hasher.finalize();
    let mut next = [0u8; 32];
    next.copy_from_slice(&digest);
    next
}

/// Ensure a reconstructed secret scalar matches the published group key with Taproot parity.
pub fn normalize_secret_to_pubkey(
    mut x: Scalar,
    expected: &ProjectivePoint,
) -> Result<Scalar> {
    let candidate = ProjectivePoint::GENERATOR * x;
    if candidate == *expected {
        return Ok(x);
    }

    x = -x;
    let neg_candidate = ProjectivePoint::GENERATOR * x;
    if neg_candidate == *expected {
        return Ok(x);
    }

    Err(FrostPmError::Relation("normalize-secret"))
}

/// Expand a truncated provenance mark key to 32 bytes for ratcheting.
pub fn expand_mark_key(key_trunc: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(PM_KEY32_DST);
    hasher.update(key_trunc);
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}
