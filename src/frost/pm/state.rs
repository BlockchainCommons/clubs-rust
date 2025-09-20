use dcbor::Date;
use k256::ProjectivePoint;
use provenance_mark::{ProvenanceMark, ProvenanceMarkResolution};
use sha2::{Digest, Sha256};

use crate::frost::group::FrostGroup;
use crate::frost::pm::primitives::{
    DleqProof, expand_mark_key, hash_to_curve, key_from_gamma, pm_message,
    point_bytes, point_from_bytes, ratchet_state, vrf_verify_for_x,
};
use crate::{Error, Result};

const GENESIS_DST: &[u8] = b"PM-Genesis";
const CHAIN_ID_DST: &[u8] = b"PM-CHAIN-ID";

fn genesis_state() -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(GENESIS_DST);
    let digest = hasher.finalize();
    let mut state = [0u8; 32];
    state.copy_from_slice(&digest);
    state
}

fn derive_chain_id(
    resolution: ProvenanceMarkResolution,
    group_point: &ProjectivePoint,
    label: &[u8],
) -> Result<Vec<u8>> {
    let x_bytes = point_bytes(group_point)?;
    let mut hasher = Sha256::new();
    hasher.update(CHAIN_ID_DST);
    hasher.update(x_bytes);
    hasher.update(label);
    let digest = hasher.finalize();
    Ok(digest[..resolution.link_length()].to_vec())
}

pub struct FrostProvenanceChain {
    // --- Chain identity (never changes) ---
    /// How long each link in the chain is (short, medium, etc.) so humans know
    /// what sort of identifier to expect.
    resolution: ProvenanceMarkResolution,
    /// Public anchor that identifies this chain; stays the same no matter which
    /// quorum advances it.
    chain_id: Vec<u8>,
    /// The group’s shared public key point on the curve; needed for VRF checks.
    group_point: ProjectivePoint,

    // --- Rolling state (updates every time a new mark is published) ---
    /// The key revealed in the most recently published mark.
    last_key: Vec<u8>,
    /// Public “memory” derived from prior marks so anyone can build the next
    /// VRF message deterministically.
    ratchet_state: [u8; 32],
    /// How many marks have been published so far (starting at zero for genesis).
    sequence: u32,
    /// Timestamp attached to the most recent mark, used to ensure time never
    /// moves backwards.
    last_date: Date,
}

impl FrostProvenanceChain {
    pub fn new(
        group: &FrostGroup,
        resolution: ProvenanceMarkResolution,
        label: impl AsRef<[u8]>,
        genesis_date: Date,
    ) -> Result<Self> {
        let group_point = group.verifying_key_point()?;
        let chain_id =
            derive_chain_id(resolution, &group_point, label.as_ref())?;
        let state = genesis_state();
        Ok(Self {
            resolution,
            chain_id: chain_id.clone(),
            group_point,
            last_key: chain_id,
            ratchet_state: state,
            sequence: 0,
            last_date: genesis_date,
        })
    }

    pub fn chain_id(&self) -> &[u8] {
        &self.chain_id
    }
    pub fn sequence(&self) -> u32 {
        self.sequence
    }
    pub fn last_date(&self) -> &Date {
        &self.last_date
    }
    pub fn resolution(&self) -> ProvenanceMarkResolution {
        self.resolution
    }

    pub fn verify_advance(
        &mut self,
        mark: &ProvenanceMark,
        gamma_bytes: &[u8; 33],
        proof: &DleqProof,
    ) -> Result<()> {
        if mark.chain_id() != self.chain_id {
            return Err(Error::msg("advance chain id mismatch"));
        }
        if mark.seq() != self.sequence {
            return Err(Error::msg("advance sequence mismatch"));
        }
        if mark.key() != self.last_key {
            return Err(Error::msg("advance key mismatch"));
        }
        if mark.date() < &self.last_date {
            return Err(Error::msg("advance date regresses"));
        }

        let next_step = (self.sequence as u64) + 1;
        let message = pm_message(
            &self.group_point,
            &self.chain_id,
            &self.ratchet_state,
            next_step,
        )?;
        let h_point = hash_to_curve(&message)?;
        let gamma_point = point_from_bytes(gamma_bytes)?;
        vrf_verify_for_x(&self.group_point, &h_point, &gamma_point, proof)?;

        let full_key = key_from_gamma(&gamma_point)?;
        let link_len = self.resolution.link_length();
        let next_key_vec = full_key[..link_len].to_vec();

        let rebuilt = ProvenanceMark::new(
            self.resolution,
            self.last_key.clone(),
            next_key_vec.clone(),
            self.chain_id.clone(),
            self.sequence,
            mark.date().clone(),
            mark.info(),
        )?;
        if rebuilt != *mark {
            return Err(Error::msg("advance mark does not match VRF output"));
        }

        let expanded_key = expand_mark_key(&next_key_vec);
        self.ratchet_state = ratchet_state(&self.ratchet_state, &expanded_key);
        self.last_key = next_key_vec;
        self.sequence += 1;
        self.last_date = mark.date().clone();
        Ok(())
    }
}
