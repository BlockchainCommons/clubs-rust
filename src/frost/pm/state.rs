use std::collections::BTreeMap;

use bc_components::XID;
use dcbor::Date;
use k256::ProjectivePoint;
use provenance_mark::{ProvenanceMark, ProvenanceMarkResolution};
use sha2::{Digest, Sha256};

use crate::frost::pm::primitives::{
    DleqProof, expand_mark_key, hash_to_curve, key_from_gamma, pm_message,
    point_bytes, point_from_bytes, ratchet_state, vrf_verify_for_x,
};
use crate::frost::{
    group::FrostGroup, participant::FrostParticipant, pm::FrostPmCoordinator,
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

#[derive(Clone, Debug)]
pub struct FrostProvenanceAdvance {
    pub mark: ProvenanceMark,
    pub gamma_bytes: [u8; 33],
    pub proof: DleqProof,
}

pub struct FrostProvenanceChain {
    resolution: ProvenanceMarkResolution,
    chain_id: Vec<u8>,
    current_key: Vec<u8>,
    ratchet_state: [u8; 32],
    sequence: u32,
    last_date: Date,
    group_point: ProjectivePoint,
    group_clone: FrostGroup,
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
            current_key: chain_id,
            ratchet_state: state,
            sequence: 0,
            last_date: genesis_date,
            group_point,
            group_clone: group.clone(),
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

    pub fn advance(
        &mut self,
        coordinator: &mut FrostPmCoordinator,
        participants: &mut BTreeMap<XID, FrostParticipant>,
        roster: &[XID],
        date: Date,
    ) -> Result<FrostProvenanceAdvance> {
        if date < self.last_date {
            return Err(Error::msg("provenance date must be non-decreasing"));
        }

        let next_step = (self.sequence as u64) + 1;
        let message = pm_message(
            &self.group_point,
            &self.chain_id,
            &self.ratchet_state,
            next_step,
        )?;
        let h_point = hash_to_curve(&message)?;

        coordinator.start_session();
        let session = coordinator.session_id();

        for xid in roster {
            let signer = participants.get_mut(xid).ok_or_else(|| {
                Error::msg(format!("unknown participant: {}", xid))
            })?;
            let commitment = signer.pm_round1_commit(session, &h_point)?;
            coordinator.add_commitment(commitment)?;
        }

        let signing_package =
            coordinator.signing_package_for(roster, &h_point)?;
        for xid in roster {
            let signer = participants.get_mut(xid).ok_or_else(|| {
                Error::msg(format!("unknown participant: {}", xid))
            })?;
            let gamma_share = signer
                .pm_round2_emit_gamma(&self.group_clone, &signing_package)?;
            coordinator.record_gamma_share(gamma_share)?;
        }

        let challenge = coordinator.challenge()?;
        for xid in roster {
            let signer = participants.get_mut(xid).ok_or_else(|| {
                Error::msg(format!("unknown participant: {}", xid))
            })?;
            let response = signer.pm_finalize_response(&challenge)?;
            coordinator.record_response(response)?;
        }

        let (gamma_point, proof) = coordinator.finalize()?;
        let gamma_bytes = point_bytes(&gamma_point)?;
        let full_key = key_from_gamma(&gamma_point)?;
        let link_len = self.resolution.link_length();
        let mut next_key = vec![0u8; link_len];
        next_key.copy_from_slice(&full_key[..link_len]);

        let mark = ProvenanceMark::new(
            self.resolution,
            self.current_key.clone(),
            next_key.clone(),
            self.chain_id.clone(),
            self.sequence,
            date.clone(),
            Option::<dcbor::CBOR>::None,
        )?;

        // Update chain state for next iteration.
        let expanded_key = expand_mark_key(&next_key);
        self.ratchet_state = ratchet_state(&self.ratchet_state, &expanded_key);
        self.current_key = next_key;
        self.sequence += 1;
        self.last_date = date;

        Ok(FrostProvenanceAdvance { mark, gamma_bytes, proof })
    }

    pub fn verify_advance(
        &mut self,
        advance: &FrostProvenanceAdvance,
    ) -> Result<()> {
        if advance.mark.chain_id() != self.chain_id {
            return Err(Error::msg("advance chain id mismatch"));
        }
        if advance.mark.seq() != self.sequence {
            return Err(Error::msg("advance sequence mismatch"));
        }
        if advance.mark.key() != self.current_key {
            return Err(Error::msg("advance key mismatch"));
        }
        if advance.mark.date() < &self.last_date {
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
        let gamma_point = point_from_bytes(&advance.gamma_bytes)?;
        vrf_verify_for_x(
            &self.group_point,
            &h_point,
            &gamma_point,
            &advance.proof,
        )?;

        let full_key = key_from_gamma(&gamma_point)?;
        let link_len = self.resolution.link_length();
        let next_key_vec = full_key[..link_len].to_vec();

        let rebuilt = ProvenanceMark::new(
            self.resolution,
            self.current_key.clone(),
            next_key_vec.clone(),
            self.chain_id.clone(),
            self.sequence,
            advance.mark.date().clone(),
            advance.mark.info(),
        )?;
        if rebuilt != advance.mark {
            return Err(Error::msg("advance mark does not match VRF output"));
        }

        let expanded_key = expand_mark_key(&next_key_vec);
        self.ratchet_state = ratchet_state(&self.ratchet_state, &expanded_key);
        self.current_key = next_key_vec;
        self.sequence += 1;
        self.last_date = advance.mark.date().clone();
        Ok(())
    }
}
