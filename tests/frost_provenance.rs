use std::collections::BTreeMap;

use bc_components::{PrivateKeyBase, XID, XIDProvider};
use bc_xid::XIDDocument;
use clubs::frost::{
    FrostGroup, FrostParticipant,
    pm::{
        DleqProof, FrostPmCoordinator, FrostProvenanceChain, expand_mark_key,
        hash_to_curve, key_from_gamma, pm_message, point_bytes, ratchet_state,
    },
};
use dcbor::Date;
use k256::ProjectivePoint;
use provenance_mark::{ProvenanceMark, ProvenanceMarkResolution};
use sha2::{Digest, Sha256};

#[derive(Clone)]
struct Advance {
    mark: ProvenanceMark,
    gamma_bytes: [u8; 33],
    proof: DleqProof,
}

struct PublishingState {
    resolution: ProvenanceMarkResolution,
    chain_id: Vec<u8>,
    last_key: Vec<u8>,
    ratchet_state: [u8; 32],
    sequence: u32,
    last_date: Date,
    group: FrostGroup,
    group_point: ProjectivePoint,
}

impl PublishingState {
    fn new(
        group: &FrostGroup,
        resolution: ProvenanceMarkResolution,
        label: &[u8],
        genesis_date: Date,
    ) -> clubs::Result<Self> {
        let group_point = group.verifying_key_point()?;
        let chain_id = derive_chain_id(resolution, &group_point, label)?;
        let ratchet_state = genesis_state();
        Ok(Self {
            resolution,
            chain_id: chain_id.clone(),
            last_key: chain_id,
            ratchet_state,
            sequence: 0,
            last_date: genesis_date,
            group: group.clone(),
            group_point,
        })
    }

    fn run_ceremony(
        &mut self,
        coordinator: &mut FrostPmCoordinator,
        participants: &mut BTreeMap<XID, FrostParticipant>,
        roster: &[XID],
        date: Date,
    ) -> clubs::Result<Advance> {
        if date < self.last_date {
            return Err(clubs::Error::msg(
                "provenance date must be non-decreasing",
            ));
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
                clubs::Error::msg(format!("unknown participant: {}", xid))
            })?;
            let commitment = signer.pm_round1_commit(session, &h_point)?;
            coordinator.add_commitment(commitment)?;
        }

        let signing_package =
            coordinator.signing_package_for(roster, &h_point)?;
        for xid in roster {
            let signer = participants.get_mut(xid).ok_or_else(|| {
                clubs::Error::msg(format!("unknown participant: {}", xid))
            })?;
            let gamma_share =
                signer.pm_round2_emit_gamma(&self.group, &signing_package)?;
            coordinator.record_gamma_share(gamma_share)?;
        }

        let challenge = coordinator.challenge()?;
        for xid in roster {
            let signer = participants.get_mut(xid).ok_or_else(|| {
                clubs::Error::msg(format!("unknown participant: {}", xid))
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
            self.last_key.clone(),
            next_key.clone(),
            self.chain_id.clone(),
            self.sequence,
            date.clone(),
            Option::<dcbor::CBOR>::None,
        )?;

        let expanded_key = expand_mark_key(&next_key);
        self.ratchet_state = ratchet_state(&self.ratchet_state, &expanded_key);
        self.last_key = next_key;
        self.sequence += 1;
        self.last_date = date;

        Ok(Advance { mark, gamma_bytes, proof })
    }
}

fn genesis_state() -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"PM-Genesis");
    let digest = hasher.finalize();
    let mut state = [0u8; 32];
    state.copy_from_slice(&digest);
    state
}

fn derive_chain_id(
    resolution: ProvenanceMarkResolution,
    group_point: &ProjectivePoint,
    label: &[u8],
) -> clubs::Result<Vec<u8>> {
    let x_bytes = point_bytes(group_point)?;
    let mut hasher = Sha256::new();
    hasher.update(b"PM-CHAIN-ID");
    hasher.update(x_bytes);
    hasher.update(label);
    let digest = hasher.finalize();
    Ok(digest[..resolution.link_length()].to_vec())
}

fn iso_date(date: &str) -> Date {
    Date::from_string(date).expect("valid ISO-8601 date")
}

fn collect_marks(advances: &[Advance]) -> Vec<ProvenanceMark> {
    advances.iter().map(|a| a.mark.clone()).collect()
}

#[test]
fn frost_provenance_story_alice_bob_charlie() -> clubs::Result<()> {
    let alice_doc =
        XIDDocument::new_with_private_key_base(PrivateKeyBase::new());
    let bob_doc = XIDDocument::new_with_private_key_base(PrivateKeyBase::new());
    let charlie_doc =
        XIDDocument::new_with_private_key_base(PrivateKeyBase::new());

    let members = vec![alice_doc.xid(), bob_doc.xid(), charlie_doc.xid()];
    let (group, mut participants): (FrostGroup, BTreeMap<_, _>) =
        FrostGroup::new_with_trusted_dealer(2, members.clone())?;

    let genesis = iso_date("2025-01-01");
    let mut publishing_state = PublishingState::new(
        &group,
        ProvenanceMarkResolution::Quartile,
        b"Gordian Club Minutes",
        genesis.clone(),
    )?;
    let mut verifier_chain = FrostProvenanceChain::new(
        &group,
        ProvenanceMarkResolution::Quartile,
        b"Gordian Club Minutes",
        genesis,
    )?;
    let mut coordinator = FrostPmCoordinator::new(group.clone());

    let publishing_plan: Vec<(&str, Vec<_>, Date)> = vec![
        (
            "Founding minutes signed by Alice and Bob",
            vec![alice_doc.xid(), bob_doc.xid()],
            iso_date("2025-01-02"),
        ),
        (
            "Charlie records the second meeting alongside Alice",
            vec![alice_doc.xid(), charlie_doc.xid()],
            iso_date("2025-01-05"),
        ),
        (
            "Alice travels; Bob and Charlie publish an interim update",
            vec![bob_doc.xid(), charlie_doc.xid()],
            iso_date("2025-01-07"),
        ),
    ];

    let mut advances: Vec<Advance> = Vec::new();
    for (blurb, roster, date) in publishing_plan {
        let Advance { mark, gamma_bytes, proof } = publishing_state
            .run_ceremony(&mut coordinator, &mut participants, &roster, date)?;

        verifier_chain.verify_advance(&mark, &gamma_bytes, &proof)?;
        advances.push(Advance { mark, gamma_bytes, proof });

        eprintln!("{}", blurb);
    }

    let marks = collect_marks(&advances);
    assert!(ProvenanceMark::is_sequence_valid(&marks));
    for window in marks.windows(2) {
        let current = &window[0];
        let next = &window[1];
        assert!(current.precedes(next));
    }

    let chain_id = verifier_chain.chain_id().to_vec();
    for advance in &advances {
        assert_eq!(advance.mark.chain_id(), chain_id);
    }

    Ok(())
}
