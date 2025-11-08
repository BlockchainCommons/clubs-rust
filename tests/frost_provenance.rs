use std::collections::BTreeMap;

use bc_components::{XID, XIDProvider};
use bc_xid::{GenesisMarkOptions, InceptionKeyOptions, XIDDocument};
use clubs::frost::{
    FrostGroup,
    pm::{
        DleqProof, FrostPmCoordinator, FrostPmParticipant,
        FrostProvenanceChain, key_from_gamma, point_bytes,
    },
};
use dcbor::Date;
use provenance_mark::{ProvenanceMark, ProvenanceMarkResolution};

#[derive(Clone)]
struct Advance {
    mark: ProvenanceMark,
    gamma_bytes: [u8; 33],
    proof: DleqProof,
}

fn iso_date(date: &str) -> Date {
    Date::from_string(date).expect("valid ISO-8601 date")
}

fn collect_marks(advances: &[Advance]) -> Vec<ProvenanceMark> {
    advances.iter().map(|a| a.mark.clone()).collect()
}

fn run_ceremony(
    chain: &mut FrostProvenanceChain,
    coordinator: &mut FrostPmCoordinator,
    participants: &mut BTreeMap<XID, FrostPmParticipant>,
    roster: &[XID],
    date: Date,
) -> clubs::Result<Advance> {
    if date < *chain.last_date() {
        return Err(clubs::Error::msg(
            "provenance date must be non-decreasing",
        ));
    }

    let (_, _, h_point) = chain.next_message()?;

    coordinator.start_session();
    let session = coordinator.session_id();

    for xid in roster {
        let signer = participants.get_mut(xid).ok_or_else(|| {
            clubs::Error::msg(format!("unknown participant: {}", xid))
        })?;
        let commitment = signer.round1_commit(session, &h_point)?;
        coordinator.add_commitment(commitment)?;
    }

    let signing_package = coordinator.signing_package_for(roster, &h_point)?;
    for xid in roster {
        let signer = participants.get_mut(xid).ok_or_else(|| {
            clubs::Error::msg(format!("unknown participant: {}", xid))
        })?;
        let gamma_share =
            signer.round2_emit_gamma(chain.group(), &signing_package)?;
        coordinator.record_gamma_share(gamma_share)?;
    }

    let challenge = coordinator.challenge()?;
    for xid in roster {
        let signer = participants.get_mut(xid).ok_or_else(|| {
            clubs::Error::msg(format!("unknown participant: {}", xid))
        })?;
        let response = signer.finalize_response(&challenge)?;
        coordinator.record_response(response)?;
    }

    let (gamma_point, proof) = coordinator.finalize()?;
    let gamma_bytes = point_bytes(&gamma_point)?;
    let full_key = key_from_gamma(&gamma_point)?;
    let link_len = chain.resolution().link_length();
    let mut next_key = vec![0u8; link_len];
    next_key.copy_from_slice(&full_key[..link_len]);

    let mark = ProvenanceMark::new(
        chain.resolution(),
        chain.last_key().to_vec(),
        next_key,
        chain.chain_id().to_vec(),
        chain.sequence(),
        date,
        Option::<dcbor::CBOR>::None,
    )?;

    chain.verify_advance(&mark, &gamma_bytes, &proof)?;

    Ok(Advance { mark, gamma_bytes, proof })
}

#[test]
fn frost_provenance_story() -> clubs::Result<()> {
    // Provision three club members with their own XIDs so they can hold FROST
    // signing shares and appear as independent actors in the ceremony.
    let alice_doc = XIDDocument::new(
        InceptionKeyOptions::Default,
        GenesisMarkOptions::None,
    );
    let bob_doc = XIDDocument::new(
        InceptionKeyOptions::Default,
        GenesisMarkOptions::None,
    );
    let charlie_doc = XIDDocument::new(
        InceptionKeyOptions::Default,
        GenesisMarkOptions::None,
    );

    // Establish a 2-of-3 threshold group, mirroring the quorum size we expect
    // for provenance publishing.
    let members = vec![alice_doc.xid(), bob_doc.xid(), charlie_doc.xid()];
    let (group, participant_cores): (
        FrostGroup,
        BTreeMap<XID, clubs::frost::FrostParticipantCore>,
    ) = FrostGroup::new_with_trusted_dealer(2, members.clone())?;

    // Turn each participant core into the provenance-mark aware participant
    // type so they can perform the VRF-specific rounds.
    let mut participants: BTreeMap<XID, FrostPmParticipant> = participant_cores
        .into_iter()
        .map(|(xid, core)| (xid, FrostPmParticipant::from_core(core)))
        .collect();

    // Both publisher and verifier start from the same genesis state to ensure
    // they agree on the public chain inputs.
    let genesis = iso_date("2025-01-01");
    // The publishing chain mirrors the coordinator's evolving view while it
    // aggregates shares and produces new marks.
    let mut publishing_chain = FrostProvenanceChain::new(
        &group,
        ProvenanceMarkResolution::Quartile,
        b"Gordian Club Minutes",
        genesis.clone(),
    )?;
    // The verifier chain simulates an external observer that only consumes the
    // published artifacts; keeping it separate demonstrates that verification
    // does not depend on the publisher's mutable state.
    let mut verifier_chain = FrostProvenanceChain::new(
        &group,
        ProvenanceMarkResolution::Quartile,
        b"Gordian Club Minutes",
        genesis,
    )?;
    // Single coordinator drives each ceremony, collecting commitments and
    // assembling the aggregate responses.
    let mut coordinator = FrostPmCoordinator::new(group.clone());

    // Narrated plan of meetings: each tuple carries the roster that will make
    // up the signing quorum and the date stamped into the mark.
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
        // Advance the publishing chain by running a full two-round FROST VRF
        // ceremony for the requested roster and date.
        let advance = run_ceremony(
            &mut publishing_chain,
            &mut coordinator,
            &mut participants,
            &roster,
            date,
        )?;

        // An independent verifier validates the mark using only public inputs,
        // emulating how observers would audit the chain.
        verifier_chain.verify_advance(
            &advance.mark,
            &advance.gamma_bytes,
            &advance.proof,
        )?;
        advances.push(advance);

        eprintln!("{}", blurb);
    }

    // The marks must form a well-ordered provenance chain that reveals the
    // prior secret and introduces the next one in sequence.
    let marks = collect_marks(&advances);
    assert!(ProvenanceMark::is_sequence_valid(&marks));
    for window in marks.windows(2) {
        let current = &window[0];
        let next = &window[1];
        assert!(current.precedes(next));
    }

    // All marks should stay bound to the publishing chain's identifier.
    let chain_id = verifier_chain.chain_id().to_vec();
    for advance in &advances {
        assert_eq!(advance.mark.chain_id(), chain_id);
    }

    Ok(())
}
