use std::collections::BTreeMap;

use bc_components::{PrivateKeyBase, XID, XIDProvider};
use bc_xid::XIDDocument;
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
        let commitment = signer.pm_round1_commit(session, &h_point)?;
        coordinator.add_commitment(commitment)?;
    }

    let signing_package = coordinator.signing_package_for(roster, &h_point)?;
    for xid in roster {
        let signer = participants.get_mut(xid).ok_or_else(|| {
            clubs::Error::msg(format!("unknown participant: {}", xid))
        })?;
        let gamma_share =
            signer.pm_round2_emit_gamma(chain.group(), &signing_package)?;
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
fn frost_provenance_story_alice_bob_charlie() -> clubs::Result<()> {
    let alice_doc =
        XIDDocument::new_with_private_key_base(PrivateKeyBase::new());
    let bob_doc = XIDDocument::new_with_private_key_base(PrivateKeyBase::new());
    let charlie_doc =
        XIDDocument::new_with_private_key_base(PrivateKeyBase::new());

    let members = vec![alice_doc.xid(), bob_doc.xid(), charlie_doc.xid()];
    let (group, participant_cores): (
        FrostGroup,
        BTreeMap<XID, clubs::frost::FrostParticipantCore>,
    ) = FrostGroup::new_with_trusted_dealer(2, members.clone())?;

    let mut participants: BTreeMap<XID, FrostPmParticipant> = participant_cores
        .into_iter()
        .map(|(xid, core)| (xid, FrostPmParticipant::from_core(core)))
        .collect();

    let genesis = iso_date("2025-01-01");
    let mut publishing_chain = FrostProvenanceChain::new(
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
        let advance = run_ceremony(
            &mut publishing_chain,
            &mut coordinator,
            &mut participants,
            &roster,
            date,
        )?;

        verifier_chain.verify_advance(
            &advance.mark,
            &advance.gamma_bytes,
            &advance.proof,
        )?;
        advances.push(advance);

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
