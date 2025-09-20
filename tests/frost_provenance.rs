use std::collections::BTreeMap;

use bc_components::{PrivateKeyBase, XIDProvider};
use bc_xid::XIDDocument;
use clubs::frost::{
    FrostGroup,
    pm::{FrostPmCoordinator, FrostProvenanceAdvance, FrostProvenanceChain},
};
use dcbor::Date;
use provenance_mark::ProvenanceMark;
use provenance_mark::ProvenanceMarkResolution;

fn iso_date(date: &str) -> Date {
    Date::from_string(date).expect("valid ISO-8601 date")
}

fn collect_marks(advances: &[FrostProvenanceAdvance]) -> Vec<ProvenanceMark> {
    advances.iter().map(|a| a.mark.clone()).collect()
}

#[test]
fn frost_provenance_story_alice_bob_charlie() -> clubs::Result<()> {
    // Alice launches the club with Bob and Charlie as co-organizers.
    let alice_doc =
        XIDDocument::new_with_private_key_base(PrivateKeyBase::new());
    let bob_doc = XIDDocument::new_with_private_key_base(PrivateKeyBase::new());
    let charlie_doc =
        XIDDocument::new_with_private_key_base(PrivateKeyBase::new());

    let members = vec![alice_doc.xid(), bob_doc.xid(), charlie_doc.xid()];
    let (group, mut participants): (FrostGroup, BTreeMap<_, _>) =
        FrostGroup::new_with_trusted_dealer(2, members.clone())?;

    // The club agrees to ratchet the provenance mark chain at quartile resolution.
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

    // Story beats: a different roster carries the chain forward each time.
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

    let mut advances: Vec<FrostProvenanceAdvance> = Vec::new();
    for (blurb, roster, date) in publishing_plan {
        let advance = publishing_chain.advance(
            &mut coordinator,
            &mut participants,
            &roster,
            date,
        )?;

        // Everyone who only observes the chain can verify the step without
        // touching any secret material.
        verifier_chain.verify_advance(&advance)?;
        advances.push(advance);

        // Tuck the narrative into the test output for future debugging.
        eprintln!("{}", blurb);
    }

    // Validate the resulting marks with the provenance-mark crate helpers.
    let marks = collect_marks(&advances);
    assert!(ProvenanceMark::is_sequence_valid(&marks));
    for window in marks.windows(2) {
        let current = &window[0];
        let next = &window[1];
        assert!(current.precedes(next));
    }

    // The chain id remains stable regardless of which quorum advanced it.
    let chain_id = publishing_chain.chain_id().to_vec();
    for advance in &advances {
        assert_eq!(advance.mark.chain_id(), chain_id);
    }

    Ok(())
}
