use bc_components::XIDProvider;
use bc_envelope::prelude::*;
use bc_xid::{XIDDocument, XIDGenesisMarkOptions, XIDInceptionKeyOptions};
use clubs::frost::{
    FrostGroup, FrostSigningCoordinator, FrostSigningParticipant,
};
use indoc::indoc;

#[test]
fn frost_two_of_three_signs_envelope_and_verify() {
    // --- Create three XIDDocuments ---
    let alice_doc = XIDDocument::new(
        XIDInceptionKeyOptions::Default,
        XIDGenesisMarkOptions::None,
    );
    let bob_doc = XIDDocument::new(
        XIDInceptionKeyOptions::Default,
        XIDGenesisMarkOptions::None,
    );
    let charlie_doc = XIDDocument::new(
        XIDInceptionKeyOptions::Default,
        XIDGenesisMarkOptions::None,
    );

    // --- Prepare an Envelope, wrapped so the signature covers the whole
    // structure ---
    let message = Envelope::new("FROST demo")
        .add_assertion(
            known_values::NOTE,
            "This is an assertion on the subject.",
        )
        .wrap();
    // --- Build FrostGroup of all participants using Trusted Dealer ---
    let members = vec![alice_doc.xid(), bob_doc.xid(), charlie_doc.xid()];
    let (group, participant_cores) =
        FrostGroup::new_with_trusted_dealer(2, members).unwrap();
    let mut participants: std::collections::BTreeMap<_, _> = participant_cores
        .into_iter()
        .map(|(xid, core)| (xid, FrostSigningParticipant::from_core(core)))
        .collect();

    // Materialize participant contexts from the map
    let mut alice_participant = participants.remove(&alice_doc.xid()).unwrap();
    let mut bob_participant = participants.remove(&bob_doc.xid()).unwrap();
    let mut charlie_participant =
        participants.remove(&charlie_doc.xid()).unwrap();

    // Coordinator orchestrates the ceremony as a neutral message hub
    let mut coordinator = FrostSigningCoordinator::new(group.clone());
    coordinator.set_message(message);
    let session_id = coordinator.session_id();

    // Round-1: each participant in the roster generates a commitment and sends
    // it to coordinator
    let alice_commitment = alice_participant.round1_commit(session_id).unwrap();
    coordinator
        .add_commitment(alice_commitment.clone())
        .unwrap();
    // Idempotent re-send should be accepted silently
    coordinator.add_commitment(alice_commitment).unwrap();

    let bob_commitment = bob_participant.round1_commit(session_id).unwrap();
    coordinator.add_commitment(bob_commitment.clone()).unwrap();

    let charlie_commitment =
        charlie_participant.round1_commit(session_id).unwrap();
    coordinator.add_commitment(charlie_commitment).unwrap();

    // Coordinator records explicit consent after participants review the
    // message
    coordinator.record_consent(alice_doc.xid()).unwrap();
    coordinator.record_consent(bob_doc.xid()).unwrap();
    // Coordinator compiles a signing package from the consenting roster
    let signing_package = coordinator.signing_package_from_consent().unwrap();

    // Round-2: each selected participant produces their signature share locally
    // and sends it back
    let alice_share = alice_participant
        .round2_sign(&group, &signing_package)
        .unwrap();
    coordinator.add_share(alice_share.clone()).unwrap();
    // Idempotent re-send should be accepted silently
    coordinator.add_share(alice_share).unwrap();

    let bob_share = bob_participant
        .round2_sign(&group, &signing_package)
        .unwrap();
    coordinator.add_share(bob_share.clone()).unwrap();

    // Coordinator aggregates shares and attaches the final signature to the
    // message
    let signed_envelope = coordinator.finalize().unwrap();

    #[rustfmt::skip]
    let expected = (indoc! {r#"
        {
            "FROST demo" [
                'note': "This is an assertion on the subject."
            ]
        } [
            'signed': Signature
        ]
    "#}).trim();
    assert_eq!(signed_envelope.format(), expected);

    let signing_key = group.verifying_signing_key();
    signed_envelope.verify_signature_from(&signing_key).unwrap();
}
