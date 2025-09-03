use bc_components::XIDProvider;
use bc_envelope::prelude::*;
use bc_xid::XIDDocument;
use clubs::frost::{
    FrostCoordinator, FrostGroup,
};

#[test]
fn frost_two_of_three_signs_envelope_and_verify() {
    // --- Create three XIDDocuments (like basic_scenario) ---
    let alice_doc = XIDDocument::new_with_private_key_base(
        bc_components::PrivateKeyBase::new(),
    );
    let bob_doc = XIDDocument::new_with_private_key_base(
        bc_components::PrivateKeyBase::new(),
    );
    let charlie_doc = XIDDocument::new_with_private_key_base(
        bc_components::PrivateKeyBase::new(),
    );

    // --- Prepare an Envelope, wrapped it so the signature covers the whole
    // structure ---
    let message = Envelope::new("FROST demo")
        .add_assertion("note", "This is an assertion on the subject.")
        .wrap();
    // --- Build FrostGroup using Gordian analogs and Trusted Dealer ---
    let members = vec![alice_doc.xid(), bob_doc.xid(), charlie_doc.xid()];
    let (group, mut participants) = FrostGroup::new_with_trusted_dealer(2, members).unwrap();

    // Materialize participant contexts from the map
    let mut alice_participant = participants.remove(&alice_doc.xid()).unwrap();
    let mut bob_participant = participants.remove(&bob_doc.xid()).unwrap();
    let mut _charlie_participant = participants.remove(&charlie_doc.xid()).unwrap();

    // Coordinator orchestrates the ceremony as a neutral message hub
    let mut coordinator = FrostCoordinator::new(group.clone());
    coordinator.set_message(message);

    // Round-1: each participant in the roster generates a commitment and sends it to coordinator
    let alice_commitment = alice_participant.round1_commit().unwrap();
    let bob_commitment = bob_participant.round1_commit().unwrap();
    let charlie_commitment = _charlie_participant.round1_commit().unwrap();
    coordinator.add_commitment(alice_commitment).unwrap();
    coordinator.add_commitment(bob_commitment).unwrap();
    // coordinator.add_commitment(charlie_commitment).unwrap();

    // Coordinator compiles a signing package and distributes it to selected participants
    let signing_package = coordinator.signing_package().unwrap();

    // Round-2: each selected participant produces their signature share locally and sends it back
    let alice_share = alice_participant.round2_sign(&group, &signing_package).unwrap();
    let bob_share = bob_participant.round2_sign(&group, &signing_package).unwrap();
    coordinator.add_share(alice_share).unwrap();
    coordinator.add_share(bob_share).unwrap();

    // Coordinator aggregates shares and attaches the final signature to the message
    let signed_envelope = coordinator.finalize().unwrap();
    let signing_key = group.verifying_signing_key();
    signed_envelope.verify_signature_from(&signing_key).unwrap();
}
