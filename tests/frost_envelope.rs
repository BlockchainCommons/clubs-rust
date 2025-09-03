use bc_components::XIDProvider;
use bc_envelope::{PrivateKeyBase, prelude::*};
use bc_xid::XIDDocument;
use clubs::frost::{FrostCoordinator, FrostGroup};

#[test]
fn frost_two_of_three_signs_envelope_and_verify() {
    // --- Create three XIDDocuments ---
    let alice_doc =
        XIDDocument::new_with_private_key_base(PrivateKeyBase::new());
    let bob_doc = XIDDocument::new_with_private_key_base(PrivateKeyBase::new());
    let charlie_doc =
        XIDDocument::new_with_private_key_base(PrivateKeyBase::new());

    // --- Prepare an Envelope, wrapped it so the signature covers the whole
    // structure ---
    let message = Envelope::new("FROST demo")
        .add_assertion("note", "This is an assertion on the subject.")
        .wrap();
    // --- Build FrostGroup of all participants using Trusted Dealer ---
    let members = vec![alice_doc.xid(), bob_doc.xid(), charlie_doc.xid()];
    let (group, mut participants) =
        FrostGroup::new_with_trusted_dealer(2, members).unwrap();

    // Materialize participant contexts from the map
    let mut alice_participant = participants.remove(&alice_doc.xid()).unwrap();
    let mut bob_participant = participants.remove(&bob_doc.xid()).unwrap();
    let mut charlie_participant =
        participants.remove(&charlie_doc.xid()).unwrap();

    // Coordinator orchestrates the ceremony as a neutral message hub
    let mut coordinator = FrostCoordinator::new(group.clone());
    coordinator.set_message(message);
    let session_id = coordinator.session_id();

    // Round-1: each participant in the roster generates a commitment and sends it to coordinator
    let alice_commitment = alice_participant.round1_commit(session_id).unwrap();
    coordinator
        .add_commitment(alice_commitment.clone())
        .unwrap();

        let bob_commitment = bob_participant.round1_commit(session_id).unwrap();
    coordinator.add_commitment(bob_commitment.clone()).unwrap();

    let charlie_commitment = charlie_participant.round1_commit(session_id).unwrap();
    coordinator.add_commitment(charlie_commitment).unwrap();
    // Idempotent re-send should be accepted silently
    coordinator.add_commitment(alice_commitment).unwrap();

    // Coordinator records explicit consent after participants review the message
    coordinator.record_consent(alice_doc.xid()).unwrap();
    coordinator.record_consent(bob_doc.xid()).unwrap();
    // Coordinator compiles a signing package and distributes it to selected participants
    // Select a threshold roster for this ceremony (2-of-3): Alice, Bob (both consented)
    let signing_package = coordinator
        .signing_package_for(&[alice_doc.xid(), bob_doc.xid()])
        .unwrap();

    // Round-2: each selected participant produces their signature share locally and sends it back
    let alice_share = alice_participant
        .round2_sign(&group, &signing_package)
        .unwrap();
    let bob_share = bob_participant
        .round2_sign(&group, &signing_package)
        .unwrap();
    coordinator.add_share(alice_share.clone()).unwrap();
    coordinator.add_share(bob_share.clone()).unwrap();
    // Idempotent re-send should be accepted silently
    coordinator.add_share(alice_share).unwrap();

    // Coordinator aggregates shares and attaches the final signature to the message
    let signed_envelope = coordinator.finalize().unwrap();
    let signing_key = group.verifying_signing_key();
    signed_envelope.verify_signature_from(&signing_key).unwrap();
}
