use bc_components::XIDProvider;
use bc_envelope::prelude::*;
use bc_xid::XIDDocument;
use clubs::frost::{
    FrostGroup, FrostSignatureShares,
    aggregate_and_attach_signature, build_signing_package,
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

    // Round-1: each participant in the roster generates a commitment
    let alice_commitment = alice_participant.round1_commit().unwrap();
    let bob_commitment = bob_participant.round1_commit().unwrap();

    // Build signing package from the selected commitments (2-of-3)
    let signing_package = build_signing_package(&message, vec![alice_commitment, bob_commitment]);

    // Round-2: each selected participant produces their signature share locally
    let alice_share = alice_participant.round2_sign(&group, &signing_package).unwrap();
    let bob_share = bob_participant.round2_sign(&group, &signing_package).unwrap();
    let signature_shares = FrostSignatureShares::new(vec![alice_share, bob_share]);
    let signed_wrapped =
        aggregate_and_attach_signature(&message, &group, &signing_package, &signature_shares).unwrap();
    let signing_key = group.verifying_signing_key();
    assert!(signed_wrapped.has_signature_from(&signing_key).unwrap());
    signed_wrapped.verify_signature_from(&signing_key).unwrap();
}
