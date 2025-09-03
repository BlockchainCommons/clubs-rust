use bc_components::XIDProvider;
use bc_envelope::prelude::*;
use bc_xid::XIDDocument;
use clubs::frost::{
    FrostGroup, FrostSignatureShares,
    aggregate_and_attach_signature as agg_attach, build_signing_package,
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

    // --- Prepare an Envelope, then WRAP it so the signature covers the whole
    // structure ---
    let base = Envelope::new("FROST demo")
        .add_assertion("note", "This is an assertion on the subject.");
    let wrapped = base.wrap();
    // --- Build FROSTGroup using Gordian analogs and Trusted Dealer ---
    let members = vec![alice_doc.xid(), bob_doc.xid(), charlie_doc.xid()];
    let (group, mut participants) =
        FrostGroup::new_with_trusted_dealer(2, members).unwrap();

    // Round-1: each selected participant generates commitments locally
    let mut commitments = Vec::new();
    for xid in [alice_doc.xid(), bob_doc.xid()] {
        let c = participants.get_mut(&xid).unwrap().round1_commit().unwrap();
        commitments.push(c);
    }
    // Build signing package from envelope digest and commitments
    let signing_package_g = build_signing_package(&wrapped, commitments);

    // Round-2: each selected participant produces their signature share locally
    let mut shares_vec = Vec::new();
    for xid in [alice_doc.xid(), bob_doc.xid()] {
        let s = participants
            .get(&xid)
            .unwrap()
            .round2_sign(&group, &signing_package_g)
            .unwrap();
        shares_vec.push(s);
    }
    let shares_g = FrostSignatureShares::new(shares_vec);
    let (signed_wrapped, signing_key) =
        agg_attach(&wrapped, &group, &signing_package_g, &shares_g).unwrap();
    assert!(signed_wrapped.has_signature_from(&signing_key).unwrap());
    signed_wrapped.verify_signature_from(&signing_key).unwrap();
}

// (Helper moved into clubs::frost module).
