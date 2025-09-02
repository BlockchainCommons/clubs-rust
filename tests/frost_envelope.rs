use std::collections::BTreeMap;

use bc_components::{DigestProvider, XIDProvider};
use bc_envelope::prelude::*;
use clubs::frost::{
    aggregate_and_attach_signature as agg_attach, FrostDealer, FrostSigner,
};
use bc_xid::XIDDocument;

#[test]
fn frost_two_of_three_signs_envelope_and_verify() {
    // --- Create three XIDDocuments (like basic_scenario) ---
    let alice_doc = XIDDocument::new_with_private_key_base(bc_components::PrivateKeyBase::new());
    let bob_doc = XIDDocument::new_with_private_key_base(bc_components::PrivateKeyBase::new());
    let charlie_doc = XIDDocument::new_with_private_key_base(bc_components::PrivateKeyBase::new());

    // --- Prepare an Envelope, then WRAP it so the signature covers the whole structure ---
    let base = Envelope::new("FROST demo")
        .add_assertion("note", "This is an assertion on the subject.");
    let wrapped = base.wrap();
    // --- Build FROSTGroup using Gordian analogs and Trusted Dealer ---
    let signers = vec![
        FrostSigner { xid: alice_doc.xid(), identifier: 1 },
        FrostSigner { xid: bob_doc.xid(), identifier: 2 },
        FrostSigner { xid: charlie_doc.xid(), identifier: 3 },
    ];
    let mut dealer = FrostDealer::new_trusted_dealer(2, signers).unwrap();
    let group = dealer.group().clone();

    // Use Gordian API for Round-1 and Round-2:
    let signing_package_g = dealer.round1_prepare(&wrapped, &[1, 2]).unwrap();
    let shares_g = dealer.round2_sign(&signing_package_g, &[1, 2]).unwrap();
    let (signed_wrapped, signing_key) = agg_attach(&wrapped, &group, &signing_package_g, &shares_g).unwrap();
    assert!(signed_wrapped.has_signature_from(&signing_key).unwrap());
    signed_wrapped.verify_signature_from(&signing_key).unwrap();
}

// (Helper moved into clubs::frost module).
