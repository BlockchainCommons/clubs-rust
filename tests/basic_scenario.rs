use bc_envelope::prelude::*;
use bc_components::{PrivateKeyBase, PublicKeysProvider, XIDProvider};
use bc_xid::XIDDocument;
use clubs::edition::{Edition, PublicKeyPermitMeta};
use indoc::indoc;
use known_values::NAME;
use provenance_mark::{ProvenanceMarkGenerator, ProvenanceMarkResolution};

fn fixed_key(byte: u8) -> PrivateKeyBase { PrivateKeyBase::from_data([byte; 32]) }

#[test]
fn basic_scenario_alice_bob_charlie() {
    // Ensure formatting knows tags and known values.
    provenance_mark::register_tags();

    // Actors (deterministic keys and XIDs).
    let alice_k = fixed_key(0xA1);
    let bob_k = fixed_key(0xB2);
    let charlie_k = fixed_key(0xC3);

    let alice = XIDDocument::new_with_private_key_base(alice_k.clone());
    let bob = XIDDocument::new_with_private_key_base(bob_k.clone());
    let charlie = XIDDocument::new_with_private_key_base(charlie_k.clone());

    // New club (its own XIDDocument).
    let club_k = fixed_key(0xD4);
    let club = XIDDocument::new_with_private_key_base(club_k.clone());

    // First edition content.
    let content = Envelope::new("Welcome to the club!")
        .add_assertion(NAME, "Gordian Test Club");

    // Provenance (deterministic).
    let mut pm_gen =
        ProvenanceMarkGenerator::new_with_passphrase(ProvenanceMarkResolution::Quartile, "ClubSeed");
    let date = Date::from_string("2025-01-01").unwrap();
    let provenance = pm_gen.next(date, Some("Club genesis edition"));

    // Edition 1: sealed to all three, signed by the club.
    let edition = Edition::new(club.xid(), provenance, content);
    let recipients = vec![
        (alice_k.public_keys(), PublicKeyPermitMeta::new(Some(alice.xid()))),
        (bob_k.public_keys(), PublicKeyPermitMeta::new(Some(bob.xid()))),
        (charlie_k.public_keys(), PublicKeyPermitMeta::new(Some(charlie.xid()))),
    ];
    let sealed = edition.seal_and_sign(&recipients, &club_k, None).unwrap();

    // Phase One: print and collect expected text, then replace with assert below.
    // println!("{}", sealed.format());

    // Phase Two: test against expected output.
    #[rustfmt::skip]
    let expected = (indoc! {r#"
        XID(02dca4b9) [
            {
                'hasRecipient': SealedMessage
            } [
                'holder': XID(1944dcbc)
            ]
            {
                'hasRecipient': SealedMessage
            } [
                'holder': XID(448e2e0b)
            ]
            {
                'hasRecipient': SealedMessage
            } [
                'holder': XID(74107ca5)
            ]
            'content': ENCRYPTED
            'provenance': ProvenanceMark(ef7c82c8)
            'signed': Signature
        ]
    "#}).trim();
    assert_eq!(sealed.format(), expected);
}
