use bc_components::{
    PrivateKeyBase, PublicKeysProvider, SSKRGroupSpec, SSKRSpec, SymmetricKey,
    XIDProvider,
};
use bc_envelope::prelude::*;
use bc_xid::{XIDDocument, XIDGenesisMarkOptions, XIDInceptionKeyOptions};
use clubs::{edition::Edition, public_key_permit::PublicKeyPermit};
use indoc::indoc;
use known_values::NAME;
use provenance_mark::{ProvenanceMarkGenerator, ProvenanceMarkResolution};

fn fixed_key(byte: u8) -> PrivateKeyBase {
    PrivateKeyBase::from_data([byte; 32])
}

#[test]
fn basic_scenario_alice_bob_charlie() {
    // Ensure formatting knows tags and known values.
    provenance_mark::register_tags();

    // Actors (deterministic keys and XIDs).
    let alice_k = fixed_key(0xA1);
    let bob_k = fixed_key(0xB2);
    let charlie_k = fixed_key(0xC3);

    let alice = XIDDocument::new(
        XIDInceptionKeyOptions::PrivateKeyBase(alice_k.clone()),
        XIDGenesisMarkOptions::None,
    );
    let bob = XIDDocument::new(
        XIDInceptionKeyOptions::PrivateKeyBase(bob_k.clone()),
        XIDGenesisMarkOptions::None,
    );
    let charlie = XIDDocument::new(
        XIDInceptionKeyOptions::PrivateKeyBase(charlie_k.clone()),
        XIDGenesisMarkOptions::None,
    );
    // New club (its own XIDDocument).
    let club_k = fixed_key(0xD4);
    let club = XIDDocument::new(
        XIDInceptionKeyOptions::PrivateKeyBase(club_k.clone()),
        XIDGenesisMarkOptions::None,
    );

    // First edition content.
    let content = Envelope::new("Welcome to the club!")
        .add_assertion(NAME, "Gordian Test Club")
        .wrap();

    // Wrap content before getting digest
    let content_digest = content.digest();

    // Provenance (deterministic).
    let mut pm_gen = ProvenanceMarkGenerator::new_with_passphrase(
        ProvenanceMarkResolution::Quartile,
        "ClubSeed",
    );
    let date = Date::from_string("2025-01-01").unwrap();
    let provenance = pm_gen.next(date, Some(content_digest));

    // Edition 1: sealed to all three, signed by the club.
    let edition =
        Edition::new(club.xid(), provenance, content.clone()).unwrap();
    let recipients: Vec<PublicKeyPermit> = vec![
        PublicKeyPermit::for_member(alice.xid(), &alice_k.public_keys()),
        PublicKeyPermit::for_member(bob.xid(), &bob_k.public_keys()),
        PublicKeyPermit::for_member(charlie.xid(), &charlie_k.public_keys()),
    ];
    // Combine permits: recipients and SSKR 2-of-3 group
    let group = SSKRGroupSpec::new(2, 3).unwrap();
    let spec = SSKRSpec::new(1, vec![group]).unwrap();
    let (sealed, shares_opt) = edition
        .seal_with_permits(&recipients, Some(spec), &club_k)
        .unwrap();
    let shares = shares_opt.expect("Expected SSKR shares when spec provided");
    assert_eq!(shares.len(), 1);
    assert_eq!(shares[0].len(), 3);

    // Phase One: print and collect expected text, then replace with assert
    // below. println!("{}", sealed.format());

    // Phase Two: test against expected output.
    // expected-text-output-rubric:
    #[rustfmt::skip]
    let expected = (indoc! {r#"
        {
            ENCRYPTED [
                'isA': "Edition"
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
                "club": XID(02dca4b9)
                'provenance': ProvenanceMark(e67182ae)
            ]
        } [
            'signed': Signature
        ]
    "#}).trim();
    assert_eq!(sealed.format(), expected);

    // expected-text-output-rubric:
    #[rustfmt::skip]
    let expected = (indoc! {r#"
        ENCRYPTED [
            'sskrShare': SSKRShare
        ]
    "#}).trim();
    assert_eq!(shares[0][0].format(), expected);

    // Round-trip: convert envelope back to Edition and examine its
    // serialization.
    let edition_rt =
        Edition::unseal(sealed.clone(), &club_k.public_keys()).unwrap();
    let roundtrip_env: Envelope = edition_rt.clone().into();
    // expected-text-output-rubric:
    #[rustfmt::skip]
    let expected_rt = (indoc! {r#"
        ENCRYPTED [
            'isA': "Edition"
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
            "club": XID(02dca4b9)
            'provenance': ProvenanceMark(e67182ae)
        ]
    "#}).trim();
    assert_eq!(roundtrip_env.format(), expected_rt);

    // Idempotent: decode the round-tripped envelope and compare Editions.
    let edition_rt2 = Edition::try_from(roundtrip_env).unwrap();
    // Entire Edition is idempotent and comparable
    assert_eq!(edition_rt, edition_rt2);

    // Member decrypts: Alice unseals and reads content
    let mut content_key: Option<SymmetricKey> = None;
    for permit in &edition_rt.permits {
        if let PublicKeyPermit::Decode { sealed, .. } = permit
            && let Ok(plaintext) = sealed.decrypt(&alice_k)
        {
            let key = SymmetricKey::from_tagged_cbor_data(plaintext).unwrap();
            content_key = Some(key);
            break;
        }
    }
    let content_key =
        content_key.expect("Alice should be able to unwrap content key");
    let encrypted_content = edition_rt.content.clone();
    let decrypted_wrapped =
        encrypted_content.decrypt_subject(&content_key).unwrap();
    let decrypted_content = decrypted_wrapped.try_unwrap().unwrap();
    assert!(decrypted_content.is_identical_to(&content));

    // SSKR quorum: combine 2-of-3 shares to recover content
    let share1 = &shares[0][0];
    let share2 = &shares[0][1];
    let recovered_wrapped = Envelope::sskr_join(&[share1, share2]).unwrap();
    let recovered = recovered_wrapped.try_unwrap().unwrap();
    assert!(recovered.is_identical_to(&content));
}
