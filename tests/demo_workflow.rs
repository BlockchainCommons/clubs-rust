//! Complete workflow test replicating clubs-demo.py
//!
//! This test suite validates the entire clubs workflow using direct API calls
//! instead of CLI commands. It covers:
//! - Publisher and member key generation
//! - Content creation and wrapping
//! - Provenance mark chain management
//! - Edition composition with permits and SSKR
//! - Edition verification and signature checks
//! - Permit extraction and content decryption
//! - Provenance sequence validation
//! - Round-trip serialization (UR and CBOR)
//!
//! The main test (`test_complete_demo_workflow`) replicates the full demo
//! script, while additional tests validate edge cases and error conditions.

use bc_components::{
    DigestProvider, PrivateKeyBase, PublicKeysProvider, SSKRGroupSpec,
    SSKRSpec, SymmetricKey, XIDProvider,
};
use bc_envelope::prelude::*;
use bc_xid::{GenesisMarkOptions, InceptionKeyOptions, XIDDocument};
use clubs::{edition::Edition, public_key_permit::PublicKeyPermit};
use dcbor::Date;
use provenance_mark::{
    ProvenanceMark, ProvenanceMarkGenerator, ProvenanceMarkResolution,
};

fn fixed_key(byte: u8) -> PrivateKeyBase {
    PrivateKeyBase::from_data([byte; 32])
}

#[test]
fn test_complete_demo_workflow() {
    // Register tags for formatting
    provenance_mark::register_tags();

    // ═══════════════════════════════════════════════════════════════════════
    // STEP 1: Generate Publisher and Member Cryptographic Material
    // ═══════════════════════════════════════════════════════════════════════

    // Publisher keys
    let publisher_prvkeys = fixed_key(0xAA);
    let publisher_xid = XIDDocument::new(
        InceptionKeyOptions::PrivateKeyBase(publisher_prvkeys.clone()),
        GenesisMarkOptions::None,
    );

    // Member keys (Alice and Bob)
    let alice_prvkeys = fixed_key(0xA1);
    let alice_pubkeys = alice_prvkeys.public_keys();
    let alice_xid = XIDDocument::new(
        InceptionKeyOptions::PrivateKeyBase(alice_prvkeys.clone()),
        GenesisMarkOptions::None,
    );

    let bob_prvkeys = fixed_key(0xB0);
    let bob_pubkeys = bob_prvkeys.public_keys();
    let bob_xid = XIDDocument::new(
        InceptionKeyOptions::PrivateKeyBase(bob_prvkeys.clone()),
        GenesisMarkOptions::None,
    );
    // ═══════════════════════════════════════════════════════════════════════
    // STEP 2: Create Genesis Edition Content
    // ═══════════════════════════════════════════════════════════════════════

    // Build content envelope with subject and title assertion
    let content_subject = Envelope::new("Welcome to the Gordian Club!");
    let content_clear =
        content_subject.add_assertion("title", "Genesis Edition");
    let content_wrapped = content_clear.wrap();

    // Validate wrapped structure
    assert!(content_wrapped.is_wrapped());

    // Capture content digest
    let content_digest = content_wrapped.digest().into_owned();

    // ═══════════════════════════════════════════════════════════════════════
    // STEP 3: Initialize Provenance Mark Chain
    // ═══════════════════════════════════════════════════════════════════════

    let mut pm_gen = ProvenanceMarkGenerator::new_with_passphrase(
        ProvenanceMarkResolution::Quartile,
        "DemoSeed2025",
    );

    let date = Date::from_string("2025-10-01").unwrap();

    let genesis_mark = pm_gen.next(date.clone(), Some(content_digest));

    // Validate provenance mark includes info
    assert!(genesis_mark.info().is_some());

    // Test round-trip serialization
    let mark_ur = genesis_mark.ur_string();
    let mark_rt = ProvenanceMark::from_ur_string(&mark_ur).unwrap();
    assert_eq!(genesis_mark, mark_rt);

    // ═══════════════════════════════════════════════════════════════════════
    // STEP 4: Compose Genesis Edition with Permits and SSKR
    // ═══════════════════════════════════════════════════════════════════════

    let edition = Edition::new(
        publisher_xid.xid(),
        genesis_mark.clone(),
        content_wrapped.clone(),
    )
    .unwrap();

    // Create permits for both members
    let recipients: Vec<PublicKeyPermit> = vec![
        PublicKeyPermit::for_member(alice_xid.xid(), &alice_pubkeys),
        PublicKeyPermit::for_member(bob_xid.xid(), &bob_pubkeys),
    ];

    // Create 2-of-3 SSKR spec
    let group = SSKRGroupSpec::new(2, 3).unwrap();
    let spec = SSKRSpec::new(1, vec![group]).unwrap();

    // Seal with permits and SSKR
    let (sealed, shares_opt) = edition
        .seal_with_permits(&recipients, Some(spec.clone()), &publisher_prvkeys)
        .unwrap();

    let shares = shares_opt.expect("Should have SSKR shares");
    assert_eq!(shares.len(), 1, "Should have 1 group");
    assert_eq!(shares[0].len(), 3, "Should have 3 shares");

    // Verify envelope has signature
    assert!(
        sealed
            .has_signature_from(&publisher_prvkeys.public_keys())
            .unwrap()
    );

    // ═══════════════════════════════════════════════════════════════════════
    // STEP 5: Verify Genesis Edition
    // ═══════════════════════════════════════════════════════════════════════

    // Verify signature with publisher's public keys
    sealed.verify(&publisher_prvkeys.public_keys()).unwrap();

    // Unseal to Edition struct
    let edition_rt =
        Edition::unseal(sealed.clone(), &publisher_prvkeys.public_keys())
            .unwrap();

    // Validate unsealed edition matches original
    assert_eq!(edition_rt.club_xid, publisher_xid.xid());
    assert_eq!(edition_rt.provenance, genesis_mark);

    // ═══════════════════════════════════════════════════════════════════════
    // STEP 6: Extract and Test Permits
    // ═══════════════════════════════════════════════════════════════════════

    // Count permits
    let permit_count = edition_rt
        .permits
        .iter()
        .filter(|p| matches!(p, PublicKeyPermit::Decode { .. }))
        .count();
    assert_eq!(permit_count, 2, "Should have 2 permits");

    // ═══════════════════════════════════════════════════════════════════════
    // STEP 7: Decrypt Content with Alice's Permit
    // ═══════════════════════════════════════════════════════════════════════

    let mut content_key: Option<SymmetricKey> = None;

    for permit in &edition_rt.permits {
        if let PublicKeyPermit::Decode { sealed, member_xid } = permit {
            // Check if this is Alice's permit
            if member_xid == &Some(alice_xid.xid()) {
                if let Ok(plaintext) = sealed.decrypt(&alice_prvkeys) {
                    let key =
                        SymmetricKey::from_tagged_cbor_data(plaintext).unwrap();
                    content_key = Some(key);
                    break;
                }
            }
        }
    }

    let alice_content_key =
        content_key.expect("Alice should decrypt her permit");

    // Decrypt content with Alice's key
    let decrypted = edition_rt
        .content
        .decrypt_subject(&alice_content_key)
        .unwrap();

    // The content was wrapped before encryption, so decrypted is wrapped
    // Unwrap once to get back to content_wrapped, then unwrap again to get
    // content_clear
    let once_unwrapped = decrypted.try_unwrap().unwrap();
    let twice_unwrapped = once_unwrapped.try_unwrap().unwrap();
    assert!(twice_unwrapped.is_identical_to(&content_clear));

    // ═══════════════════════════════════════════════════════════════════════
    // STEP 8: Decrypt Content via SSKR Shares
    // ═══════════════════════════════════════════════════════════════════════

    // Use shares 0 and 1 to recover content (2-of-3 threshold)
    let share1 = &shares[0][0];
    let share2 = &shares[0][1];

    let recovered_wrapped = Envelope::sskr_join(&[share1, share2]).unwrap();
    let recovered = recovered_wrapped.try_unwrap().unwrap();

    // SSKR recovers the wrapped content, unwrap again to compare
    let recovered_unwrapped = recovered.try_unwrap().unwrap();
    assert!(recovered_unwrapped.is_identical_to(&content_clear));

    // Test that single share is insufficient
    let insufficient_result = Envelope::sskr_join(&[share1]);
    assert!(insufficient_result.is_err(), "Single share should fail");

    // ═══════════════════════════════════════════════════════════════════════
    // STEP 9: Create Second Edition with Updated Content
    // ═══════════════════════════════════════════════════════════════════════

    // New content for second edition
    let update_subject =
        Envelope::new("Club update: upcoming workshops and Q&A sessions");
    let update_clear = update_subject.add_assertion("title", "Second Edition");
    let update_wrapped = update_clear.wrap();

    // Capture updated content digest
    let update_digest = update_wrapped.digest().into_owned();

    // Advance provenance chain
    let second_mark = pm_gen.next(date, Some(update_digest));

    // Validate second mark
    assert!(second_mark.info().is_some());
    assert_eq!(second_mark.seq(), 1);

    // Validate provenance chain continuity
    assert_eq!(genesis_mark.chain_id(), second_mark.chain_id());
    assert_eq!(genesis_mark.seq() + 1, second_mark.seq());

    // ═══════════════════════════════════════════════════════════════════════
    // STEP 10: Compose Second Edition
    // ═══════════════════════════════════════════════════════════════════════

    let second_edition = Edition::new(
        publisher_xid.xid(),
        second_mark.clone(),
        update_wrapped.clone(),
    )
    .unwrap();

    // Use same recipients and SSKR spec
    let (second_sealed, second_shares_opt) = second_edition
        .seal_with_permits(&recipients, Some(spec.clone()), &publisher_prvkeys)
        .unwrap();

    let second_shares = second_shares_opt.expect("Should have SSKR shares");
    assert_eq!(second_shares.len(), 1);
    assert_eq!(second_shares[0].len(), 3);

    // ═══════════════════════════════════════════════════════════════════════
    // STEP 11: Verify Second Edition
    // ═══════════════════════════════════════════════════════════════════════

    second_sealed
        .verify(&publisher_prvkeys.public_keys())
        .unwrap();

    let second_edition_rt = Edition::unseal(
        second_sealed.clone(),
        &publisher_prvkeys.public_keys(),
    )
    .unwrap();

    assert_eq!(second_edition_rt.club_xid, publisher_xid.xid());
    assert_eq!(second_edition_rt.provenance, second_mark);

    // ═══════════════════════════════════════════════════════════════════════
    // STEP 12: Validate Edition Sequence
    // ═══════════════════════════════════════════════════════════════════════

    // Both editions should belong to the same club
    assert_eq!(edition_rt.club_xid, second_edition_rt.club_xid);

    // Provenance marks should form a chain
    assert_eq!(
        edition_rt.provenance.chain_id(),
        second_edition_rt.provenance.chain_id()
    );
    assert_eq!(
        edition_rt.provenance.seq() + 1,
        second_edition_rt.provenance.seq()
    );

    // ═══════════════════════════════════════════════════════════════════════
    // STEP 13: Test Round-Trip Serialization
    // ═══════════════════════════════════════════════════════════════════════

    // Test UR round-trip for sealed edition
    let sealed_ur = sealed.ur_string();
    let sealed_rt = Envelope::from_ur_string(&sealed_ur).unwrap();
    assert!(sealed_rt.is_identical_to(&sealed));

    // Test CBOR round-trip
    let sealed_cbor = sealed.to_cbor_data();
    let sealed_from_cbor = Envelope::try_from_cbor_data(sealed_cbor).unwrap();
    assert!(sealed_from_cbor.is_identical_to(&sealed));

    // Test round-trip for SSKR shares
    for share in &shares[0] {
        let share_ur = share.ur_string();
        let share_rt = Envelope::from_ur_string(&share_ur).unwrap();
        assert!(share_rt.is_identical_to(share));
    }
}

#[test]
fn test_invalid_edition_content() {
    provenance_mark::register_tags();

    let publisher_prvkeys = fixed_key(0xCC);
    let publisher_xid = XIDDocument::new(
        InceptionKeyOptions::PrivateKeyBase(publisher_prvkeys),
        GenesisMarkOptions::None,
    );

    let mut pm_gen = ProvenanceMarkGenerator::new_with_passphrase(
        ProvenanceMarkResolution::Low,
        "TestSeed",
    );
    let date = Date::from_string("2025-10-01").unwrap();
    let mark = pm_gen.next(date, Some("Test"));

    // Content with assertions should fail
    let invalid_content =
        Envelope::new("Content").add_assertion("key", "value");

    let result = Edition::new(publisher_xid.xid(), mark, invalid_content);
    assert!(result.is_err());
}

#[test]
fn test_edition_without_sskr() {
    provenance_mark::register_tags();

    let publisher_prvkeys = fixed_key(0xDD);
    let publisher_xid = XIDDocument::new(
        InceptionKeyOptions::PrivateKeyBase(publisher_prvkeys.clone()),
        GenesisMarkOptions::None,
    );

    let alice_prvkeys = fixed_key(0xA2);
    let alice_pubkeys = alice_prvkeys.public_keys();
    let alice_xid = XIDDocument::new(
        InceptionKeyOptions::PrivateKeyBase(alice_prvkeys.clone()),
        GenesisMarkOptions::None,
    );

    let content = Envelope::new("Test content").wrap();
    let content_digest = content.digest().into_owned();

    let mut pm_gen = ProvenanceMarkGenerator::new_with_passphrase(
        ProvenanceMarkResolution::Low,
        "TestSeed2",
    );
    let date = Date::from_string("2025-10-01").unwrap();
    let mark = pm_gen.next(date, Some(content_digest));

    let edition = Edition::new(publisher_xid.xid(), mark, content).unwrap();

    let recipients =
        vec![PublicKeyPermit::for_member(alice_xid.xid(), &alice_pubkeys)];

    // Seal without SSKR
    let (sealed, shares_opt) = edition
        .seal_with_permits(&recipients, None, &publisher_prvkeys)
        .unwrap();

    assert!(shares_opt.is_none(), "Should not have SSKR shares");
    assert!(
        sealed
            .has_signature_from(&publisher_prvkeys.public_keys())
            .unwrap()
    );

    // Unseal and verify
    let edition_rt =
        Edition::unseal(sealed, &publisher_prvkeys.public_keys()).unwrap();
    assert_eq!(edition_rt.permits.len(), 1);
}

#[test]
fn test_wrong_permit_key() {
    provenance_mark::register_tags();

    let publisher_prvkeys = fixed_key(0xEE);
    let publisher_xid = XIDDocument::new(
        InceptionKeyOptions::PrivateKeyBase(publisher_prvkeys.clone()),
        GenesisMarkOptions::None,
    );

    let alice_prvkeys = fixed_key(0xA3);
    let alice_pubkeys = alice_prvkeys.public_keys();
    let alice_xid = XIDDocument::new(
        InceptionKeyOptions::PrivateKeyBase(alice_prvkeys.clone()),
        GenesisMarkOptions::None,
    );

    // Bob tries to decrypt Alice's permit
    let bob_prvkeys = fixed_key(0xB3);

    let content = Envelope::new("Secret").wrap();
    let content_digest = content.digest().into_owned();

    let mut pm_gen = ProvenanceMarkGenerator::new_with_passphrase(
        ProvenanceMarkResolution::Low,
        "TestSeed3",
    );
    let date = Date::from_string("2025-10-01").unwrap();
    let mark = pm_gen.next(date, Some(content_digest));

    let edition = Edition::new(publisher_xid.xid(), mark, content).unwrap();

    let recipients =
        vec![PublicKeyPermit::for_member(alice_xid.xid(), &alice_pubkeys)];

    let (sealed, _) = edition
        .seal_with_permits(&recipients, None, &publisher_prvkeys)
        .unwrap();

    let edition_rt =
        Edition::unseal(sealed, &publisher_prvkeys.public_keys()).unwrap();

    // Bob should fail to decrypt Alice's permit
    let mut bob_succeeded = false;
    for permit in &edition_rt.permits {
        if let PublicKeyPermit::Decode { sealed, .. } = permit {
            if sealed.decrypt(&bob_prvkeys).is_ok() {
                bob_succeeded = true;
            }
        }
    }

    assert!(!bob_succeeded, "Bob should not decrypt Alice's permit");
}

#[test]
fn test_wrong_signature_verification() {
    provenance_mark::register_tags();

    let publisher_prvkeys = fixed_key(0xFF);
    let publisher_xid = XIDDocument::new(
        InceptionKeyOptions::PrivateKeyBase(publisher_prvkeys.clone()),
        GenesisMarkOptions::None,
    );

    // Different key for verification
    let wrong_prvkeys = fixed_key(0x00);

    let content = Envelope::new("Content").wrap();
    let content_digest = content.digest().into_owned();

    let mut pm_gen = ProvenanceMarkGenerator::new_with_passphrase(
        ProvenanceMarkResolution::Low,
        "TestSeed4",
    );
    let date = Date::from_string("2025-10-01").unwrap();
    let mark = pm_gen.next(date, Some(content_digest));

    let edition = Edition::new(publisher_xid.xid(), mark, content).unwrap();

    let (sealed, _) = edition
        .seal_with_permits(&[], None, &publisher_prvkeys)
        .unwrap();

    // Should fail with wrong key
    let result = sealed.verify(&wrong_prvkeys.public_keys());
    assert!(result.is_err(), "Verification should fail with wrong key");

    // Should fail to unseal
    let result = Edition::unseal(sealed, &wrong_prvkeys.public_keys());
    assert!(result.is_err(), "Unseal should fail with wrong key");
}

#[test]
fn test_multiple_sskr_groups() {
    provenance_mark::register_tags();

    let publisher_prvkeys = fixed_key(0x11);
    let publisher_xid = XIDDocument::new(
        InceptionKeyOptions::PrivateKeyBase(publisher_prvkeys.clone()),
        GenesisMarkOptions::None,
    );

    let content = Envelope::new("Multi-group content").wrap();
    let content_digest = content.digest().into_owned();

    let mut pm_gen = ProvenanceMarkGenerator::new_with_passphrase(
        ProvenanceMarkResolution::Low,
        "MultiGroup",
    );
    let date = Date::from_string("2025-10-01").unwrap();
    let mark = pm_gen.next(date, Some(content_digest));

    let edition =
        Edition::new(publisher_xid.xid(), mark, content.clone()).unwrap();

    // Create 2 groups: 2-of-3 and 3-of-5
    let group1 = SSKRGroupSpec::new(2, 3).unwrap();
    let group2 = SSKRGroupSpec::new(3, 5).unwrap();
    let spec = SSKRSpec::new(1, vec![group1, group2]).unwrap();

    let (_sealed, shares_opt) = edition
        .seal_with_permits(&[], Some(spec), &publisher_prvkeys)
        .unwrap();

    let shares = shares_opt.expect("Should have SSKR shares");
    assert_eq!(shares.len(), 2, "Should have 2 groups");
    assert_eq!(shares[0].len(), 3, "Group 0 should have 3 shares");
    assert_eq!(shares[1].len(), 5, "Group 1 should have 5 shares");

    // Can recover from group 0 with 2 shares
    let recovered1 =
        Envelope::sskr_join(&[&shares[0][0], &shares[0][1]]).unwrap();
    let recovered1_unwrapped = recovered1.try_unwrap().unwrap();
    assert!(recovered1_unwrapped.is_identical_to(&content));

    // Can recover from group 1 with 3 shares
    let recovered2 =
        Envelope::sskr_join(&[&shares[1][0], &shares[1][1], &shares[1][2]])
            .unwrap();
    let recovered2_unwrapped = recovered2.try_unwrap().unwrap();
    assert!(recovered2_unwrapped.is_identical_to(&content));

    // Cannot recover from group 1 with only 2 shares
    let result = Envelope::sskr_join(&[&shares[1][0], &shares[1][1]]);
    assert!(result.is_err(), "Should fail with insufficient shares");
}

#[test]
fn test_provenance_info_matches_content_digest() {
    provenance_mark::register_tags();

    let publisher_prvkeys = fixed_key(0x22);
    let publisher_xid = XIDDocument::new(
        InceptionKeyOptions::PrivateKeyBase(publisher_prvkeys.clone()),
        GenesisMarkOptions::None,
    );

    let content = Envelope::new("Test content").wrap();
    let content_digest = content.digest().into_owned();

    let mut pm_gen = ProvenanceMarkGenerator::new_with_passphrase(
        ProvenanceMarkResolution::Low,
        "TestSeed5",
    );
    let date = Date::from_string("2025-10-01").unwrap();

    // Create mark with correct content digest in info field
    let correct_mark = pm_gen.next(date.clone(), Some(content_digest.clone()));

    // Verify the mark contains the digest
    assert!(correct_mark.info().is_some());
    let info_cbor = correct_mark.info().unwrap();
    // Info is now stored as a tagged Digest
    let info_digest =
        bc_components::Digest::from_tagged_cbor(info_cbor).unwrap();
    assert_eq!(
        info_digest, content_digest,
        "Provenance mark info should match content digest"
    );

    // Creating an edition with matching digest should succeed
    let edition = Edition::new(
        publisher_xid.xid(),
        correct_mark.clone(),
        content.clone(),
    );
    assert!(
        edition.is_ok(),
        "Edition with matching digest should succeed"
    );
}

#[test]
fn test_provenance_info_mismatch_content_digest() {
    provenance_mark::register_tags();

    let publisher_prvkeys = fixed_key(0x23);
    let publisher_xid = XIDDocument::new(
        InceptionKeyOptions::PrivateKeyBase(publisher_prvkeys.clone()),
        GenesisMarkOptions::None,
    );

    let content = Envelope::new("Test content").wrap();

    // Create a different content to get a different digest
    let wrong_content = Envelope::new("Wrong content").wrap();
    let wrong_digest = wrong_content.digest().into_owned();

    let mut pm_gen = ProvenanceMarkGenerator::new_with_passphrase(
        ProvenanceMarkResolution::Low,
        "TestSeed6",
    );
    let date = Date::from_string("2025-10-01").unwrap();

    // Create mark with WRONG content digest in info field
    let wrong_mark = pm_gen.next(date, Some(wrong_digest.clone()));

    // Now that Edition::new validates the digest, this should FAIL
    let edition =
        Edition::new(publisher_xid.xid(), wrong_mark.clone(), content.clone());

    assert!(
        edition.is_err(),
        "Edition::new should reject provenance mark with mismatched digest"
    );

    // Verify we get the expected error message
    let err = edition.unwrap_err();
    assert!(
        err.to_string().contains("does not match content digest"),
        "Error should mention digest mismatch, got: {}",
        err
    );

    // We can at least verify the mismatch programmatically
    if let Some(info_cbor) = wrong_mark.info() {
        let info_digest =
            bc_components::Digest::from_tagged_cbor(info_cbor).unwrap();
        let content_digest = content.digest().into_owned();
        assert_ne!(
            info_digest, content_digest,
            "Digest in provenance info does not match actual content digest"
        );
    }
}

#[test]
fn test_provenance_without_info_field() {
    provenance_mark::register_tags();

    let publisher_prvkeys = fixed_key(0x24);
    let publisher_xid = XIDDocument::new(
        InceptionKeyOptions::PrivateKeyBase(publisher_prvkeys.clone()),
        GenesisMarkOptions::None,
    );

    let content = Envelope::new("Test content").wrap();

    let mut pm_gen = ProvenanceMarkGenerator::new_with_passphrase(
        ProvenanceMarkResolution::Low,
        "TestSeed7",
    );
    let date = Date::from_string("2025-10-01").unwrap();

    // Create mark without info field (pass None)
    let mark_no_info = pm_gen.next(date, None::<String>);

    // Verify no info field
    assert!(
        mark_no_info.info().is_none(),
        "Mark should not have info field"
    );

    // Creating edition without info field should succeed (for now)
    let edition =
        Edition::new(publisher_xid.xid(), mark_no_info, content.clone());

    // TODO: Should we require info field? This depends on policy.
    // For now, document that it's allowed
    assert!(
        edition.is_ok(),
        "Edition without provenance info field is currently allowed"
    );
}

#[test]
fn test_edition_sequence_with_digest_validation() {
    provenance_mark::register_tags();

    let publisher_prvkeys = fixed_key(0x25);
    let publisher_xid = XIDDocument::new(
        InceptionKeyOptions::PrivateKeyBase(publisher_prvkeys.clone()),
        GenesisMarkOptions::None,
    );

    let mut pm_gen = ProvenanceMarkGenerator::new_with_passphrase(
        ProvenanceMarkResolution::Low,
        "TestSeed8",
    );
    let date = Date::from_string("2025-10-01").unwrap();

    // First edition with correct digest
    let content1 = Envelope::new("First edition").wrap();
    let digest1 = content1.digest().into_owned();
    let mark1 = pm_gen.next(date.clone(), Some(digest1));
    let edition1 = Edition::new(publisher_xid.xid(), mark1, content1).unwrap();

    // Second edition with correct digest
    let content2 = Envelope::new("Second edition").wrap();
    let digest2 = content2.digest().into_owned();
    let mark2 = pm_gen.next(date.clone(), Some(digest2));
    let edition2 = Edition::new(publisher_xid.xid(), mark2, content2).unwrap();

    // Verify sequence
    assert_eq!(edition1.provenance.seq(), 0);
    assert_eq!(edition2.provenance.seq(), 1);
    assert_eq!(
        edition1.provenance.chain_id(),
        edition2.provenance.chain_id()
    );

    // Both editions should have their content digests in provenance info
    assert!(edition1.provenance.info().is_some());
    assert!(edition2.provenance.info().is_some());
}
