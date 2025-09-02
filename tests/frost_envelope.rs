use std::collections::BTreeMap;

use bc_components::{DigestProvider, SchnorrPublicKey, Signature, SigningPublicKey};
use bc_envelope::prelude::*;
use frost_secp256k1_tr as frost;
use frost_secp256k1_tr::{
    Identifier,
    keys::{KeyPackage, PublicKeyPackage},
    round1::{SigningCommitments, SigningNonces},
    round2::SignatureShare,
};
use rand::rngs::OsRng;

#[test]
fn frost_two_of_three_signs_envelope_and_verify() {
    // --- Setup a 2-of-3 FROST (secp256k1-taproot) group using Trusted Dealer ---
    let max_signers: u16 = 3;
    let min_signers: u16 = 2;
    let ids: Vec<Identifier> = vec![
        Identifier::try_from(1u16).unwrap(), // Alice
        Identifier::try_from(2u16).unwrap(), // Bob
        Identifier::try_from(3u16).unwrap(), // Charlie
    ];

    let mut rng = OsRng;
    let (secret_shares, public_key_package): (
        BTreeMap<Identifier, frost::keys::SecretShare>,
        PublicKeyPackage,
    ) = frost::keys::generate_with_dealer(
        max_signers,
        min_signers,
        frost::keys::IdentifierList::Custom(&ids),
        &mut rng,
    )
    .expect("trusted dealer generation");

    // Convert SecretShare -> KeyPackage for each participant
    let mut key_packages: BTreeMap<Identifier, KeyPackage> = BTreeMap::new();
    for (id, ss) in &secret_shares {
        let kp = KeyPackage::try_from(ss.clone()).expect("key package");
        key_packages.insert(*id, kp);
    }

    // --- Prepare an Envelope, then WRAP it so the signature covers the whole structure ---
    let base = Envelope::new("FROST demo: quorum signs this subject")
        .add_assertion("note", "This is only a demo of FROST signing a wrapped envelope subject digest.");
    let wrapped = base.wrap();
    // Subject of `wrapped` is the original envelope; signing covers the wrapped subject digest
    let wrapped_subject = wrapped.subject();
    let message_digest = wrapped_subject.digest();
    let message: &[u8] = message_digest.as_ref().as_ref();

    // --- Round 1: Alice + Bob produce nonces and commitments (Charlie idle) ---
    let alice_id = ids[0];
    let bob_id = ids[1];
    let _charlie_id = ids[2];

    let (alice_nonces, alice_comms): (SigningNonces, SigningCommitments) =
        frost::round1::commit(
            key_packages[&alice_id].signing_share(),
            &mut rng,
        );
    let (bob_nonces, bob_comms): (SigningNonces, SigningCommitments) =
        frost::round1::commit(key_packages[&bob_id].signing_share(), &mut rng);

    let mut commitments: BTreeMap<Identifier, SigningCommitments> = BTreeMap::new();
    commitments.insert(alice_id, alice_comms);
    commitments.insert(bob_id, bob_comms);

    // Build the signing package with the message and signer commitments
    let signing_package = frost::SigningPackage::new(commitments, message);

    // --- Round 2: Alice + Bob create signature shares ---
    let alice_share: SignatureShare = frost::round2::sign(
        &signing_package,
        &alice_nonces,
        &key_packages[&alice_id],
    )
    .expect("alice share");
    let bob_share: SignatureShare = frost::round2::sign(
        &signing_package,
        &bob_nonces,
        &key_packages[&bob_id],
    )
    .expect("bob share");

    let mut shares: BTreeMap<Identifier, SignatureShare> = BTreeMap::new();
    shares.insert(alice_id, alice_share);
    shares.insert(bob_id, bob_share);

    // --- Aggregate, attach, and verify via helper ---
    let (signed_wrapped, signing_key) = aggregate_and_attach_signature(
        &wrapped,
        &signing_package,
        &shares,
        &public_key_package,
    );
    assert!(signed_wrapped.has_signature_from(&signing_key).unwrap());
    signed_wrapped.verify_signature_from(&signing_key).unwrap();
}

fn aggregate_and_attach_signature(
    envelope: &Envelope,
    signing_package: &frost::SigningPackage,
    shares: &BTreeMap<Identifier, SignatureShare>,
    public_key_package: &PublicKeyPackage,
) -> (Envelope, SigningPublicKey) {
    // Aggregate and check with FROST verifying key
    let group_sig = frost::aggregate(signing_package, shares, public_key_package)
        .expect("aggregate");
    // Derive message to verify from the envelope's subject digest
    let subject = envelope.subject();
    let subject_digest = subject.digest();
    let message: &[u8] = subject_digest.as_ref().as_ref();
    public_key_package
        .verifying_key()
        .verify(message, &group_sig)
        .expect("group signature verifies");

    // Convert to bc-components::Signature (BIP-340 Schnorr)
    let sig_vec = group_sig.serialize().expect("serialize signature");
    assert_eq!(sig_vec.len(), 64);
    let mut sig_bytes = [0u8; 64];
    sig_bytes.copy_from_slice(&sig_vec);
    let signature = Signature::schnorr_from_data(sig_bytes);

    // Convert group pubkey to x-only Schnorr key for bc-components
    let pk_bytes33 = public_key_package
        .verifying_key()
        .serialize()
        .expect("serialize group key");
    assert!(pk_bytes33.len() == 33 && (pk_bytes33[0] == 0x02 || pk_bytes33[0] == 0x03));
    let mut xonly = [0u8; 32];
    xonly.copy_from_slice(&pk_bytes33[1..]);
    let schnorr_pk = SchnorrPublicKey::from_data(xonly);
    let signing_key = SigningPublicKey::from_schnorr(schnorr_pk);

    // Attach signature assertion to the envelope (signatures are assertions on the subject)
    let signed = envelope.add_assertion(known_values::SIGNED, signature);
    (signed, signing_key)
}
