use std::collections::BTreeMap;

use bc_components::{DigestProvider, SchnorrPublicKey, Signature, SigningPublicKey, Verifier};
use bc_envelope::prelude::*;
use frost_secp256k1_tr as frost;
use frost_secp256k1_tr::Group; // for Group::serialize
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

    // --- Aggregate the group signature and verify with the group public key (FROST API) ---
    let group_sig = frost::aggregate(&signing_package, &shares, &public_key_package)
        .expect("aggregate");

    // Third party verifier uses only the group pubkey to check the signature over message
    public_key_package
        .verifying_key()
        .verify(message, &group_sig)
        .expect("group signature verifies");

    // --- Convert to bc-components::Signature and attach to the WRAPPED envelope ---
    // FROST signature should be indistinguishable from a BIP-340 Schnorr signature.
    let sig_vec = group_sig.serialize().expect("serialize signature");
    assert_eq!(sig_vec.len(), 64);
    let mut sig_bytes = [0u8; 64];
    sig_bytes.copy_from_slice(&sig_vec);
    let signature = Signature::schnorr_from_data(sig_bytes);

    // Convert the FROST group public key to a Schnorr x-only pubkey (32 bytes)
    // Serialize group public key (compressed SEC1 33 bytes) via the verifying key API
    let pk_bytes33 = public_key_package
        .verifying_key()
        .serialize()
        .expect("serialize group key");
    assert!(pk_bytes33.len() == 33 && (pk_bytes33[0] == 0x02 || pk_bytes33[0] == 0x03));
    let mut xonly = [0u8; 32];
    xonly.copy_from_slice(&pk_bytes33[1..]);
    let schnorr_pk = SchnorrPublicKey::from_data(xonly);
    let signing_key = SigningPublicKey::from_schnorr(schnorr_pk);

    // Attach the signature as an assertion to the WRAPPED envelope
    let signed_wrapped = wrapped.add_assertion(known_values::SIGNED, signature.clone());

    // Verify using bc-envelope's verification helpers and the group public key
    assert!(signed_wrapped.has_signature_from(&signing_key).unwrap());
    signed_wrapped.verify_signature_from(&signing_key).unwrap();
}
