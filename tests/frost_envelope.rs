use std::collections::BTreeMap;

use bc_components::{DigestProvider, PrivateKeyBase, SchnorrPublicKey, SigningPublicKey};
use bc_envelope::prelude::*;
use clubs::frost::{
    aggregate_and_attach_signature as agg_attach, FrostPublicKeyPackage, FrostSigner,
    FrostSigningCommitmentSec1, FrostSigningPackageG, FrostSignatureSharesG, FROSTGroup,
};
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
    let base = Envelope::new("FROST demo")
        .add_assertion("note", "This is an assertion on the subject.");
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

    // --- Build Gordian FROSTGroup analog and call the stack-friendly helper ---
    // Convert group verifying key (33-byte SEC1 -> x-only Schnorr SigningPublicKey)
    let pk_bytes33_vec = public_key_package
        .verifying_key()
        .serialize()
        .expect("serialize group key");
    assert!(pk_bytes33_vec.len() == 33 && (pk_bytes33_vec[0] == 0x02 || pk_bytes33_vec[0] == 0x03));
    let mut pk_bytes33 = [0u8; 33];
    pk_bytes33.copy_from_slice(&pk_bytes33_vec);
    let mut xonly = [0u8; 32];
    xonly.copy_from_slice(&pk_bytes33[1..]);
    let schnorr_pk = SchnorrPublicKey::from_data(xonly);
    let signing_key = SigningPublicKey::from_schnorr(schnorr_pk);

    // Build three local XIDs for Alice, Bob, and Charlie
    let alice_xid = bc_components::XID::new(
        PrivateKeyBase::new().schnorr_public_keys().signing_public_key(),
    );
    let bob_xid = bc_components::XID::new(
        PrivateKeyBase::new().schnorr_public_keys().signing_public_key(),
    );
    let charlie_xid = bc_components::XID::new(
        PrivateKeyBase::new().schnorr_public_keys().signing_public_key(),
    );

    // Build verifying_shares map from the frost public key package and our known ids
    let mut verifying_shares_sec1: BTreeMap<Vec<u8>, [u8; 33]> = BTreeMap::new();
    for id in &ids {
        let vs_bytes = public_key_package
            .verifying_shares()
            .get(id)
            .unwrap()
            .serialize()
            .expect("serialize verifying share");
        let mut arr = [0u8; 33];
        arr.copy_from_slice(&vs_bytes);
        verifying_shares_sec1.insert(id.serialize(), arr);
    }
    let pubkey_pkg = FrostPublicKeyPackage { verifying_key_sec1: pk_bytes33, verifying_shares_sec1 };
    let group = FROSTGroup::new(
        min_signers as usize,
        vec![
            FrostSigner { xid: alice_xid, identifier: 1 },
            FrostSigner { xid: bob_xid, identifier: 2 },
            FrostSigner { xid: charlie_xid, identifier: 3 },
        ],
        pubkey_pkg,
    );

    // Convert frost signing package + shares to Gordian analogs
    let mut commitments_g: BTreeMap<u16, FrostSigningCommitmentSec1> = BTreeMap::new();
    for (id, comm) in signing_package.signing_commitments() {
        let hid = comm
            .hiding()
            .serialize()
            .expect("serialize hiding commitment");
        let bind = comm
            .binding()
            .serialize()
            .expect("serialize binding commitment");
        let mut h = [0u8; 33];
        h.copy_from_slice(&hid);
        let mut b = [0u8; 33];
        b.copy_from_slice(&bind);
        let id_u16 = if *id == alice_id { 1 } else if *id == bob_id { 2 } else { 3 };
        commitments_g.insert(id_u16, FrostSigningCommitmentSec1 { hiding: h, binding: b });
    }
    let signing_package_g = FrostSigningPackageG { message: message.to_vec(), commitments: commitments_g };
    let mut shares_g: BTreeMap<u16, Vec<u8>> = BTreeMap::new();
    for (id, share) in &shares {
        let id_u16 = if *id == alice_id { 1 } else if *id == bob_id { 2 } else { 3 };
        shares_g.insert(id_u16, share.serialize());
    }
    let shares_g = FrostSignatureSharesG { shares: shares_g };

    let (signed_wrapped, signing_key) = agg_attach(&wrapped, &group, &signing_package_g, &shares_g).unwrap();
    assert!(signed_wrapped.has_signature_from(&signing_key).unwrap());
    signed_wrapped.verify_signature_from(&signing_key).unwrap();
}

// (Helper moved into clubs::frost module).
