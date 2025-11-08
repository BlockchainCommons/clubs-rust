use std::collections::BTreeMap;

use bc_components::{Digest, PrivateKeyBase, XIDProvider};
use bc_xid::{GenesisMarkOptions, InceptionKeyOptions, XIDDocument};
use clubs::frost::{
    FrostGroup, FrostParticipantCore,
    content::{
        FrostContentCoordinator, FrostContentKey, FrostContentParticipant,
    },
    pm::primitives::{
        hash_to_curve, key_from_gamma, normalize_secret_to_pubkey,
    },
};
use frost_secp256k1_tr as frost;
use k256::Scalar;
use nistrs::{BitsData, TEST_THRESHOLD, TestResultT, prelude::*};

fn content_participants(
    cores: &BTreeMap<bc_components::XID, FrostParticipantCore>,
) -> BTreeMap<bc_components::XID, FrostContentParticipant> {
    cores
        .iter()
        .map(|(xid, core)| {
            (*xid, FrostContentParticipant::from_core(core.clone()))
        })
        .collect()
}

fn run_content_ceremony(
    group: &FrostGroup,
    participants: &mut BTreeMap<bc_components::XID, FrostContentParticipant>,
    roster: &[bc_components::XID],
    digest: &Digest,
) -> FrostContentKey {
    use clubs::frost::content::CONTENT_MESSAGE_PREFIX;

    let mut coordinator = FrostContentCoordinator::new(group.clone());
    coordinator.start_session();
    let session = coordinator.session_id();

    let mut msg =
        Vec::with_capacity(CONTENT_MESSAGE_PREFIX.len() + digest.data().len());
    msg.extend_from_slice(CONTENT_MESSAGE_PREFIX);
    msg.extend_from_slice(digest.data());
    let h_point = hash_to_curve(&msg).expect("hash_to_curve");

    for xid in roster {
        let participant = participants.get_mut(xid).expect("participant");
        let commitment = participant
            .round1_commit(session, &h_point)
            .expect("round1 commit");
        coordinator
            .add_commitment(commitment)
            .expect("add commitment");
    }

    let package = coordinator
        .signing_package_for(roster, digest)
        .expect("signing package");

    for xid in roster {
        let participant = participants.get_mut(xid).expect("participant");
        let gamma_share = participant
            .round2_emit_gamma(group, &package)
            .expect("gamma share");
        coordinator
            .record_gamma_share(gamma_share)
            .expect("record gamma");
    }

    let challenge = coordinator.challenge().expect("challenge");
    for xid in roster {
        let participant = participants.get_mut(xid).expect("participant");
        let response = participant
            .finalize_response(&challenge)
            .expect("response share");
        coordinator
            .record_response(response)
            .expect("record response");
    }

    coordinator.finalize().expect("finalize")
}

#[test]
fn content_key_deterministic_and_roster_invariant() {
    provenance_mark::register_tags();

    let mut members = Vec::new();
    for _ in 0..5 {
        let base = PrivateKeyBase::new();
        let doc = XIDDocument::new(
            InceptionKeyOptions::PrivateKeyBase(base),
            GenesisMarkOptions::None,
        );
        members.push(doc.xid());
    }

    let (group, participant_cores) =
        FrostGroup::new_with_trusted_dealer(3, members.clone()).unwrap();

    let digest = Digest::from_image(b"Example Gordian Content");

    let roster_a: Vec<_> = members.iter().copied().take(3).collect();
    let roster_b: Vec<_> = vec![members[0], members[2], members[4]];

    let mut part_a = content_participants(&participant_cores);
    let mut part_b = content_participants(&participant_cores);
    let mut part_a_again = content_participants(&participant_cores);

    let key_a = run_content_ceremony(&group, &mut part_a, &roster_a, &digest);
    key_a.verify(&group).unwrap();

    let key_b = run_content_ceremony(&group, &mut part_b, &roster_b, &digest);
    key_b.verify(&group).unwrap();

    let key_a_again =
        run_content_ceremony(&group, &mut part_a_again, &roster_a, &digest);
    key_a_again.verify(&group).unwrap();

    assert_eq!(key_a.key, key_b.key);
    assert_eq!(key_a.key, key_a_again.key);
    assert_eq!(key_a.digest, digest);
}

fn reconstruct_secret(
    key_packages: &BTreeMap<frost::Identifier, frost::keys::KeyPackage>,
    ids: &[u16],
) -> Scalar {
    let quorum: Vec<_> = ids
        .iter()
        .map(|i| frost::Identifier::try_from(*i).unwrap())
        .collect();
    let recon_input: Vec<_> =
        quorum.iter().map(|id| key_packages[id].clone()).collect();
    frost::keys::reconstruct(&recon_input)
        .expect("reconstruct")
        .to_scalar()
}

fn generate_keys_for_randomness(
    key_packages: &BTreeMap<frost::Identifier, frost::keys::KeyPackage>,
    pubkeys: &frost::keys::PublicKeyPackage,
    steps: usize,
) -> Vec<[u8; 32]> {
    use clubs::frost::content::CONTENT_MESSAGE_PREFIX;

    let x_point = pubkeys.verifying_key().to_element();
    let x_raw = reconstruct_secret(key_packages, &[1, 3, 5]);
    let x = normalize_secret_to_pubkey(x_raw, &x_point).expect("normalize");

    (0..steps)
        .map(|idx| {
            let body = format!("content-digest-{idx}");
            let digest = Digest::from_image(body.as_bytes());
            let mut msg = Vec::with_capacity(
                CONTENT_MESSAGE_PREFIX.len() + digest.data().len(),
            );
            msg.extend_from_slice(CONTENT_MESSAGE_PREFIX);
            msg.extend_from_slice(digest.data());
            let h_point = hash_to_curve(&msg).expect("hash_to_curve");
            let gamma = h_point * x;
            key_from_gamma(&gamma).expect("key_from_gamma")
        })
        .collect()
}

#[test]
fn content_keys_nist_randomness_suite() {
    let (key_packages, pubkeys) = dealer_keygen(5, 3);
    let steps = 8192usize;
    let keys = generate_keys_for_randomness(&key_packages, &pubkeys, steps);

    let mut bytes = Vec::with_capacity(steps * 32);
    for key in &keys {
        bytes.extend_from_slice(key);
    }
    let data = BitsData::from_binary(bytes);

    let chk = |name: &str, r: TestResultT| {
        assert!(r.0, "NIST {} failed (p = {})", name, r.1);
        assert!(
            r.1 >= TEST_THRESHOLD,
            "NIST {}: p-value {} < {}",
            name,
            r.1,
            TEST_THRESHOLD
        );
    };

    chk("frequency", frequency_test(&data));
    chk("runs", runs_test(&data));
    chk("fft", fft_test(&data));
    chk("universal", universal_test(&data));

    chk(
        "block_frequency(m=128)",
        block_frequency_test(&data, 128)
            .expect("block frequency preconditions"),
    );
    chk(
        "longest_run_of_ones",
        longest_run_of_ones_test(&data).expect("longest-run preconditions"),
    );
    chk("rank", rank_test(&data).expect("rank preconditions"));
    let cu = cumulative_sums_test(&data);
    chk("cumulative_sums-forward", cu[0]);
    chk("cumulative_sums-reverse", cu[1]);
    chk(
        "approximate_entropy(m=10)",
        approximate_entropy_test(&data, 10),
    );
    let serial = serial_test(&data, 16);
    chk("serial(m=16)[0]", serial[0]);
    chk("serial(m=16)[1]", serial[1]);
    chk(
        "overlapping_template(m=9)",
        overlapping_template_test(&data, 9),
    );

    let nonov = non_overlapping_template_test(&data, 9)
        .expect("non-overlapping preconditions");
    let mut fail_indices = Vec::new();
    for (i, tr) in nonov.iter().enumerate() {
        if !(tr.0 && tr.1 >= TEST_THRESHOLD) {
            fail_indices.push((i, tr.1));
        }
    }
    let total = nonov.len();
    let allowed = ((total as f64) * 0.02).ceil() as usize;
    assert!(
        fail_indices.len() <= allowed,
        "NIST non_overlapping_template(m=9): {} of {} subtests failed (allow ≤ {}); examples: {:?}",
        fail_indices.len(),
        total,
        allowed,
        &fail_indices[..fail_indices.len().min(5)]
    );

    match random_excursions_test(&data) {
        Ok(arr) => {
            for (i, tr) in arr.into_iter().enumerate() {
                chk(&format!("random_excursions[{}]", i), tr);
            }
        }
        Err(e) => eprintln!("random_excursions skipped: {}", e),
    }
    match random_excursions_variant_test(&data) {
        Ok(arr) => {
            for (i, tr) in arr.into_iter().enumerate() {
                chk(&format!("random_excursions_variant[{}]", i), tr);
            }
        }
        Err(e) => eprintln!("random_excursions_variant skipped: {}", e),
    }
}

fn dealer_keygen(
    n: u16,
    t: u16,
) -> (
    BTreeMap<frost::Identifier, frost::keys::KeyPackage>,
    frost::keys::PublicKeyPackage,
) {
    let rng = rand::rngs::OsRng;
    let (shares, pubkeys) = frost::keys::generate_with_dealer(
        n,
        t,
        frost::keys::IdentifierList::Default,
        rng,
    )
    .expect("keygen");
    let mut kp = BTreeMap::new();
    for (id, secret_share) in shares {
        kp.insert(
            id,
            frost::keys::KeyPackage::try_from(secret_share).expect("share->kp"),
        );
    }
    (kp, pubkeys)
}
