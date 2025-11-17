use std::collections::BTreeMap;

use bc_components::{
    Digest, PrivateKeyBase, PublicKeysProvider, SealedMessage, SymmetricKey,
    XID, XIDProvider,
};
use bc_envelope::prelude::*;
use bc_xid::{XIDDocument, XIDGenesisMarkOptions, XIDInceptionKeyOptions};
use clubs::{
    Error, Result,
    edition::Edition,
    frost::{
        FrostGroup, FrostSigningCoordinator, FrostSigningParticipant,
        content::{
            CONTENT_MESSAGE_PREFIX, FrostContentCoordinator, FrostContentKey,
            FrostContentParticipant,
        },
        pm::{
            DleqProof, FrostPmCoordinator, FrostPmParticipant,
            FrostProvenanceChain, key_from_gamma, point_bytes,
            primitives::hash_to_curve,
        },
    },
    provenance_mark_provider::ProvenanceMarkProvider,
    public_key_permit::PublicKeyPermit,
};
use dcbor::Date;
use provenance_mark::{ProvenanceMark, ProvenanceMarkResolution};

fn iso_date(input: &str) -> Date {
    Date::from_string(input).expect("valid ISO-8601 date")
}

fn frost_pm_advance(
    chain: &mut FrostProvenanceChain,
    coordinator: &mut FrostPmCoordinator,
    participants: &mut BTreeMap<XID, FrostPmParticipant>,
    roster: &[XID],
    date: Date,
    info: Option<&Digest>,
) -> Result<(ProvenanceMark, [u8; 33], DleqProof)> {
    if date < *chain.last_date() {
        return Err(Error::msg("provenance date must be non-decreasing"));
    }

    let (_, _, h_point) = chain.next_message()?;

    coordinator.start_session();
    let session = coordinator.session_id();

    for xid in roster {
        let signer = participants.get_mut(xid).ok_or_else(|| {
            Error::msg(format!("unknown participant: {}", xid))
        })?;
        let commitment = signer.round1_commit(session, &h_point)?;
        coordinator.add_commitment(commitment)?;
    }

    let signing_package = coordinator.signing_package_for(roster, &h_point)?;
    for xid in roster {
        let signer = participants.get_mut(xid).ok_or_else(|| {
            Error::msg(format!("unknown participant: {}", xid))
        })?;
        let gamma_share =
            signer.round2_emit_gamma(chain.group(), &signing_package)?;
        coordinator.record_gamma_share(gamma_share)?;
    }

    let challenge = coordinator.challenge()?;
    for xid in roster {
        let signer = participants.get_mut(xid).ok_or_else(|| {
            Error::msg(format!("unknown participant: {}", xid))
        })?;
        let response = signer.finalize_response(&challenge)?;
        coordinator.record_response(response)?;
    }

    let (gamma_point, proof) = coordinator.finalize()?;
    let gamma_bytes = point_bytes(&gamma_point)?;
    let full_key = key_from_gamma(&gamma_point)?;
    let link_len = chain.resolution().link_length();
    let mut next_key = vec![0u8; link_len];
    next_key.copy_from_slice(&full_key[..link_len]);

    let mark = ProvenanceMark::new(
        chain.resolution(),
        chain.last_key().to_vec(),
        next_key,
        chain.chain_id().to_vec(),
        chain.sequence(),
        date,
        info.cloned(),
    )?;

    chain.verify_advance(&mark, &gamma_bytes, &proof)?;

    Ok((mark, gamma_bytes, proof))
}

fn build_unsigned_sealed_edition(
    edition: &Edition,
    recipients: &[PublicKeyPermit],
    content_key: &SymmetricKey,
) -> Result<Envelope> {
    let do_encrypt = !recipients.is_empty();

    let mut base_subject =
        if edition.content.is_encrypted() || edition.content.is_wrapped() {
            edition.content.clone()
        } else {
            edition.content.clone().wrap()
        };

    if do_encrypt {
        base_subject = edition.content.encrypt(content_key);
    }

    let mut envelope = base_subject
        .add_type("Edition")
        .add_assertion("club", edition.club_xid)
        .add_assertion(known_values::PROVENANCE, edition.provenance.clone());

    if do_encrypt {
        let edition_id_aad: Vec<u8> = envelope.digest().data().to_vec();
        for permit in recipients {
            match permit {
                PublicKeyPermit::Encode { recipient, member_xid } => {
                    let sealed = SealedMessage::new_with_aad(
                        content_key.to_cbor_data(),
                        recipient,
                        Some(edition_id_aad.as_slice()),
                    );
                    let mut assertion = Envelope::new_assertion(
                        known_values::HAS_RECIPIENT,
                        sealed,
                    );
                    if let Some(xid) = member_xid {
                        assertion =
                            assertion.add_assertion(known_values::HOLDER, *xid);
                    }
                    envelope = envelope.add_assertion_envelope(assertion)?;
                }
                PublicKeyPermit::Decode { .. } => {
                    return Err(Error::msg(
                        "cannot build sealed edition from decode permits",
                    ));
                }
            }
        }
    }

    Ok(envelope)
}

fn frost_content_generate_key(
    group: &FrostGroup,
    coordinator: &mut FrostContentCoordinator,
    participants: &mut BTreeMap<XID, FrostContentParticipant>,
    roster: &[XID],
    digest: &Digest,
) -> Result<FrostContentKey> {
    coordinator.start_session();
    let session = coordinator.session_id();

    let mut msg =
        Vec::with_capacity(CONTENT_MESSAGE_PREFIX.len() + digest.data().len());
    msg.extend_from_slice(CONTENT_MESSAGE_PREFIX);
    msg.extend_from_slice(digest.data());
    let h_point = hash_to_curve(&msg)?;

    for xid in roster {
        let participant = participants.get_mut(xid).ok_or_else(|| {
            Error::msg(format!("unknown content participant: {}", xid))
        })?;
        let commitment = participant.round1_commit(session, &h_point)?;
        coordinator.add_commitment(commitment)?;
    }

    let package = coordinator.signing_package_for(roster, digest)?;

    for xid in roster {
        let participant = participants.get_mut(xid).ok_or_else(|| {
            Error::msg(format!("unknown content participant: {}", xid))
        })?;
        let gamma_share = participant.round2_emit_gamma(group, &package)?;
        coordinator.record_gamma_share(gamma_share)?;
    }

    let challenge = coordinator.challenge()?;
    for xid in roster {
        let participant = participants.get_mut(xid).ok_or_else(|| {
            Error::msg(format!("unknown content participant: {}", xid))
        })?;
        let response = participant.finalize_response(&challenge)?;
        coordinator.record_response(response)?;
    }

    coordinator.finalize()
}

fn frost_sign_envelope(
    group: &FrostGroup,
    mut coordinator: FrostSigningCoordinator,
    participants: &mut BTreeMap<XID, FrostSigningParticipant>,
    roster: &[XID],
    message: Envelope,
) -> Result<Envelope> {
    coordinator.set_message(message);
    let session = coordinator.session_id();

    for xid in roster {
        let signer = participants
            .get_mut(xid)
            .ok_or_else(|| Error::msg(format!("unknown signer: {}", xid)))?;
        let commitment = signer.round1_commit(session)?;
        coordinator.add_commitment(commitment)?;
        coordinator.record_consent(*xid)?;
    }

    let signing_package = coordinator.signing_package_from_consent()?;

    for xid in roster {
        let signer = participants
            .get_mut(xid)
            .ok_or_else(|| Error::msg(format!("unknown signer: {}", xid)))?;
        let share = signer.round2_sign(group, &signing_package)?;
        coordinator.add_share(share)?;
    }

    coordinator.finalize()
}

#[test]
fn frost_club_integration_story() -> Result<()> {
    // A 2-of-3 Gordian Club (Alice, Bob, Charlie) publishes three editions.
    // Each edition repeats the same ritual:
    // 1. approve plaintext,
    // 2. derive a shared content key,
    // 3. advance the provenance mark, and
    // 4. sign the sealed envelope.
    provenance_mark::register_tags();

    // Each member has a private key, used for both XID and signing.
    let alice_base = PrivateKeyBase::new();
    let alice_doc = XIDDocument::new(
        XIDInceptionKeyOptions::PrivateKeyBase(alice_base.clone()),
        XIDGenesisMarkOptions::None,
    );

    let bob_base = PrivateKeyBase::new();
    let bob_doc = XIDDocument::new(
        XIDInceptionKeyOptions::PrivateKeyBase(bob_base.clone()),
        XIDGenesisMarkOptions::None,
    );

    let charlie_base = PrivateKeyBase::new();
    let charlie_doc = XIDDocument::new(
        XIDInceptionKeyOptions::PrivateKeyBase(charlie_base.clone()),
        XIDGenesisMarkOptions::None,
    );
    // Build the initial roster; FROST keygen distributes shares to these XIDs.
    let members = vec![alice_doc.xid(), bob_doc.xid(), charlie_doc.xid()];
    let (group, participant_cores) =
        FrostGroup::new_with_trusted_dealer(2, members.clone())?;

    let mut signing_participants: BTreeMap<XID, FrostSigningParticipant> =
        BTreeMap::new();
    let mut pm_participants: BTreeMap<XID, FrostPmParticipant> =
        BTreeMap::new();
    let mut content_participants: BTreeMap<XID, FrostContentParticipant> =
        BTreeMap::new();
    for (xid, core) in participant_cores {
        signing_participants
            .insert(xid, FrostSigningParticipant::from_core(core.clone()));
        pm_participants
            .insert(xid, FrostPmParticipant::from_core(core.clone()));
        content_participants
            .insert(xid, FrostContentParticipant::from_core(core));
    }

    let club_verifier = group.verifying_signing_key();
    let club_xid = XID::new(&club_verifier);

    // Both publisher and independent verifier start from the same genesis mark
    // so later verification needs only public information.
    let genesis = iso_date("2025-01-01");
    let mut publishing_chain = FrostProvenanceChain::new(
        &group,
        ProvenanceMarkResolution::Quartile,
        b"Gordian Club Minutes",
        genesis.clone(),
    )?;
    let mut verifier_chain = FrostProvenanceChain::new(
        &group,
        ProvenanceMarkResolution::Quartile,
        b"Gordian Club Minutes",
        genesis,
    )?;
    let mut pm_coordinator = FrostPmCoordinator::new(group.clone());
    let mut content_coordinator = FrostContentCoordinator::new(group.clone());

    // Local test convenience: keep each member's private key handy so the test
    // can decrypt permits. In production these keys stay with the members; the
    // only shared output is the quorum-derived symmetric key and its permits.
    let mut member_privates: BTreeMap<XID, PrivateKeyBase> = BTreeMap::new();
    member_privates.insert(alice_doc.xid(), alice_base.clone());
    member_privates.insert(bob_doc.xid(), bob_base.clone());
    member_privates.insert(charlie_doc.xid(), charlie_base.clone());

    let permit_recipients: Vec<PublicKeyPermit> = vec![
        PublicKeyPermit::for_member(alice_doc.xid(), &alice_base.public_keys()),
        PublicKeyPermit::for_member(bob_doc.xid(), &bob_base.public_keys()),
        PublicKeyPermit::for_member(
            charlie_doc.xid(),
            &charlie_base.public_keys(),
        ),
    ];

    // Agenda for each meeting: which quorum signs, when it happens, and the
    // plaintext agenda that will become the edition content.
    let publishing_plan = vec![
        (
            "Founding minutes signed by Alice and Bob",
            vec![alice_doc.xid(), bob_doc.xid()],
            iso_date("2025-02-01"),
            "Agenda: establish charter",
        ),
        (
            "Charlie joins Alice for the follow-up meeting",
            vec![alice_doc.xid(), charlie_doc.xid()],
            iso_date("2025-02-05"),
            "Agenda: assign roles",
        ),
        (
            "Bob and Charlie publish interim update",
            vec![bob_doc.xid(), charlie_doc.xid()],
            iso_date("2025-02-10"),
            "Agenda: review action items",
        ),
    ];

    let mut published_editions: Vec<Edition> = Vec::new();

    // Each publishing step walks through the three ceremonies:
    // 1. Review plaintext and derive a shared content key.
    // 2. Advance the provenance chain with the newly approved digest.
    // 3. Seal and FROST-sign the edition that binds everything together.
    for (label, roster, date, body) in publishing_plan {
        // --- Ceremony 1: quorum reviews the plaintext envelope and derives the
        // symmetric key that will encrypt it. The digest is computed over the
        // wrapped plaintext so everyone can confirm later that the ciphertext
        // matches what they approved.
        let content = Envelope::new(body)
            .add_assertion(known_values::NOTE, label)
            .wrap();
        // println!("{}", content.format());
        let content_digest = content.digest().into_owned();
        let content_key = frost_content_generate_key(
            &group,
            &mut content_coordinator,
            &mut content_participants,
            &roster,
            &content_digest,
        )?;
        content_key.verify(&group)?;
        assert_eq!(content_key.digest, content_digest);

        // --- Ceremony 2: derive the next provenance mark using the approved
        // digest and the same roster. The mark becomes the causal link for the
        // edition, so it must predate the signing ceremony.
        let (mark, gamma_bytes, proof) = frost_pm_advance(
            &mut publishing_chain,
            &mut pm_coordinator,
            &mut pm_participants,
            &roster,
            date,
            Some(&content_digest),
        )?;
        verifier_chain.verify_advance(&mark, &gamma_bytes, &proof)?;
        let mark_info_digest = mark
            .info()
            .map(|c| Digest::try_from(c).expect("mark info digest"))
            .expect("provenance mark should carry content digest");
        assert_eq!(mark_info_digest, content_digest);

        // --- Ceremony 3: seal the content with the shared key, attach the
        // provenance mark, and have the same roster sign the edition envelope.
        // Note: encryption itself is done by whoever holds the plaintext
        // (participants or trusted publisher); the coordinator never sees the
        // cleartext, only the digest the group already approved.
        let edition =
            Edition::new(club_xid, mark.clone(), content.clone()).unwrap();
        let unsigned = build_unsigned_sealed_edition(
            &edition,
            &permit_recipients,
            &content_key.key,
        )?;
        // println!("{}", unsigned.format());

        let signing_coordinator = FrostSigningCoordinator::new(group.clone());
        let signed = frost_sign_envelope(
            &group,
            signing_coordinator,
            &mut signing_participants,
            &roster,
            unsigned.clone().wrap(),
        )?;

        signed.verify_signature_from(&club_verifier)?;
        println!("{}", signed.format());

        // The signed edition should round-trip cleanly and carry the mark,
        // permits, and encryption we expect.
        let verified = Edition::unseal(signed.clone(), &club_verifier)?;
        assert_eq!(verified.club_xid, club_xid);
        assert_eq!(verified.provenance, mark);
        assert_eq!(verified.permits.len(), permit_recipients.len());

        // Any member of the signing roster must be able to recover the shared
        // symmetric key and decrypt the edition content. This proves the
        // permits were bound to the approved digest/key pair.
        let mut decrypted_once = false;
        for permit in &verified.permits {
            if let PublicKeyPermit::Decode { sealed, .. } = permit {
                for signer in &roster {
                    if let Some(priv_base) = member_privates.get(signer)
                        && let Ok(plaintext) = sealed.decrypt(priv_base)
                    {
                        let key =
                            SymmetricKey::from_tagged_cbor_data(plaintext)
                                .map_err(|e| {
                                    Error::msg(format!(
                                        "invalid content key encoding: {e}"
                                    ))
                                })?;
                        assert_eq!(key, content_key.key);
                        let decrypted_wrapped =
                            verified.content.decrypt_subject(&key)?;
                        let decrypted = decrypted_wrapped.try_unwrap()?;
                        assert!(decrypted.is_identical_to(&content));
                        decrypted_once = true;
                        break;
                    }
                }
            }
            if decrypted_once {
                break;
            }
        }
        assert!(decrypted_once, "roster should decrypt the edition");

        published_editions.push(verified);
    }

    // The resulting editions must advance in lockstep with their provenance
    // marks: starting from genesis and preserving order with no gaps.
    assert!(<Edition as ProvenanceMarkProvider>::is_sequence_valid(
        &published_editions
    ));
    assert!(
        published_editions
            .first()
            .map(|edition| edition.is_genesis())
            .unwrap_or(false)
    );
    for window in published_editions.windows(2) {
        assert!(window[0].precedes(&window[1]));
    }

    Ok(())
}
