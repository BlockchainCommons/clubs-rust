use std::collections::BTreeMap;

use bc_components::{
    PrivateKeyBase, PublicKeysProvider, SealedMessage, SymmetricKey, XID,
    XIDProvider,
};
use bc_envelope::prelude::*;
use bc_xid::XIDDocument;
use clubs::{
    Error, Result,
    edition::Edition,
    frost::{
        FrostGroup, FrostSigningCoordinator, FrostSigningParticipant,
        pm::{
            DleqProof, FrostPmCoordinator, FrostPmParticipant,
            FrostProvenanceChain, key_from_gamma, point_bytes,
        },
    },
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
        Option::<dcbor::CBOR>::None,
    )?;

    chain.verify_advance(&mark, &gamma_bytes, &proof)?;

    Ok((mark, gamma_bytes, proof))
}

fn build_unsigned_sealed_edition(
    edition: &Edition,
    recipients: &[PublicKeyPermit],
) -> Result<Envelope> {
    let content_key = SymmetricKey::new();
    let do_encrypt = !recipients.is_empty();

    let mut base_subject =
        if edition.content.is_encrypted() || edition.content.is_wrapped() {
            edition.content.clone()
        } else {
            edition.content.clone().wrap()
        };

    if do_encrypt {
        base_subject = edition.content.encrypt(&content_key);
    }

    let mut envelope = base_subject
        .add_type("Edition")
        .add_assertion("club", edition.club_id)
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
    provenance_mark::register_tags();

    let alice_base = PrivateKeyBase::new();
    let bob_base = PrivateKeyBase::new();
    let charlie_base = PrivateKeyBase::new();

    let alice_doc = XIDDocument::new_with_private_key_base(alice_base.clone());
    let bob_doc = XIDDocument::new_with_private_key_base(bob_base.clone());
    let charlie_doc =
        XIDDocument::new_with_private_key_base(charlie_base.clone());

    let members = vec![alice_doc.xid(), bob_doc.xid(), charlie_doc.xid()];
    let (group, participant_cores) =
        FrostGroup::new_with_trusted_dealer(2, members.clone())?;

    let mut signing_participants: BTreeMap<XID, FrostSigningParticipant> =
        BTreeMap::new();
    let mut pm_participants: BTreeMap<XID, FrostPmParticipant> =
        BTreeMap::new();
    for (xid, core) in participant_cores {
        signing_participants
            .insert(xid, FrostSigningParticipant::from_core(core.clone()));
        pm_participants.insert(xid, FrostPmParticipant::from_core(core));
    }

    let club_verifier = group.verifying_signing_key();
    let club_xid = XID::new(&club_verifier);

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

    let mut published_marks: Vec<ProvenanceMark> = Vec::new();

    for (label, roster, date, body) in publishing_plan {
        let (mark, gamma_bytes, proof) = frost_pm_advance(
            &mut publishing_chain,
            &mut pm_coordinator,
            &mut pm_participants,
            &roster,
            date,
        )?;
        verifier_chain.verify_advance(&mark, &gamma_bytes, &proof)?;

        let content =
            Envelope::new(body).add_assertion(known_values::NOTE, label);
        let edition = Edition::new(club_xid, mark.clone(), content.clone());
        let unsigned =
            build_unsigned_sealed_edition(&edition, &permit_recipients)?;

        let signing_coordinator = FrostSigningCoordinator::new(group.clone());
        let signed = frost_sign_envelope(
            &group,
            signing_coordinator,
            &mut signing_participants,
            &roster,
            unsigned.clone().wrap(),
        )?;

        signed.verify_signature_from(&club_verifier)?;

        let verified = Edition::unseal(signed.clone(), &club_verifier)?;
        assert_eq!(verified.club_id, club_xid);
        assert_eq!(verified.provenance, mark);
        assert_eq!(verified.permits.len(), permit_recipients.len());

        let mut decrypted_once = false;
        for permit in &verified.permits {
            if let PublicKeyPermit::Decode { sealed, .. } = permit {
                for signer in &roster {
                    if let Some(priv_base) = member_privates.get(signer) {
                        if let Ok(plaintext) = sealed.decrypt(priv_base) {
                            let key =
                                SymmetricKey::from_tagged_cbor_data(plaintext)
                                    .map_err(|e| {
                                        Error::msg(format!(
                                            "invalid content key encoding: {e}"
                                        ))
                                    })?;
                            let decrypted_wrapped =
                                verified.content.decrypt_subject(&key)?;
                            let decrypted = decrypted_wrapped.try_unwrap()?;
                            assert!(decrypted.is_identical_to(&content));
                            decrypted_once = true;
                            break;
                        }
                    }
                }
            }
            if decrypted_once {
                break;
            }
        }
        assert!(decrypted_once, "roster should decrypt the edition");

        published_marks.push(mark);
    }

    assert!(ProvenanceMark::is_sequence_valid(&published_marks));
    for window in published_marks.windows(2) {
        let current = &window[0];
        let next = &window[1];
        assert!(current.precedes(next));
    }

    Ok(())
}
