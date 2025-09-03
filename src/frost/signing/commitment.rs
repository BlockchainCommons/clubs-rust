use bc_components::{XID, ARID};
use bc_envelope::prelude::*;
use known_values::HOLDER;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FrostSigningCommitment {
    pub xid: XID,
    pub session: ARID,
    pub(crate) hiding: [u8; 33],
    pub(crate) binding: [u8; 33],
}

impl From<FrostSigningCommitment> for Envelope {
    fn from(value: FrostSigningCommitment) -> Self {
        let mut e = Envelope::new(known_values::UNIT);
        e = e.add_assertion(HOLDER, value.xid);
        e = e.add_assertion("session", value.session);
        e = e.add_assertion("hiding", CBOR::to_byte_string(value.hiding));
        e = e.add_assertion("binding", CBOR::to_byte_string(value.binding));
        e
    }
}

impl TryFrom<Envelope> for FrostSigningCommitment {
    type Error = anyhow::Error;
    fn try_from(envelope: Envelope) -> anyhow::Result<Self> {
        let subj_env = envelope.subject();
        let kv = subj_env.try_known_value()?;
        if kv.value() != known_values::UNIT.value() {
            anyhow::bail!("unexpected subject for FrostSigningCommitment");
        }
        let xid: XID = envelope.try_object_for_predicate(HOLDER)?;
        let session: ARID = envelope.try_object_for_predicate("session")?;
        let hiding_bs: ByteString = envelope.try_object_for_predicate("hiding")?;
        let hiding_bytes = hiding_bs.as_ref();
        if hiding_bytes.len() != 33 { anyhow::bail!("invalid hiding length"); }
        let mut hiding = [0u8; 33];
        hiding.copy_from_slice(hiding_bytes);
        let binding_bs: ByteString = envelope.try_object_for_predicate("binding")?;
        let binding_bytes = binding_bs.as_ref();
        if binding_bytes.len() != 33 { anyhow::bail!("invalid binding length"); }
        let mut binding = [0u8; 33];
        binding.copy_from_slice(binding_bytes);
        Ok(FrostSigningCommitment { xid, session, hiding, binding })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use indoc::indoc;

    #[test]
    fn frost_signing_commitment_roundtrip_text() {
        let xid = bc_components::XID::from_hex(
            "0000000000000000000000000000000000000000000000000000000000000000",
        );
        let session = bc_components::ARID::from_hex(
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        );
        let commit = FrostSigningCommitment { xid, session, hiding: [0xA1; 33], binding: [0xB2; 33] };
        let env: Envelope = commit.clone().into();
        #[rustfmt::skip]
        let expected = (indoc! {r#"
            '' [
                "binding": Bytes(33)
                "hiding": Bytes(33)
                "session": ARID(aaaaaaaa)
                'holder': XID(00000000)
            ]
        "#}).trim();
        assert_eq!(env.format(), expected);
        let rt = FrostSigningCommitment::try_from(env).unwrap();
        assert_eq!(commit, rt);
    }
}
