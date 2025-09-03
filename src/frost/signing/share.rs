use bc_components::{XID, ARID};
use bc_envelope::prelude::*;
use known_values::HOLDER;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FrostSignatureShare {
    pub xid: XID,
    pub session: ARID,
    pub(crate) share: Vec<u8>,
}

impl From<FrostSignatureShare> for Envelope {
    fn from(value: FrostSignatureShare) -> Self {
        let mut e = Envelope::new(known_values::UNIT);
        e = e.add_assertion(HOLDER, value.xid);
        e = e.add_assertion("session", value.session);
        e = e.add_assertion("share", CBOR::to_byte_string(value.share.clone()));
        e
    }
}

impl TryFrom<Envelope> for FrostSignatureShare {
    type Error = anyhow::Error;
    fn try_from(envelope: Envelope) -> anyhow::Result<Self> {
        let subj_env = envelope.subject();
        let kv = subj_env.try_known_value()?;
        if kv.value() != known_values::UNIT.value() {
            anyhow::bail!("unexpected subject for FrostSignatureShare");
        }
        let xid_env = envelope.object_for_predicate(HOLDER)?;
        let xid: XID = xid_env.try_leaf()?.try_into()?;
        let session_env = envelope.object_for_predicate("session")?;
        let session: ARID = session_env.try_leaf()?.try_into()?;
        let share_env = envelope.object_for_predicate("share")?;
        let share = share_env.try_leaf()?.try_byte_string()?.to_vec();
        Ok(FrostSignatureShare { xid, session, share })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use indoc::indoc;

    #[test]
    fn frost_signature_share_roundtrip_text() {
        let xid = bc_components::XID::from_hex(
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        );
        let session = bc_components::ARID::from_hex(
            "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
        );
        let share = FrostSignatureShare { xid, session, share: vec![0x55, 0x66, 0x77] };
        let env: Envelope = share.clone().into();
        #[rustfmt::skip]
        let expected = (indoc! {r#"
            '' [
                "session": ARID(cccccccc)
                "share": Bytes(3)
                'holder': XID(aaaaaaaa)
            ]
        "#}).trim();
        assert_eq!(env.format(), expected);
        let rt = FrostSignatureShare::try_from(env).unwrap();
        assert_eq!(share, rt);
    }
}
