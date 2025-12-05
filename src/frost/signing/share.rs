use bc_components::{ARID, XID};
use bc_envelope::prelude::*;

use crate::{Error, Result};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FrostSignatureShare {
    pub xid: XID,
    pub session: ARID,
    pub(crate) share: Vec<u8>,
}

impl From<FrostSignatureShare> for Envelope {
    fn from(value: FrostSignatureShare) -> Self {
        let mut e = Envelope::new(known_values::UNIT);
        e = e.add_type("FrostSignatureShare");
        e = e.add_assertion(known_values::HOLDER, value.xid);
        e = e.add_assertion("session", value.session);
        e = e.add_assertion("share", CBOR::to_byte_string(value.share.clone()));
        e
    }
}

impl TryFrom<Envelope> for FrostSignatureShare {
    type Error = Error;
    fn try_from(envelope: Envelope) -> Result<Self> {
        envelope.check_type("FrostSignatureShare")?;
        let subj_env = envelope.subject();
        let kv = subj_env.try_known_value()?;
        if kv.value() != known_values::UNIT.value() {
            return Err(Error::msg(
                "unexpected subject for FrostSignatureShare",
            ));
        }
        let xid: XID =
            envelope.try_object_for_predicate(known_values::HOLDER)?;
        let session: ARID = envelope.try_object_for_predicate("session")?;
        let share_bs: ByteString =
            envelope.try_object_for_predicate("share")?;
        let share: Vec<u8> = share_bs.into();
        Ok(FrostSignatureShare { xid, session, share })
    }
}

#[cfg(test)]
mod tests {
    use indoc::indoc;

    use super::*;

    #[test]
    fn frost_signature_share_roundtrip_text() {
        let xid = XID::from_hex(
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        );
        let session = ARID::from_hex(
            "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
        );
        let share =
            FrostSignatureShare { xid, session, share: vec![0x55, 0x66, 0x77] };
        let env: Envelope = share.clone().into();
        #[rustfmt::skip]
        let expected = (indoc! {r#"
            '' [
                'isA': "FrostSignatureShare"
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
