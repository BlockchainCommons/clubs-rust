use crate::{Error, Result};
use bc_components::{ARID, XID};
use bc_envelope::prelude::*;
use known_values::HOLDER;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FrostSigningCommitment {
    pub xid: XID,
    pub session: ARID,
    pub(crate) hiding: ByteString,
    pub(crate) binding: ByteString,
}

impl FrostSigningCommitment {
    pub fn new(
        xid: XID,
        session: ARID,
        hiding: impl AsRef<[u8]>,
        binding: impl AsRef<[u8]>,
    ) -> Result<Self> {
        let h = hiding.as_ref();
        let b = binding.as_ref();
        if h.len() != 33 {
            return Err(Error::msg(format!(
                "invalid hiding length: {}",
                h.len()
            )));
        }
        if b.len() != 33 {
            return Err(Error::msg(format!(
                "invalid binding length: {}",
                b.len()
            )));
        }
        Ok(Self {
            xid,
            session,
            hiding: ByteString::from(h),
            binding: ByteString::from(b),
        })
    }
}

impl From<FrostSigningCommitment> for Envelope {
    fn from(value: FrostSigningCommitment) -> Self {
        let mut e = Envelope::new(known_values::UNIT);
        e = e.add_type("FrostSigningCommitment");
        e = e.add_assertion(HOLDER, value.xid);
        e = e.add_assertion("session", value.session);
        e = e.add_assertion("hiding", CBOR::from(value.hiding));
        e = e.add_assertion("binding", CBOR::from(value.binding));
        e
    }
}

impl TryFrom<Envelope> for FrostSigningCommitment {
    type Error = Error;
    fn try_from(envelope: Envelope) -> Result<Self> {
        envelope.check_type_envelope("FrostSigningCommitment")?;
        let subj_env = envelope.subject();
        let kv = subj_env.try_known_value()?;
        if kv.value() != known_values::UNIT.value() {
            return Err(Error::msg(
                "unexpected subject for FrostSigningCommitment",
            ));
        }
        let xid: XID = envelope.try_object_for_predicate(HOLDER)?;
        let session: ARID = envelope.try_object_for_predicate("session")?;
        let hiding: ByteString = envelope.try_object_for_predicate("hiding")?;
        let binding: ByteString =
            envelope.try_object_for_predicate("binding")?;
        if hiding.len() != 33 {
            return Err(Error::msg("invalid hiding length"));
        }
        if binding.len() != 33 {
            return Err(Error::msg("invalid binding length"));
        }
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
        let commit =
            FrostSigningCommitment::new(xid, session, [0xA1; 33], [0xB2; 33])
                .unwrap();
        let env: Envelope = commit.clone().into();
        #[rustfmt::skip]
        let expected = (indoc! {r#"
            '' [
                'isA': "FrostSigningCommitment"
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
