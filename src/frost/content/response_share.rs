use bc_components::{ARID, XID};
use bc_envelope::prelude::*;
use k256::Scalar;
use known_values::HOLDER;

use crate::{
    Error, Result,
    frost::pm::{scalar_from_be_bytes, scalar_to_be_bytes},
};

/// Participant response share for the content-key ceremony (partial `z`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FrostContentResponseShare {
    pub xid: XID,
    pub session: ARID,
    pub z_bytes: [u8; 32],
}

impl FrostContentResponseShare {
    pub fn to_scalar(&self) -> Result<Scalar> {
        scalar_from_be_bytes(&self.z_bytes)
    }

    pub fn from_scalar(xid: XID, session: ARID, scalar: &Scalar) -> Self {
        Self { xid, session, z_bytes: scalar_to_be_bytes(scalar) }
    }
}

impl From<FrostContentResponseShare> for Envelope {
    fn from(value: FrostContentResponseShare) -> Self {
        let mut e = Envelope::new(known_values::UNIT);
        e = e.add_type("FrostContentResponseShare");
        e = e.add_assertion(HOLDER, value.xid);
        e = e.add_assertion("session", value.session);
        e = e.add_assertion(
            "z",
            CBOR::from(ByteString::from(value.z_bytes.to_vec())),
        );
        e
    }
}

impl TryFrom<Envelope> for FrostContentResponseShare {
    type Error = Error;

    fn try_from(envelope: Envelope) -> Result<Self> {
        envelope.check_type_envelope("FrostContentResponseShare")?;
        let subj_env = envelope.subject();
        let kv = subj_env.try_known_value()?;
        if kv.value() != known_values::UNIT.value() {
            return Err(Error::msg(
                "unexpected subject for FrostContentResponseShare",
            ));
        }
        let xid: XID = envelope.try_object_for_predicate(HOLDER)?;
        let session: ARID = envelope.try_object_for_predicate("session")?;
        let z_bs: ByteString = envelope.try_object_for_predicate("z")?;
        let z_vec: Vec<u8> = z_bs.into();
        let z_bytes: [u8; 32] = z_vec
            .try_into()
            .map_err(|_| Error::msg("invalid z length"))?;
        Ok(Self { xid, session, z_bytes })
    }
}

pub(crate) fn response_share_scalar_from_bytes(bytes: &[u8]) -> Result<Scalar> {
    scalar_from_be_bytes(bytes)
}

#[cfg(test)]
mod tests {
    use indoc::indoc;

    use super::*;

    #[test]
    fn frost_content_response_share_roundtrip_text() {
        let xid = XID::from_hex(
            "3333333333333333333333333333333333333333333333333333333333333333",
        );
        let session = ARID::from_hex(
            "4444444444444444444444444444444444444444444444444444444444444444",
        );
        let share =
            FrostContentResponseShare { xid, session, z_bytes: [0x44; 32] };
        let env: Envelope = share.clone().into();
        #[rustfmt::skip]
        let expected = (indoc! {r#"
            '' [
                'isA': "FrostContentResponseShare"
                "session": ARID(44444444)
                "z": Bytes(32)
                'holder': XID(33333333)
            ]
        "#}).trim();
        assert_eq!(env.format(), expected);
        let rt = FrostContentResponseShare::try_from(env).unwrap();
        assert_eq!(share, rt);
    }
}
