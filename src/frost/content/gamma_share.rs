use bc_components::{ARID, XID};
use bc_envelope::prelude::*;
use k256::ProjectivePoint;
use known_values::HOLDER;

use crate::{Error, Result, frost::pm::primitives::point_from_bytes};

/// Participant contribution to the VRF output when deriving a content key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FrostContentGammaShare {
    pub xid: XID,
    pub session: ARID,
    pub gamma_bytes: [u8; 33],
}

impl FrostContentGammaShare {
    pub fn to_point(&self) -> Result<ProjectivePoint> {
        point_from_bytes(&self.gamma_bytes).map_err(Into::into)
    }
}

impl From<FrostContentGammaShare> for Envelope {
    fn from(value: FrostContentGammaShare) -> Self {
        let mut e = Envelope::new(known_values::UNIT);
        e = e.add_type("FrostContentGammaShare");
        e = e.add_assertion(HOLDER, value.xid);
        e = e.add_assertion("session", value.session);
        e = e.add_assertion(
            "gamma",
            CBOR::from(ByteString::from(value.gamma_bytes.to_vec())),
        );
        e
    }
}

impl TryFrom<Envelope> for FrostContentGammaShare {
    type Error = Error;

    fn try_from(envelope: Envelope) -> Result<Self> {
        envelope.check_type("FrostContentGammaShare")?;
        let subj_env = envelope.subject();
        let kv = subj_env.try_known_value()?;
        if kv.value() != known_values::UNIT.value() {
            return Err(Error::msg(
                "unexpected subject for FrostContentGammaShare",
            ));
        }
        let xid: XID = envelope.try_object_for_predicate(HOLDER)?;
        let session: ARID = envelope.try_object_for_predicate("session")?;
        let gamma_bs: ByteString =
            envelope.try_object_for_predicate("gamma")?;
        let gamma_vec: Vec<u8> = gamma_bs.into();
        let gamma_bytes: [u8; 33] = gamma_vec
            .try_into()
            .map_err(|_| Error::msg("invalid gamma length"))?;
        Ok(Self { xid, session, gamma_bytes })
    }
}

#[cfg(test)]
mod tests {
    use indoc::indoc;

    use super::*;

    #[test]
    fn frost_content_gamma_share_roundtrip_text() {
        let xid = XID::from_hex(
            "1111111111111111111111111111111111111111111111111111111111111111",
        );
        let session = ARID::from_hex(
            "2222222222222222222222222222222222222222222222222222222222222222",
        );
        let share =
            FrostContentGammaShare { xid, session, gamma_bytes: [0x33; 33] };
        let env: Envelope = share.clone().into();
        #[rustfmt::skip]
        let expected = (indoc! {r#"
            '' [
                'isA': "FrostContentGammaShare"
                "gamma": Bytes(33)
                "session": ARID(22222222)
                'holder': XID(11111111)
            ]
        "#}).trim();
        assert_eq!(env.format(), expected);
        let rt = FrostContentGammaShare::try_from(env).unwrap();
        assert_eq!(share, rt);
    }
}
