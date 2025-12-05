use bc_components::{ARID, XID};
use bc_envelope::prelude::*;
use k256::ProjectivePoint;
use known_values::HOLDER;

use crate::{Error, Result, frost::pm::primitives::point_from_bytes};

/// Round-1 commitment for a provenance-mark VRF ceremony.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FrostPmCommitment {
    pub xid: XID,
    pub session: ARID,
    pub g_commitment: [u8; 33],
    pub h_commitment: [u8; 33],
}

impl FrostPmCommitment {
    pub fn g_point(&self) -> Result<ProjectivePoint> {
        point_from_bytes(&self.g_commitment).map_err(Into::into)
    }

    pub fn h_point(&self) -> Result<ProjectivePoint> {
        point_from_bytes(&self.h_commitment).map_err(Into::into)
    }
}

impl From<FrostPmCommitment> for Envelope {
    fn from(value: FrostPmCommitment) -> Self {
        let mut e = Envelope::new(known_values::UNIT);
        e = e.add_type("FrostPmCommitment");
        e = e.add_assertion(HOLDER, value.xid);
        e = e.add_assertion("session", value.session);
        e = e.add_assertion(
            "gCommitment",
            CBOR::from(ByteString::from(value.g_commitment.to_vec())),
        );
        e = e.add_assertion(
            "hCommitment",
            CBOR::from(ByteString::from(value.h_commitment.to_vec())),
        );
        e
    }
}

impl TryFrom<Envelope> for FrostPmCommitment {
    type Error = Error;

    fn try_from(envelope: Envelope) -> Result<Self> {
        envelope.check_type("FrostPmCommitment")?;
        let subj_env = envelope.subject();
        let kv = subj_env.try_known_value()?;
        if kv.value() != known_values::UNIT.value() {
            return Err(Error::msg("unexpected subject for FrostPmCommitment"));
        }
        let xid: XID = envelope.try_object_for_predicate(HOLDER)?;
        let session: ARID = envelope.try_object_for_predicate("session")?;
        let g_bs: ByteString =
            envelope.try_object_for_predicate("gCommitment")?;
        let h_bs: ByteString =
            envelope.try_object_for_predicate("hCommitment")?;
        let g_vec: Vec<u8> = g_bs.into();
        let h_vec: Vec<u8> = h_bs.into();
        let g_commitment: [u8; 33] = g_vec
            .try_into()
            .map_err(|_| Error::msg("invalid gCommitment length"))?;
        let h_commitment: [u8; 33] = h_vec
            .try_into()
            .map_err(|_| Error::msg("invalid hCommitment length"))?;
        Ok(Self { xid, session, g_commitment, h_commitment })
    }
}

#[cfg(test)]
mod tests {
    use indoc::indoc;

    use super::*;

    #[test]
    fn frost_pm_commitment_roundtrip_text() {
        let xid = XID::from_hex(
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        );
        let session = ARID::from_hex(
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        );
        let commitment = FrostPmCommitment {
            xid,
            session,
            g_commitment: [0x11; 33],
            h_commitment: [0x22; 33],
        };
        let env: Envelope = commitment.clone().into();
        #[rustfmt::skip]
        let expected = (indoc! {r#"
            '' [
                'isA': "FrostPmCommitment"
                "gCommitment": Bytes(33)
                "hCommitment": Bytes(33)
                "session": ARID(bbbbbbbb)
                'holder': XID(aaaaaaaa)
            ]
        "#}).trim();
        assert_eq!(env.format(), expected);
        let rt = FrostPmCommitment::try_from(env).unwrap();
        assert_eq!(commitment, rt);
    }
}
