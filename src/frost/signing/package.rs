use bc_components::ARID;
use bc_envelope::prelude::*;

use super::commitment::FrostSigningCommitment;
use crate::{Error, Result};

#[derive(Clone, Debug)]
pub struct FrostSigningPackage {
    pub(crate) session: ARID,
    pub(crate) message: Envelope,
    pub(crate) commitments: Vec<FrostSigningCommitment>,
}

pub fn build_signing_package(
    session: &ARID,
    envelope: &Envelope,
    commitments: Vec<FrostSigningCommitment>,
) -> FrostSigningPackage {
    FrostSigningPackage {
        session: *session,
        message: envelope.clone(),
        commitments,
    }
}

impl From<FrostSigningPackage> for Envelope {
    fn from(value: FrostSigningPackage) -> Self {
        let mut e = Envelope::new(known_values::UNIT);
        e = e.add_type("FrostSigningPackage");
        e = e.add_assertion("session", value.session);
        e = e.add_assertion("message", value.message.clone());
        for c in value.commitments {
            let ce: Envelope = c.into();
            let assertion = Envelope::new_assertion("commitment", ce);
            e = e.add_assertion_envelope(assertion).unwrap();
        }
        e
    }
}

impl TryFrom<Envelope> for FrostSigningPackage {
    type Error = Error;
    fn try_from(envelope: Envelope) -> Result<Self> {
        envelope.check_type("FrostSigningPackage")?;
        let subj_env = envelope.subject();
        let kv = subj_env.try_known_value()?;
        if kv.value() != known_values::UNIT.value() {
            return Err(Error::msg(
                "unexpected subject for FrostSigningPackage",
            ));
        }
        let session: ARID = envelope.try_object_for_predicate("session")?;
        let message = envelope.object_for_predicate("message")?;
        let mut commitments: Vec<FrostSigningCommitment> = Vec::new();
        for assertion in envelope.assertions() {
            let pred_env = assertion.try_predicate()?;
            if let Ok(pred) = pred_env.try_leaf()
                && let Ok(name) = <String as TryFrom<_>>::try_from(pred.clone())
                && name == "commitment"
            {
                let obj_env = assertion.try_object()?;
                let c = FrostSigningCommitment::try_from(obj_env)?;
                commitments.push(c);
            }
        }
        Ok(FrostSigningPackage { session, message, commitments })
    }
}

#[cfg(test)]
mod tests {
    use bc_components::XID;
    use indoc::indoc;

    use super::*;

    #[test]
    fn frost_signing_package_roundtrip_text() {
        let xid1 = XID::from_hex(
            "1111111111111111111111111111111111111111111111111111111111111111",
        );
        let xid2 = XID::from_hex(
            "2222222222222222222222222222222222222222222222222222222222222222",
        );
        let session = ARID::from_hex(
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        );
        let c1 = FrostSigningCommitment::new(xid1, session, [1; 33], [2; 33])
            .unwrap();
        let c2 = FrostSigningCommitment::new(xid2, session, [3; 33], [4; 33])
            .unwrap();
        let msg = Envelope::new("MSG");
        let pkg = FrostSigningPackage {
            session,
            message: msg.clone(),
            commitments: vec![c1.clone(), c2.clone()],
        };
        let env: Envelope = pkg.clone().into();
        #[rustfmt::skip]
        let expected = (indoc! {r#"
            '' [
                'isA': "FrostSigningPackage"
                "commitment": '' [
                    'isA': "FrostSigningCommitment"
                    "binding": Bytes(33)
                    "hiding": Bytes(33)
                    "session": ARID(bbbbbbbb)
                    'holder': XID(11111111)
                ]
                "commitment": '' [
                    'isA': "FrostSigningCommitment"
                    "binding": Bytes(33)
                    "hiding": Bytes(33)
                    "session": ARID(bbbbbbbb)
                    'holder': XID(22222222)
                ]
                "message": "MSG"
                "session": ARID(bbbbbbbb)
            ]
        "#}).trim();
        assert_eq!(env.format(), expected);
        let rt = FrostSigningPackage::try_from(env).unwrap();
        assert_eq!(
            pkg.message.subject().digest(),
            rt.message.subject().digest()
        );
        assert_eq!(pkg.session, rt.session);
        let mut a = pkg.commitments.clone();
        let mut b = rt.commitments.clone();
        a.sort_by_key(|c| c.xid);
        b.sort_by_key(|c| c.xid);
        assert_eq!(a, b);
    }
}
