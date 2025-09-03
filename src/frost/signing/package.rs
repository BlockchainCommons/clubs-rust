use bc_components::ARID;
use bc_envelope::prelude::*;

use super::commitment::FrostSigningCommitment;

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
) -> FrostSigningPackage { FrostSigningPackage { session: *session, message: envelope.clone(), commitments } }

impl From<FrostSigningPackage> for Envelope {
    fn from(value: FrostSigningPackage) -> Self {
        let mut e = Envelope::new(known_values::UNIT);
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
    type Error = anyhow::Error;
    fn try_from(envelope: Envelope) -> anyhow::Result<Self> {
        let subj_env = envelope.subject();
        let kv = subj_env.try_known_value()?;
        if kv.value() != known_values::UNIT.value() {
            anyhow::bail!("unexpected subject for FrostSigningPackage");
        }
        let session_env = envelope.object_for_predicate("session")?;
        let session: ARID = session_env.try_leaf()?.try_into()?;
        let msg_env = envelope.object_for_predicate("message")?;
        let message = msg_env;
        let mut commitments: Vec<FrostSigningCommitment> = Vec::new();
        for assertion in envelope.assertions() {
            let pred_env = assertion.try_predicate()?;
            if let Ok(pred) = pred_env.try_leaf() {
                if let Ok(name) = <String as TryFrom<_>>::try_from(pred.clone()) {
                    if name == "commitment" {
                        let obj_env = assertion.try_object()?;
                        let c = FrostSigningCommitment::try_from(obj_env)?;
                        commitments.push(c);
                    }
                }
            }
        }
        Ok(FrostSigningPackage { session, message, commitments })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use indoc::indoc;

    #[test]
    fn frost_signing_package_roundtrip_text() {
        let xid1 = bc_components::XID::from_hex(
            "1111111111111111111111111111111111111111111111111111111111111111",
        );
        let xid2 = bc_components::XID::from_hex(
            "2222222222222222222222222222222222222222222222222222222222222222",
        );
        let session = bc_components::ARID::from_hex(
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        );
        let c1 = FrostSigningCommitment { xid: xid1, session, hiding: [1; 33], binding: [2; 33] };
        let c2 = FrostSigningCommitment { xid: xid2, session, hiding: [3; 33], binding: [4; 33] };
        let msg = Envelope::new("MSG");
        let pkg = FrostSigningPackage { session, message: msg.clone(), commitments: vec![c1.clone(), c2.clone()] };
        let env: Envelope = pkg.clone().into();
        #[rustfmt::skip]
        let expected = (indoc! {r#"
            '' [
                "commitment": '' [
                    "binding": Bytes(33)
                    "hiding": Bytes(33)
                    "session": ARID(bbbbbbbb)
                    'holder': XID(11111111)
                ]
                "commitment": '' [
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
        use bc_components::DigestProvider;
        assert_eq!(pkg.message.subject().digest(), rt.message.subject().digest());
        assert_eq!(pkg.session, rt.session);
        let mut a = pkg.commitments.clone();
        let mut b = rt.commitments.clone();
        a.sort_by_key(|c| c.xid);
        b.sort_by_key(|c| c.xid);
        assert_eq!(a, b);
    }
}
