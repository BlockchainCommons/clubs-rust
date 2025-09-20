use bc_components::ARID;
use bc_envelope::prelude::*;

use super::share::FrostSignatureShare;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FrostSignatureShares {
    pub(crate) session: ARID,
    pub(crate) shares: Vec<FrostSignatureShare>,
}

impl FrostSignatureShares {
    pub fn new(session: ARID, shares: Vec<FrostSignatureShare>) -> Self {
        Self { session, shares }
    }
}

impl From<FrostSignatureShares> for Envelope {
    fn from(value: FrostSignatureShares) -> Self {
        let mut e = Envelope::new(known_values::UNIT);
        e = e.add_type("FrostSignatureShares");
        e = e.add_assertion("session", value.session);
        for s in value.shares {
            let se: Envelope = s.into();
            let assertion = Envelope::new_assertion("share", se);
            e = e.add_assertion_envelope(assertion).unwrap();
        }
        e
    }
}

impl TryFrom<Envelope> for FrostSignatureShares {
    type Error = anyhow::Error;
    fn try_from(envelope: Envelope) -> anyhow::Result<Self> {
        envelope.check_type_envelope("FrostSignatureShares")?;
        let subj_env = envelope.subject();
        let kv = subj_env.try_known_value()?;
        if kv.value() != known_values::UNIT.value() {
            anyhow::bail!("unexpected subject for FrostSignatureShares");
        }
        let session: ARID = envelope.try_object_for_predicate("session")?;
        let mut shares: Vec<FrostSignatureShare> = Vec::new();
        for assertion in envelope.assertions() {
            let pred_env = assertion.try_predicate()?;
            if let Ok(pred) = pred_env.try_leaf() {
                if let Ok(name) = <String as TryFrom<_>>::try_from(pred.clone())
                {
                    if name == "share" {
                        let obj_env = assertion.try_object()?;
                        let s = FrostSignatureShare::try_from(obj_env)?;
                        if s.session != session {
                            anyhow::bail!(
                                "share session mismatch in container"
                            );
                        }
                        shares.push(s);
                    }
                }
            }
        }
        Ok(FrostSignatureShares { session, shares })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use indoc::indoc;

    #[test]
    fn frost_signature_shares_roundtrip_text() {
        let xid1 = bc_components::XID::from_hex(
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        );
        let xid2 = bc_components::XID::from_hex(
            "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
        );
        let session = bc_components::ARID::from_hex(
            "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
        );
        let s1 =
            FrostSignatureShare { xid: xid1, session, share: vec![0x01, 0x02] };
        let s2 =
            FrostSignatureShare { xid: xid2, session, share: vec![0x03, 0x04] };
        let shares =
            FrostSignatureShares::new(session, vec![s1.clone(), s2.clone()]);
        let env: Envelope = shares.clone().into();
        #[rustfmt::skip]
        let expected = (indoc! {r#"
            '' [
                'isA': "FrostSignatureShares"
                "session": ARID(dddddddd)
                "share": '' [
                    'isA': "FrostSignatureShare"
                    "session": ARID(dddddddd)
                    "share": Bytes(2)
                    'holder': XID(bbbbbbbb)
                ]
                "share": '' [
                    'isA': "FrostSignatureShare"
                    "session": ARID(dddddddd)
                    "share": Bytes(2)
                    'holder': XID(cccccccc)
                ]
            ]
        "#}).trim();
        assert_eq!(env.format(), expected);
        let rt = FrostSignatureShares::try_from(env).unwrap();
        assert_eq!(shares.session, rt.session);
        let mut a = shares.shares.clone();
        let mut b = rt.shares.clone();
        a.sort_by_key(|s| s.xid);
        b.sort_by_key(|s| s.xid);
        assert_eq!(a, b);
    }
}
