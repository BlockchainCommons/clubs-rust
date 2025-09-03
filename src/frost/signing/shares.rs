use bc_envelope::prelude::*;

use super::share::FrostSignatureShare;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FrostSignatureShares {
    pub(crate) shares: Vec<FrostSignatureShare>,
}

impl FrostSignatureShares {
    pub fn new(shares: Vec<FrostSignatureShare>) -> Self { Self { shares } }
}

impl From<FrostSignatureShares> for Envelope {
    fn from(value: FrostSignatureShares) -> Self {
        let mut e = Envelope::new(known_values::UNIT);
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
        let subj_env = envelope.subject();
        let kv = subj_env.try_known_value()?;
        if kv.value() != known_values::UNIT.value() {
            anyhow::bail!("unexpected subject for FrostSignatureShares");
        }
        let mut shares: Vec<FrostSignatureShare> = Vec::new();
        for assertion in envelope.assertions() {
            let pred_env = assertion.try_predicate()?;
            if let Ok(pred) = pred_env.try_leaf() {
                if let Ok(name) = <String as TryFrom<_>>::try_from(pred.clone()) {
                    if name == "share" {
                        let obj_env = assertion.try_object()?;
                        let s = FrostSignatureShare::try_from(obj_env)?;
                        shares.push(s);
                    }
                }
            }
        }
        Ok(FrostSignatureShares { shares })
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
        let s1 = FrostSignatureShare { xid: xid1, share: vec![0x01, 0x02] };
        let s2 = FrostSignatureShare { xid: xid2, share: vec![0x03, 0x04] };
        let shares = FrostSignatureShares::new(vec![s1.clone(), s2.clone()]);
        let env: Envelope = shares.clone().into();
        #[rustfmt::skip]
        let expected = (indoc! {r#"
            '' [
                "share": '' [
                    "share": Bytes(2)
                    'holder': XID(bbbbbbbb)
                ]
                "share": '' [
                    "share": Bytes(2)
                    'holder': XID(cccccccc)
                ]
            ]
        "#}).trim();
        assert_eq!(env.format(), expected);
        let rt = FrostSignatureShares::try_from(env).unwrap();
        assert_eq!(shares, rt);
    }
}

