use bc_components::XID;
use bc_envelope::prelude::*;
use known_values::HOLDER;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FrostSigningCommitment {
    pub xid: XID,
    pub(crate) hiding: [u8; 33],
    pub(crate) binding: [u8; 33],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FrostSigningPackage {
    pub(crate) message: Vec<u8>,
    pub(crate) commitments: Vec<FrostSigningCommitment>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FrostSignatureShare {
    pub xid: XID,
    pub(crate) share: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FrostSignatureShares {
    pub(crate) shares: Vec<FrostSignatureShare>,
}

impl FrostSignatureShares {
    pub fn new(shares: Vec<FrostSignatureShare>) -> Self { Self { shares } }
}

pub fn build_signing_package(
    envelope: &Envelope,
    commitments: Vec<FrostSigningCommitment>,
) -> FrostSigningPackage {
    let subj = envelope.subject();
    let d = subj.digest();
    let message = d.as_ref().data().to_vec();
    FrostSigningPackage { message, commitments }
}

// Envelope encoding/decoding for wire types

impl From<FrostSigningCommitment> for Envelope {
    fn from(value: FrostSigningCommitment) -> Self {
        let mut e = Envelope::new("FrostSigningCommitment");
        e = e.add_assertion(HOLDER, value.xid);
        e = e.add_assertion("hiding", CBOR::to_byte_string(value.hiding));
        e = e.add_assertion("binding", CBOR::to_byte_string(value.binding));
        e
    }
}

impl TryFrom<Envelope> for FrostSigningCommitment {
    type Error = anyhow::Error;
    fn try_from(envelope: Envelope) -> anyhow::Result<Self> {
        // Validate subject
        let subj: String = envelope.subject().try_leaf()?.try_into()?;
        if subj != "FrostSigningCommitment" {
            anyhow::bail!("unexpected subject: {}", subj);
        }
        let xid_env = envelope.object_for_predicate(HOLDER)?;
        let xid: XID = xid_env.try_leaf()?.try_into()?;
        let hiding_env = envelope.object_for_predicate("hiding")?;
        let hiding_bytes = hiding_env.try_leaf()?.try_byte_string()?;
        if hiding_bytes.len() != 33 {
            anyhow::bail!("invalid hiding length");
        }
        let mut hiding = [0u8; 33];
        hiding.copy_from_slice(&hiding_bytes);
        let binding_env = envelope.object_for_predicate("binding")?;
        let binding_bytes = binding_env.try_leaf()?.try_byte_string()?;
        if binding_bytes.len() != 33 {
            anyhow::bail!("invalid binding length");
        }
        let mut binding = [0u8; 33];
        binding.copy_from_slice(&binding_bytes);
        Ok(FrostSigningCommitment { xid, hiding, binding })
    }
}

impl From<FrostSigningPackage> for Envelope {
    fn from(value: FrostSigningPackage) -> Self {
        let mut e = Envelope::new("FrostSigningPackage");
        e = e.add_assertion(
            "message",
            CBOR::to_byte_string(value.message.clone()),
        );
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
        let subj: String = envelope.subject().try_leaf()?.try_into()?;
        if subj != "FrostSigningPackage" {
            anyhow::bail!("unexpected subject: {}", subj);
        }
        let msg_env = envelope.object_for_predicate("message")?;
        let message = msg_env.try_leaf()?.try_byte_string()?.to_vec();
        let mut commitments: Vec<FrostSigningCommitment> = Vec::new();
        for assertion in envelope.assertions() {
            let pred_env = assertion.try_predicate()?;
            if let Ok(pred) = pred_env.try_leaf() {
                if let Ok(name) = <String as TryFrom<_>>::try_from(pred.clone())
                {
                    if name == "commitment" {
                        let obj_env = assertion.try_object()?;
                        let c = FrostSigningCommitment::try_from(obj_env)?;
                        commitments.push(c);
                    }
                }
            }
        }
        Ok(FrostSigningPackage { message, commitments })
    }
}

impl From<FrostSignatureShare> for Envelope {
    fn from(value: FrostSignatureShare) -> Self {
        let mut e = Envelope::new("FrostSignatureShare");
        e = e.add_assertion(HOLDER, value.xid);
        e = e.add_assertion("share", CBOR::to_byte_string(value.share.clone()));
        e
    }
}

impl TryFrom<Envelope> for FrostSignatureShare {
    type Error = anyhow::Error;
    fn try_from(envelope: Envelope) -> anyhow::Result<Self> {
        let subj: String = envelope.subject().try_leaf()?.try_into()?;
        if subj != "FrostSignatureShare" {
            anyhow::bail!("unexpected subject: {}", subj);
        }
        let xid_env = envelope.object_for_predicate(HOLDER)?;
        let xid: XID = xid_env.try_leaf()?.try_into()?;
        let share_env = envelope.object_for_predicate("share")?;
        let share = share_env.try_leaf()?.try_byte_string()?.to_vec();
        Ok(FrostSignatureShare { xid, share })
    }
}

impl From<FrostSignatureShares> for Envelope {
    fn from(value: FrostSignatureShares) -> Self {
        let mut e = Envelope::new("FrostSignatureShares");
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
        let subj: String = envelope.subject().try_leaf()?.try_into()?;
        if subj != "FrostSignatureShares" {
            anyhow::bail!("unexpected subject: {}", subj);
        }
        let mut shares: Vec<FrostSignatureShare> = Vec::new();
        for assertion in envelope.assertions() {
            let pred_env = assertion.try_predicate()?;
            if let Ok(pred) = pred_env.try_leaf() {
                if let Ok(name) = <String as TryFrom<_>>::try_from(pred.clone())
                {
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
    use indoc::indoc;

    use super::*;

    #[test]
    fn frost_signing_commitment_roundtrip_text() {
        let xid = bc_components::XID::from_hex(
            "0000000000000000000000000000000000000000000000000000000000000000",
        );
        let commit = FrostSigningCommitment {
            xid,
            hiding: [0xA1; 33],
            binding: [0xB2; 33],
        };
        let env: Envelope = commit.clone().into();
        #[rustfmt::skip]
        let expected = (indoc! {r#"
            "FrostSigningCommitment" [
                "binding": Bytes(33)
                "hiding": Bytes(33)
                'holder': XID(00000000)
            ]
        "#}).trim();
        assert_eq!(env.format(), expected);
        let rt = FrostSigningCommitment::try_from(env).unwrap();
        assert_eq!(commit, rt);
    }

    #[test]
    fn frost_signing_package_roundtrip_text() {
        let xid1 = bc_components::XID::from_hex(
            "1111111111111111111111111111111111111111111111111111111111111111",
        );
        let xid2 = bc_components::XID::from_hex(
            "2222222222222222222222222222222222222222222222222222222222222222",
        );
        let c1 = FrostSigningCommitment {
            xid: xid1,
            hiding: [1; 33],
            binding: [2; 33],
        };
        let c2 = FrostSigningCommitment {
            xid: xid2,
            hiding: [3; 33],
            binding: [4; 33],
        };
        let pkg = FrostSigningPackage {
            message: vec![0xDE, 0xAD, 0xBE, 0xEF],
            commitments: vec![c1.clone(), c2.clone()],
        };
        let env: Envelope = pkg.clone().into();
        #[rustfmt::skip]
        let expected = (indoc! {r#"
            "FrostSigningPackage" [
                "commitment": "FrostSigningCommitment" [
                    "binding": Bytes(33)
                    "hiding": Bytes(33)
                    'holder': XID(11111111)
                ]
                "commitment": "FrostSigningCommitment" [
                    "binding": Bytes(33)
                    "hiding": Bytes(33)
                    'holder': XID(22222222)
                ]
                "message": Bytes(4)
            ]
        "#}).trim();
        assert_eq!(env.format(), expected);
        let rt = FrostSigningPackage::try_from(env).unwrap();
        assert_eq!(pkg, rt);
    }

    #[test]
    fn frost_signature_share_roundtrip_text() {
        let xid = bc_components::XID::from_hex(
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        );
        let share = FrostSignatureShare { xid, share: vec![0x55, 0x66, 0x77] };
        let env: Envelope = share.clone().into();
        #[rustfmt::skip]
        let expected = (indoc! {r#"
            "FrostSignatureShare" [
                "share": Bytes(3)
                'holder': XID(aaaaaaaa)
            ]
        "#}).trim();
        assert_eq!(env.format(), expected);
        let rt = FrostSignatureShare::try_from(env).unwrap();
        assert_eq!(share, rt);
    }

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
            "FrostSignatureShares" [
                "share": "FrostSignatureShare" [
                    "share": Bytes(2)
                    'holder': XID(bbbbbbbb)
                ]
                "share": "FrostSignatureShare" [
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
