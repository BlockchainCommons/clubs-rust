use std::collections::BTreeMap;

use bc_components::{ARID, Digest, XID};
use bc_envelope::prelude::*;
use k256::{ProjectivePoint, Scalar};
use known_values::HOLDER;

use crate::{
    Error, Result,
    frost::pm::{
        point_bytes, point_from_bytes, scalar_from_be_bytes, scalar_to_be_bytes,
    },
};

/// Signing package distributed by the coordinator for the content-key ceremony.
#[derive(Clone, Debug)]
pub struct FrostContentSigningPackage {
    pub session: ARID,
    pub digest: Digest,
    pub h_point: ProjectivePoint,
    pub lambda_factors: BTreeMap<XID, Scalar>,
}

impl FrostContentSigningPackage {
    pub fn lambda_for(&self, xid: &XID) -> Option<Scalar> {
        self.lambda_factors.get(xid).copied()
    }

    pub fn roster(&self) -> impl Iterator<Item = (&XID, &Scalar)> {
        self.lambda_factors.iter()
    }
}

impl From<FrostContentSigningPackage> for Envelope {
    fn from(value: FrostContentSigningPackage) -> Self {
        let mut e = Envelope::new(known_values::UNIT);
        e = e.add_type("FrostContentSigningPackage");
        e = e.add_assertion("session", value.session);
        e = e.add_assertion("digest", value.digest);
        let h_bytes = point_bytes(&value.h_point)
            .expect("valid projective point for FrostContentSigningPackage");
        e = e.add_assertion(
            "hPoint",
            CBOR::from(ByteString::from(h_bytes.to_vec())),
        );
        for (xid, lambda) in value.lambda_factors {
            let mut lam_env = Envelope::new(known_values::UNIT);
            lam_env = lam_env.add_type("FrostContentLambdaFactor");
            lam_env = lam_env.add_assertion(HOLDER, xid);
            lam_env = lam_env.add_assertion(
                "scalar",
                CBOR::from(ByteString::from(
                    scalar_to_be_bytes(&lambda).to_vec(),
                )),
            );
            let assertion = Envelope::new_assertion("lambda", lam_env);
            e = e.add_assertion_envelope(assertion).unwrap();
        }
        e
    }
}

impl TryFrom<Envelope> for FrostContentSigningPackage {
    type Error = Error;

    fn try_from(envelope: Envelope) -> Result<Self> {
        envelope.check_type("FrostContentSigningPackage")?;
        let subj_env = envelope.subject();
        let kv = subj_env.try_known_value()?;
        if kv.value() != known_values::UNIT.value() {
            return Err(Error::msg(
                "unexpected subject for FrostContentSigningPackage",
            ));
        }
        let session: ARID = envelope.try_object_for_predicate("session")?;
        let digest: Digest = envelope.try_object_for_predicate("digest")?;
        let h_bs: ByteString = envelope.try_object_for_predicate("hPoint")?;
        let h_vec: Vec<u8> = h_bs.into();
        let h_arr: [u8; 33] = h_vec
            .try_into()
            .map_err(|_| Error::msg("invalid hPoint length"))?;
        let h_point = point_from_bytes(&h_arr)?;
        let mut lambda_factors: BTreeMap<XID, Scalar> = BTreeMap::new();
        for assertion in envelope.assertions() {
            let pred_env = assertion.try_predicate()?;
            if let Ok(pred_leaf) = pred_env.try_leaf()
                && let Ok(name) =
                    <String as TryFrom<_>>::try_from(pred_leaf.clone())
                && name == "lambda"
            {
                let obj_env = assertion.try_object()?;
                obj_env.check_type("FrostContentLambdaFactor")?;
                let obj_subj = obj_env.subject();
                let obj_kv = obj_subj.try_known_value()?;
                if obj_kv.value() != known_values::UNIT.value() {
                    return Err(Error::msg(
                        "unexpected subject for FrostContentLambdaFactor",
                    ));
                }
                let xid: XID = obj_env.try_object_for_predicate(HOLDER)?;
                let scalar_bs: ByteString =
                    obj_env.try_object_for_predicate("scalar")?;
                let scalar_vec: Vec<u8> = scalar_bs.into();
                let scalar_arr: [u8; 32] = scalar_vec
                    .try_into()
                    .map_err(|_| Error::msg("invalid scalar length"))?;
                let scalar = scalar_from_be_bytes(&scalar_arr)?;
                lambda_factors.insert(xid, scalar);
            }
        }
        Ok(Self { session, digest, h_point, lambda_factors })
    }
}

#[cfg(test)]
mod tests {
    use indoc::indoc;
    use k256::Scalar;

    use super::*;

    #[test]
    fn frost_content_signing_package_roundtrip() {
        let session = ARID::from_hex(
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        );
        let digest = Digest::from_image(b"example");
        let xid1 = XID::from_hex(
            "1111111111111111111111111111111111111111111111111111111111111111",
        );
        let xid2 = XID::from_hex(
            "2222222222222222222222222222222222222222222222222222222222222222",
        );
        let mut lambda_factors = BTreeMap::new();
        lambda_factors.insert(xid1, Scalar::from(5u64));
        lambda_factors.insert(xid2, Scalar::from(7u64));
        let h_point = ProjectivePoint::GENERATOR * Scalar::from(42u64);

        let package = FrostContentSigningPackage {
            session,
            digest,
            h_point,
            lambda_factors,
        };
        let env: Envelope = package.clone().into();
        #[rustfmt::skip]
        let expected = (indoc! {r#"
            '' [
                'isA': "FrostContentSigningPackage"
                "digest": Digest(50d858e0)
                "hPoint": Bytes(33)
                "lambda": '' [
                    'isA': "FrostContentLambdaFactor"
                    "scalar": Bytes(32)
                    'holder': XID(11111111)
                ]
                "lambda": '' [
                    'isA': "FrostContentLambdaFactor"
                    "scalar": Bytes(32)
                    'holder': XID(22222222)
                ]
                "session": ARID(aaaaaaaa)
            ]
        "#}).trim();
        assert_eq!(env.format(), expected);

        let rt = FrostContentSigningPackage::try_from(env).unwrap();
        assert_eq!(rt.session, package.session);
        assert_eq!(rt.digest, package.digest);
        let exp_h = point_bytes(&package.h_point).unwrap();
        let act_h = point_bytes(&rt.h_point).unwrap();
        assert_eq!(exp_h, act_h);
        assert_eq!(package.lambda_factors.len(), rt.lambda_factors.len());
        for (xid, scalar) in package.lambda_factors.iter() {
            let rt_scalar = rt.lambda_for(xid).unwrap();
            assert_eq!(
                scalar_to_be_bytes(scalar),
                scalar_to_be_bytes(&rt_scalar)
            );
        }
    }
}
