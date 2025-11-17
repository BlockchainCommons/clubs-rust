use std::collections::BTreeMap;

use bc_components::{ARID, XID};
use bc_envelope::prelude::*;
use k256::{ProjectivePoint, Scalar};
use known_values::HOLDER;

use crate::{
    Error, Result,
    frost::pm::{
        point_bytes, point_from_bytes, scalar_from_be_bytes, scalar_to_be_bytes,
    },
};

/// Signing package distributed by the coordinator prior to computing VRF
/// shares.
#[derive(Clone, Debug)]
pub struct FrostPmSigningPackage {
    pub session: ARID,
    pub h_point: ProjectivePoint,
    pub lambda_factors: BTreeMap<XID, Scalar>,
}

impl FrostPmSigningPackage {
    pub fn lambda_for(&self, xid: &XID) -> Option<Scalar> {
        self.lambda_factors.get(xid).copied()
    }

    pub fn roster(&self) -> impl Iterator<Item = (&XID, &Scalar)> {
        self.lambda_factors.iter()
    }
}

impl From<FrostPmSigningPackage> for Envelope {
    fn from(value: FrostPmSigningPackage) -> Self {
        let mut e = Envelope::new(known_values::UNIT);
        e = e.add_type("FrostPmSigningPackage");
        e = e.add_assertion("session", value.session);
        let h_bytes = point_bytes(&value.h_point)
            .expect("valid projective point for FrostPmSigningPackage");
        e = e.add_assertion(
            "hPoint",
            CBOR::from(ByteString::from(h_bytes.to_vec())),
        );
        for (xid, lambda) in value.lambda_factors {
            let mut lam_env = Envelope::new(known_values::UNIT);
            lam_env = lam_env.add_type("FrostPmLambdaFactor");
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

impl TryFrom<Envelope> for FrostPmSigningPackage {
    type Error = Error;

    fn try_from(envelope: Envelope) -> Result<Self> {
        envelope.check_type_envelope("FrostPmSigningPackage")?;
        let subj_env = envelope.subject();
        let kv = subj_env.try_known_value()?;
        if kv.value() != known_values::UNIT.value() {
            return Err(Error::msg(
                "unexpected subject for FrostPmSigningPackage",
            ));
        }
        let session: ARID = envelope.try_object_for_predicate("session")?;
        let h_bs: ByteString = envelope.try_object_for_predicate("hPoint")?;
        let h_vec: Vec<u8> = h_bs.into();
        let h_arr: [u8; 33] = h_vec
            .try_into()
            .map_err(|_| Error::msg("invalid hPoint length"))?;
        let h_point = point_from_bytes(&h_arr)?;
        let mut lambda_factors: BTreeMap<XID, Scalar> = BTreeMap::new();
        for assertion in envelope.assertions() {
            let pred_env = assertion.try_predicate()?;
            if let Ok(pred) = pred_env.try_leaf()
                && let Ok(name) = <String as TryFrom<_>>::try_from(pred.clone())
                && name == "lambda"
            {
                let obj_env = assertion.try_object()?;
                obj_env.check_type_envelope("FrostPmLambdaFactor")?;
                let obj_subj = obj_env.subject();
                let obj_kv = obj_subj.try_known_value()?;
                if obj_kv.value() != known_values::UNIT.value() {
                    return Err(Error::msg(
                        "unexpected subject for FrostPmLambdaFactor",
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
        Ok(Self { session, h_point, lambda_factors })
    }
}

#[cfg(test)]
mod tests {
    use indoc::indoc;
    use k256::Scalar;

    use super::*;

    #[test]
    fn frost_pm_signing_package_roundtrip_text() {
        let session = ARID::from_hex(
            "5555555555555555555555555555555555555555555555555555555555555555",
        );
        let xid1 = XID::from_hex(
            "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
        );
        let xid2 = XID::from_hex(
            "fedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321",
        );
        let mut lambda_factors = BTreeMap::new();
        lambda_factors.insert(xid1, Scalar::from(5u64));
        lambda_factors.insert(xid2, Scalar::from(7u64));
        let h_point = ProjectivePoint::GENERATOR * Scalar::from(42u64);
        let package =
            FrostPmSigningPackage { session, h_point, lambda_factors };
        let env: Envelope = package.clone().into();
        #[rustfmt::skip]
        let expected = (indoc! {r#"
            '' [
                'isA': "FrostPmSigningPackage"
                "hPoint": Bytes(33)
                "lambda": '' [
                    'isA': "FrostPmLambdaFactor"
                    "scalar": Bytes(32)
                    'holder': XID(12345678)
                ]
                "lambda": '' [
                    'isA': "FrostPmLambdaFactor"
                    "scalar": Bytes(32)
                    'holder': XID(fedcba09)
                ]
                "session": ARID(55555555)
            ]
        "#}).trim();
        assert_eq!(env.format(), expected);
        let rt = FrostPmSigningPackage::try_from(env).unwrap();
        assert_eq!(rt.session, package.session);
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
