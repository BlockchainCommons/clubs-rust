use bc_components::{ARID, Digest, SymmetricKey};
use bc_envelope::prelude::*;

use super::coordinator::CONTENT_MESSAGE_PREFIX;
use crate::{
    Error, Result,
    frost::{
        group::FrostGroup,
        pm::primitives::{DleqProof, point_from_bytes, vrf_verify_for_x},
    },
};

/// Final artefact of the content-key ceremony.
#[derive(Clone, Debug)]
pub struct FrostContentKey {
    pub session: ARID,
    pub digest: Digest,
    pub key: SymmetricKey,
    pub gamma_bytes: [u8; 33],
    pub proof: DleqProof,
}

impl FrostContentKey {
    pub fn verify(&self, group: &FrostGroup) -> Result<()> {
        let mut msg = Vec::with_capacity(
            CONTENT_MESSAGE_PREFIX.len() + self.digest.as_bytes().len(),
        );
        msg.extend_from_slice(CONTENT_MESSAGE_PREFIX);
        msg.extend_from_slice(self.digest.as_bytes());

        let h_point = crate::frost::pm::primitives::hash_to_curve(&msg)?;
        let gamma_point = point_from_bytes(&self.gamma_bytes)?;
        let x_point = group.verifying_key_point()?;
        vrf_verify_for_x(&x_point, &h_point, &gamma_point, &self.proof)?;
        Ok(())
    }
}

impl From<FrostContentKey> for Envelope {
    fn from(value: FrostContentKey) -> Self {
        let mut e = Envelope::new(known_values::UNIT);
        e = e.add_type("FrostContentKeyResult");
        e = e.add_assertion("session", value.session);
        e = e.add_assertion("digest", value.digest.clone());
        e = e.add_assertion(
            "gamma",
            CBOR::from(ByteString::from(value.gamma_bytes.to_vec())),
        );
        e = e.add_assertion(
            "key",
            CBOR::from(ByteString::from(value.key.as_bytes().to_vec())),
        );
        e = e.add_assertion("proof", Envelope::from(value.proof.clone()));
        e
    }
}

impl TryFrom<Envelope> for FrostContentKey {
    type Error = Error;

    fn try_from(envelope: Envelope) -> Result<Self> {
        envelope.check_type_envelope("FrostContentKeyResult")?;
        let subj_env = envelope.subject();
        let kv = subj_env.try_known_value()?;
        if kv.value() != known_values::UNIT.value() {
            return Err(Error::msg("unexpected subject for FrostContentKey"));
        }
        let session: ARID = envelope.try_object_for_predicate("session")?;
        let digest: Digest = envelope.try_object_for_predicate("digest")?;
        let gamma_bs: ByteString =
            envelope.try_object_for_predicate("gamma")?;
        let gamma_vec: Vec<u8> = gamma_bs.into();
        let gamma_bytes: [u8; 33] = gamma_vec
            .try_into()
            .map_err(|_| Error::msg("invalid gamma length"))?;
        let key_bs: ByteString = envelope.try_object_for_predicate("key")?;
        let key_vec: Vec<u8> = key_bs.into();
        let key = SymmetricKey::from_data_ref(&key_vec)
            .map_err(|e| Error::msg(e.to_string()))?;
        let proof_env = envelope.object_for_predicate("proof")?;
        let proof = DleqProof::try_from(proof_env)?;
        Ok(Self { session, digest, key, gamma_bytes, proof })
    }
}

#[cfg(test)]
mod tests {
    use k256::{ProjectivePoint, Scalar};

    use super::*;

    #[test]
    fn frost_content_key_roundtrip() {
        let session = ARID::from_hex(
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        );
        let digest = Digest::from_image(b"example");
        let key =
            SymmetricKey::from_data([0x11; SymmetricKey::SYMMETRIC_KEY_SIZE]);
        let gamma_point = ProjectivePoint::GENERATOR * Scalar::from(5u64);
        let proof = DleqProof {
            a_bytes: [0x22; 33],
            b_bytes: [0x33; 33],
            e: Scalar::from(7u64),
            z: Scalar::from(9u64),
        };
        let gamma_bytes =
            crate::frost::pm::primitives::point_bytes(&gamma_point).unwrap();
        let result = FrostContentKey {
            session,
            digest: digest.clone(),
            key,
            gamma_bytes,
            proof,
        };

        let env: Envelope = result.clone().into();
        let rt = FrostContentKey::try_from(env).unwrap();
        assert_eq!(rt.session, result.session);
        assert_eq!(rt.digest, result.digest);
        assert_eq!(rt.key, result.key);
        assert_eq!(rt.gamma_bytes, result.gamma_bytes);
        assert_eq!(rt.proof.a_bytes, result.proof.a_bytes);
        assert_eq!(rt.proof.b_bytes, result.proof.b_bytes);
        assert_eq!(rt.proof.e, result.proof.e);
        assert_eq!(rt.proof.z, result.proof.z);
    }
}
