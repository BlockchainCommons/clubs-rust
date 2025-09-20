use std::collections::{BTreeMap, BTreeSet};

use bc_components::{ARID, XID};
use k256::{ProjectivePoint, Scalar};

use crate::frost::{
    group::FrostGroup,
    pm::{
        commitment::FrostPmCommitment,
        gamma_share::FrostPmGammaShare,
        primitives::{dleq_challenge, point_bytes},
        response_share::FrostPmResponseShare,
        signing_package::FrostPmSigningPackage,
        DleqProof,
    },
};
use crate::{Error, Result};

pub struct FrostPmCoordinator {
    group: FrostGroup,
    session_id: ARID,
    commitments: BTreeMap<XID, FrostPmCommitment>,
    roster: Option<Vec<XID>>,
    lambda_factors: Option<BTreeMap<XID, Scalar>>,
    gamma_shares: BTreeMap<XID, ProjectivePoint>,
    responses: BTreeMap<XID, Scalar>,
    aggregated_a: Option<ProjectivePoint>,
    aggregated_b: Option<ProjectivePoint>,
    aggregated_gamma: Option<ProjectivePoint>,
    challenge: Option<Scalar>,
}

impl FrostPmCoordinator {
    pub fn new(group: FrostGroup) -> Self {
        Self {
            group,
            session_id: ARID::new(),
            commitments: BTreeMap::new(),
            roster: None,
            lambda_factors: None,
            gamma_shares: BTreeMap::new(),
            responses: BTreeMap::new(),
            aggregated_a: None,
            aggregated_b: None,
            aggregated_gamma: None,
            challenge: None,
        }
    }

    pub fn group(&self) -> &FrostGroup {
        &self.group
    }

    pub fn session_id(&self) -> ARID {
        self.session_id
    }

    pub fn set_session_id(&mut self, session: ARID) {
        self.session_id = session;
    }

    pub fn start_session(&mut self) {
        self.session_id = ARID::new();
        self.commitments.clear();
        self.roster = None;
        self.lambda_factors = None;
        self.gamma_shares.clear();
        self.responses.clear();
        self.aggregated_a = None;
        self.aggregated_b = None;
        self.aggregated_gamma = None;
        self.challenge = None;
    }

    pub fn add_commitment(
        &mut self,
        commitment: FrostPmCommitment,
    ) -> Result<()> {
        if commitment.session != self.session_id {
            return Err(Error::msg("commitment has wrong session"));
        }
        if !self.group.members.contains(&commitment.xid) {
            return Err(Error::msg("commitment from non-member"));
        }
        match self.commitments.get(&commitment.xid) {
            None => {
                self.commitments.insert(commitment.xid, commitment);
            }
            Some(existing) => {
                if existing != &commitment {
                    return Err(Error::msg(
                        "conflicting commitment for participant",
                    ));
                }
            }
        }
        Ok(())
    }

    pub fn signing_package_for(
        &mut self,
        roster: &[XID],
        h_point: &ProjectivePoint,
    ) -> Result<FrostPmSigningPackage> {
        let roster_set: BTreeSet<XID> = roster.iter().copied().collect();
        if roster_set.len() != roster.len() {
            return Err(Error::msg("duplicate members in roster"));
        }
        for xid in &roster_set {
            if !self.group.members.contains(xid) {
                return Err(Error::msg("roster contains non-member"));
            }
            if !self.commitments.contains_key(xid) {
                return Err(Error::msg("missing commitment for roster member"));
            }
        }
        let lambda_factors = self.group.lagrange_coefficients(roster)?;

        self.roster = Some(roster.to_vec());
        self.lambda_factors = Some(lambda_factors.clone());
        self.gamma_shares.clear();
        self.responses.clear();
        self.aggregated_a = None;
        self.aggregated_b = None;
        self.aggregated_gamma = None;
        self.challenge = None;

        Ok(FrostPmSigningPackage {
            session: self.session_id,
            h_point: *h_point,
            lambda_factors,
        })
    }

    pub fn record_gamma_share(
        &mut self,
        share: FrostPmGammaShare,
    ) -> Result<()> {
        if share.session != self.session_id {
            return Err(Error::msg("gamma share has wrong session"));
        }
        let roster = self
            .roster
            .as_ref()
            .ok_or_else(|| Error::msg("signing package not yet prepared"))?;
        if !roster.contains(&share.xid) {
            return Err(Error::msg("gamma share from non-selected member"));
        }
        let point = share.to_point()?;
        match self.gamma_shares.get(&share.xid) {
            None => {
                self.gamma_shares.insert(share.xid, point);
            }
            Some(existing) => {
                if existing != &point {
                    return Err(Error::msg("conflicting gamma share"));
                }
            }
        }
        Ok(())
    }

    fn aggregated_values(
        &mut self,
    ) -> Result<(
        ProjectivePoint,
        ProjectivePoint,
        ProjectivePoint,
        ProjectivePoint,
    )> {
        if let (Some(a), Some(b), Some(gamma)) =
            (self.aggregated_a, self.aggregated_b, self.aggregated_gamma)
        {
            let x_point = self.group.verifying_key_point()?;
            return Ok((x_point, a, b, gamma));
        }

        let roster = self
            .roster
            .as_ref()
            .ok_or_else(|| Error::msg("signing package not yet prepared"))?;
        let _lambda_factors = self
            .lambda_factors
            .as_ref()
            .ok_or_else(|| Error::msg("lambda factors missing"))?;
        if self.gamma_shares.len() != roster.len() {
            return Err(Error::msg("gamma shares incomplete"));
        }

        let mut aggregated_a = ProjectivePoint::IDENTITY;
        let mut aggregated_b = ProjectivePoint::IDENTITY;
        for xid in roster {
            let commitment = self.commitments.get(xid).ok_or_else(|| {
                Error::msg("missing commitment for participant")
            })?;
            let a_i = commitment.g_point()?;
            let b_i = commitment.h_point()?;
            aggregated_a += a_i;
            aggregated_b += b_i;
        }

        let mut aggregated_gamma = ProjectivePoint::IDENTITY;
        for xid in roster {
            let gamma = self
                .gamma_shares
                .get(xid)
                .ok_or_else(|| Error::msg("gamma share missing"))?;
            aggregated_gamma += *gamma;
        }

        // Store for reuse.
        self.aggregated_a = Some(aggregated_a);
        self.aggregated_b = Some(aggregated_b);
        self.aggregated_gamma = Some(aggregated_gamma);
        let x_point = self.group.verifying_key_point()?;
        Ok((x_point, aggregated_a, aggregated_b, aggregated_gamma))
    }

    pub fn challenge(&mut self) -> Result<Scalar> {
        if let Some(challenge) = self.challenge {
            return Ok(challenge);
        }
        let (x_point, a, b, gamma) = self.aggregated_values()?;
        let challenge = dleq_challenge(&x_point, &gamma, &a, &b)?;
        self.challenge = Some(challenge);
        Ok(challenge)
    }

    pub fn record_response(
        &mut self,
        response: FrostPmResponseShare,
    ) -> Result<()> {
        if response.session != self.session_id {
            return Err(Error::msg("response share has wrong session"));
        }
        let roster = self
            .roster
            .as_ref()
            .ok_or_else(|| Error::msg("signing package not yet prepared"))?;
        if !roster.contains(&response.xid) {
            return Err(Error::msg("response share from non-selected member"));
        }
        let scalar = response.to_scalar()?;
        match self.responses.get(&response.xid) {
            None => {
                self.responses.insert(response.xid, scalar);
            }
            Some(existing) => {
                if *existing != scalar {
                    return Err(Error::msg("conflicting response share"));
                }
            }
        }
        Ok(())
    }

    pub fn finalize(&mut self) -> Result<(ProjectivePoint, DleqProof)> {
        let roster_ids =
            self.roster.as_ref().cloned().ok_or_else(|| {
                Error::msg("signing package not yet prepared")
            })?;
        if self.responses.len() != roster_ids.len() {
            return Err(Error::msg("insufficient response shares"));
        }

        let challenge = self.challenge()?;
        let (_x_point, a, b, gamma) = self.aggregated_values()?;

        let mut z_total = Scalar::ZERO;
        for xid in &roster_ids {
            let share = self
                .responses
                .get(xid)
                .ok_or_else(|| Error::msg("missing response share"))?;
            z_total += *share;
        }

        let a_bytes = point_bytes(&a)?;
        let b_bytes = point_bytes(&b)?;

        let proof = DleqProof { a_bytes, b_bytes, e: challenge, z: z_total };
        Ok((gamma, proof))
    }
}
