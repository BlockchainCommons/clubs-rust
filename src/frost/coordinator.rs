use std::collections::{BTreeMap, BTreeSet};

use crate::{Error, Result};
use bc_components::{ARID, XID};
use bc_envelope::prelude::*;

use super::aggregate::aggregate_and_attach_signature;
use super::group::FrostGroup;
use super::signing::{
    FrostSignatureShare, FrostSignatureShares, FrostSigningCommitment,
    FrostSigningPackage, build_signing_package,
};

/// A neutral coordinator for a FROST signing ceremony.
///
/// Holds the `FrostGroup`, collects Round-1 commitments for a specific
/// message `Envelope`, constructs the signing package, collects Round-2
/// signature shares, then aggregates the final signature and returns the
/// signed `Envelope`.
pub struct FrostCoordinator {
    group: FrostGroup,
    message: Option<Envelope>,
    // Track per-member commitments and shares for idempotency and conflict detection
    commitments: BTreeMap<XID, FrostSigningCommitment>,
    shares: BTreeMap<XID, FrostSignatureShare>,
    // The signing package prepared for this ceremony (selected roster)
    package: Option<FrostSigningPackage>,
    // Session identifier for this ceremony
    session_id: ARID,
    // Members who have explicitly consented to sign after viewing the message
    consent: BTreeSet<XID>,
}

impl FrostCoordinator {
    pub fn new(group: FrostGroup) -> Self {
        Self {
            group,
            message: None,
            commitments: BTreeMap::new(),
            shares: BTreeMap::new(),
            package: None,
            session_id: ARID::new(),
            consent: BTreeSet::new(),
        }
    }

    pub fn group(&self) -> &FrostGroup {
        &self.group
    }
    pub fn session_id(&self) -> ARID {
        self.session_id
    }
    pub fn set_session_id(&mut self, session_id: ARID) {
        self.session_id = session_id;
    }

    /// Set or replace the message to be signed (typically a wrapped Envelope).
    pub fn set_message(&mut self, message: Envelope) {
        self.message = Some(message);
    }

    /// Add a Round-1 commitment from a participant.
    pub fn add_commitment(&mut self, c: FrostSigningCommitment) -> Result<()> {
        // Ensure the commitment belongs to a group member
        if !self.group.members.contains(&c.xid) {
            return Err(Error::msg(format!(
                "commitment from non-member: {}",
                c.xid
            )));
        }
        if c.session != self.session_id {
            return Err(Error::msg(format!(
                "commitment has wrong session for member {}",
                c.xid
            )));
        }
        match self.commitments.get(&c.xid) {
            None => {
                self.commitments.insert(c.xid, c);
            }
            Some(existing) => {
                if existing != &c {
                    return Err(Error::msg(format!(
                        "conflicting commitment received from member {}",
                        c.xid
                    )));
                }
                // else identical: idempotent
            }
        }
        Ok(())
    }

    /// Build the signing package for distribution to participants.
    /// Uses ALL collected commitments. Stores the package for finalize().
    pub fn signing_package(&mut self) -> Result<FrostSigningPackage> {
        let msg = self
            .message
            .as_ref()
            .ok_or_else(|| Error::msg("message not set in coordinator"))?;
        let pkg = build_signing_package(
            &self.session_id,
            msg,
            self.commitments.values().cloned().collect(),
        );
        self.package = Some(pkg.clone());
        Ok(pkg)
    }

    /// Build the signing package using only the specified roster of members.
    /// This allows collecting commitments from all members, while selecting a
    /// subset (>= threshold) for this ceremony. Stores the package for finalize().
    pub fn signing_package_for(
        &mut self,
        roster: &[XID],
    ) -> Result<FrostSigningPackage> {
        if roster.len() < self.group.threshold {
            return Err(Error::msg(format!(
                "roster smaller than threshold: {}/{}",
                roster.len(),
                self.group.threshold
            )));
        }
        let msg = self
            .message
            .as_ref()
            .ok_or_else(|| Error::msg("message not set in coordinator"))?;
        let mut selected: Vec<FrostSigningCommitment> =
            Vec::with_capacity(roster.len());
        for xid in roster {
            if !self.consent.contains(xid) {
                return Err(Error::msg(format!(
                    "roster includes non-consenting member {}",
                    xid
                )));
            }
            let c = self.commitments.get(xid).ok_or_else(|| {
                Error::msg(format!("missing commitment for member {}", xid))
            })?;
            selected.push(c.clone());
        }
        let pkg = build_signing_package(&self.session_id, msg, selected);
        self.package = Some(pkg.clone());
        Ok(pkg)
    }

    /// Build a signing package using all consenting members (who also provided commitments).
    pub fn signing_package_from_consent(
        &mut self,
    ) -> Result<FrostSigningPackage> {
        if self.consent.len() < self.group.threshold {
            return Err(Error::msg(format!(
                "consenting roster smaller than threshold: {}/{}",
                self.consent.len(),
                self.group.threshold
            )));
        }
        let roster: Vec<XID> = self.consent.iter().cloned().collect();
        self.signing_package_for(&roster)
    }

    /// Add a Round-2 signature share from a participant that consents to sign.
    pub fn add_share(&mut self, s: FrostSignatureShare) -> Result<()> {
        // Validate member
        if !self.group.members.contains(&s.xid) {
            return Err(Error::msg(format!(
                "share from non-member: {}",
                s.xid
            )));
        }
        if s.session != self.session_id {
            return Err(Error::msg(format!(
                "share has wrong session for member {}",
                s.xid
            )));
        }
        match self.shares.get(&s.xid) {
            None => {
                self.shares.insert(s.xid, s);
            }
            Some(existing) => {
                if existing != &s {
                    return Err(Error::msg(format!(
                        "conflicting signature share received from member {}",
                        s.xid
                    )));
                }
                // else identical: idempotent
            }
        }
        Ok(())
    }

    /// Aggregate the shares into a final signature attached to the message.
    pub fn finalize(self) -> Result<Envelope> {
        let msg = self
            .message
            .ok_or_else(|| Error::msg("message not set in coordinator"))?;
        let pkg = match self.package.clone() {
            Some(p) => p,
            None => FrostSigningPackage {
                session: self.session_id,
                message: msg.clone(),
                commitments: self.commitments.clone().into_values().collect(),
            },
        };
        let shares = FrostSignatureShares::new(
            self.session_id,
            self.shares.into_values().collect(),
        );
        aggregate_and_attach_signature(&msg, &self.group, &pkg, &shares)
    }

    /// Record explicit consent from a member after viewing the message.
    pub fn record_consent(&mut self, xid: XID) -> Result<()> {
        if !self.group.members.contains(&xid) {
            return Err(Error::msg(format!(
                "consent from non-member: {}",
                xid
            )));
        }
        self.consent.insert(xid);
        Ok(())
    }
}
