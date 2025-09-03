use std::collections::BTreeMap;

use anyhow::{anyhow, Result};
use bc_envelope::prelude::*;

use super::aggregate::aggregate_and_attach_signature;
use super::group::FrostGroup;
use super::signing::{
    build_signing_package, FrostSignatureShare, FrostSignatureShares,
    FrostSigningCommitment, FrostSigningPackage,
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
    commitments: BTreeMap<bc_components::XID, FrostSigningCommitment>,
    shares: BTreeMap<bc_components::XID, FrostSignatureShare>,
}

impl FrostCoordinator {
    pub fn new(group: FrostGroup) -> Self {
        Self { group, message: None, commitments: BTreeMap::new(), shares: BTreeMap::new() }
    }

    pub fn group(&self) -> &FrostGroup { &self.group }

    /// Set or replace the message to be signed (typically a wrapped Envelope).
    pub fn set_message(&mut self, message: Envelope) { self.message = Some(message); }

    /// Add a Round-1 commitment from a participant.
    pub fn add_commitment(&mut self, c: FrostSigningCommitment) -> Result<()> {
        // Ensure the commitment belongs to a group member
        if !self.group.members.contains(&c.xid) {
            return Err(anyhow!("commitment from non-member: {}", c.xid));
        }
        match self.commitments.get(&c.xid) {
            None => {
                self.commitments.insert(c.xid, c);
            }
            Some(existing) => {
                if existing != &c {
                    return Err(anyhow!(
                        "conflicting commitment received from member {}",
                        c.xid
                    ));
                }
                // else identical: idempotent
            }
        }
        Ok(())
    }

    /// Build the signing package for distribution to the selected roster.
    pub fn signing_package(&self) -> Result<FrostSigningPackage> {
        let msg = self
            .message
            .as_ref()
            .ok_or_else(|| anyhow!("message not set in coordinator"))?;
        Ok(build_signing_package(
            msg,
            self.commitments.values().cloned().collect(),
        ))
    }

    /// Add a Round-2 signature share from a participant that consents to sign.
    pub fn add_share(&mut self, s: FrostSignatureShare) -> Result<()> {
        // Validate member
        if !self.group.members.contains(&s.xid) {
            return Err(anyhow!("share from non-member: {}", s.xid));
        }
        match self.shares.get(&s.xid) {
            None => {
                self.shares.insert(s.xid, s);
            }
            Some(existing) => {
                if existing != &s {
                    return Err(anyhow!(
                        "conflicting signature share received from member {}",
                        s.xid
                    ));
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
            .ok_or_else(|| anyhow!("message not set in coordinator"))?;
        let pkg = FrostSigningPackage {
            message: msg.clone(),
            commitments: self.commitments.into_values().collect(),
        };
        let shares = FrostSignatureShares::new(self.shares.into_values().collect());
        aggregate_and_attach_signature(&msg, &self.group, &pkg, &shares)
    }
}
