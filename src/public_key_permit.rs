use bc_components::{PublicKeys, SealedMessage, XID};

/// A public-key permit designating an intended reader and optional annotation.
///
/// The `recipient` receives the wrapped content key for this edition.
#[derive(Clone, Debug, PartialEq)]
pub enum PublicKeyPermit {
    /// Encode variant: used when creating a new edition.
    Encode {
        recipient: PublicKeys,
        member_xid: Option<XID>,
    },
    /// Decode variant: used when round-tripping from an existing envelope.
    Decode {
        sealed: SealedMessage,
        member_xid: Option<XID>,
    },
}

impl PublicKeyPermit {
    pub fn new(recipient: PublicKeys) -> Self {
        PublicKeyPermit::Encode { recipient, member_xid: None }
    }

    pub fn with_member_xid(self, member_xid: XID) -> Self {
        match self {
            PublicKeyPermit::Encode { recipient, .. } => {
                PublicKeyPermit::Encode {
                    recipient,
                    member_xid: Some(member_xid),
                }
            }
            PublicKeyPermit::Decode { sealed, .. } => {
                PublicKeyPermit::Decode { sealed, member_xid: Some(member_xid) }
            }
        }
    }

    /// Build a permit for a recipient with optional member XID annotation.
    pub fn for_member(member_xid: XID, public_keys: &PublicKeys) -> Self {
        Self::new(public_keys.clone()).with_member_xid(member_xid)
    }

    /// Build a permit for a recipient without annotation.
    pub fn for_recipient(public_keys: &PublicKeys) -> Self {
        Self::new(public_keys.clone())
    }
}
