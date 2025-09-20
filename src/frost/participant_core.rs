use bc_components::XID;
use frost_secp256k1_tr as frost;

#[derive(Clone)]
pub struct FrostParticipantCore {
    xid: XID,
    key_package: frost::keys::KeyPackage,
}

impl FrostParticipantCore {
    pub fn new(xid: XID, key_package: frost::keys::KeyPackage) -> Self {
        Self { xid, key_package }
    }

    pub fn xid(&self) -> XID { self.xid }

    pub fn key_package(&self) -> &frost::keys::KeyPackage { &self.key_package }

    pub fn into_inner(self) -> (XID, frost::keys::KeyPackage) {
        (self.xid, self.key_package)
    }
}
