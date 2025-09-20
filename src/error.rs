use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    /// Frost Error
    #[error("frost error: {0}")]
    Core(#[from] frost_secp256k1_tr::Error),

    /// ProvenanceMark Error
    #[error("provenance mark error: {0}")]
    ProvenanceMark(#[from] provenance_mark::Error),

    /// Envelope Error
    #[error("envelope error: {0}")]
    Envelope(#[from] bc_envelope::Error),

    /// General error
    #[error("general error: {0}")]
    General(String),
}

impl Error {
    pub fn msg(msg: impl Into<String>) -> Self { Error::General(msg.into()) }
}

pub type Result<T> = std::result::Result<T, Error>;
