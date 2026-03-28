use thiserror::Error as ThisError;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, ThisError)]
pub enum Error {
    #[error("serialization failed: {0}")]
    Serialization(String),
    #[error("deserialization failed: {0}")]
    Deserialization(String),
    #[error("cryptographic operation failed")]
    CryptoFailure,
    #[error("invalid relay message: {0}")]
    InvalidMessage(&'static str),
    #[error("replayed or out-of-order frame detected")]
    ReplayDetected,
    #[error("pairing URI is invalid")]
    InvalidPairingUri,
}
