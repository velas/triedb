use crate::ops::diff::verify::VerificationError;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    DecoderError(#[from] rlp::DecoderError),
    #[error(transparent)]
    VerificationError(#[from] VerificationError),
}
