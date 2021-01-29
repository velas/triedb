#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    DecoderError(#[from] rlp::DecoderError),
}
