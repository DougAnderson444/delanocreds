use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    // Credential Signature is not valid for the new Nym
    #[error("Invalid Signature")]
    InvalidSignature(String),
    // Change Relations Failed
    #[error("Change Relations Failed")]
    ChangeRelationsFailed(String),
}
