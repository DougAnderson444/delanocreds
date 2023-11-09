use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    // Credential Signature is not valid for the new Nym
    #[error("Invalid Signature")]
    InvalidSignature(String),
    // Change Relations Failed
    #[error("Change Relations Failed")]
    ChangeRelationsFailed(String),

    /// Failed to accept a [Credential] offer]
    #[error("Failed to accept a Credential offer")]
    AcceptOfferFailed(String),

    /// Failed to create a [Credential] offer
    #[error("Failed to use their Verification Key(expected {expected:?}, found {found:?})")]
    InvalidVerificationKey { expected: String, found: String },

    /// IssuerError
    #[error("IssuerError: {0}")]
    IssuerError(#[from] crate::keypair::IssuerError),

    /// Proof is not valid, did not pass verify_proof function
    #[error("Proof is not valid, did not pass verify_proof function")]
    InvalidProof,

    /// Tried to convert bytes into an [Attribute], but failed
    /// from cid::eror
    #[error("Tried to convert bytes into an Attribute, but failed")]
    InvalidAttribute(#[from] cid::Error),

    /// Tried to convert bytes into a Scalar and it failed
    #[error("Tried to convert bytes into a Scalar and it failed")]
    InvalidScalar,
}
