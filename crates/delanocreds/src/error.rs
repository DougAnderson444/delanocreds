use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    // Credential Signature is not valid for the new Nym
    #[error("Invalid Signature {0}")]
    InvalidSignature(String),
    // Change Relations Failed
    #[error("Change Relations Failed, {0}")]
    ChangeRelationsFailed(String),

    /// Failed to accept a [Credential] offer]
    #[error("Failed to accept a Credential offer {0}")]
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

    #[error("Tried to apply CBOR coded, but failed {0}")]
    CBORError(String),

    /// From base64::DecodeError
    #[error("From base64::DecodeError")]
    Base64DecodeError(#[from] base64::DecodeError),

    #[error("The given Nonce bytes were not convertable to Scalar")]
    NonceConversionError,

    /// from serde_json::Error
    #[error("Error converting Credential")]
    CredentialConversionError(#[from] serde_json::Error),
}
