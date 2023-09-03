// We need async traits because the user is likely to have to approve wallet functions and we don't want to block the main thread
#![feature(async_fn_in_trait)]
#![allow(incomplete_features)]

pub mod basic;
mod seed;
pub mod types;

pub(crate) use secrecy::Secret;
pub use seed::Seed;
use std::marker::Sized;
use types::FieldElem;

// Migration Task:
// Anywhere in delanocreds where there is `expose_secret()` needs to be moved here as a trait
// and then implemented for the type that is being exposed.
// default implementation should be to just return the value in the same way that delanocreds does currently

/// Implement this trait to create a secrets manager for use in [delanocreds]
/// All you need to create a secrets managers instance is a seed.
/// This seed will then be used to derive the secret and public keys, plus any
/// deterministic hierarchical keys that are required.
///
/// This trait has a default implementation that returns the value with no approvals
/// or checks. You may want to override this default implementation to add approvals
/// so that the secrets are not used by the application without the user's consent.
pub trait DelanocredsSecrets {
    // Associated Types
    // type Secret;
    type Public;
    type Error;

    fn new(sk: Secret<Vec<FieldElem>>) -> Self
    where
        Self: Sized;

    /// Creates a SecretsManager from a given 32-byte seed
    fn from_seed(seed: Seed) -> Result<Self, Self::Error>
    where
        Self: Sized;

    /// Returns the verification key
    fn public(&self) -> Result<Self::Public, Self::Error>;

    // Creates Verification Key [delanocreds::VK] given generators for G1 and G2
}

#[cfg(test)]
mod tests {

    #[test]
    fn it_works() {}
}
