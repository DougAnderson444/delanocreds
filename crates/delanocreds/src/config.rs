//! Configuration of the Root Issuer and the Credential Issuer.
//!
//! ## Root Issuer
//!
//! The Root Issuer is the entity that issues the root credential. It is the
//! entity that is trusted by the verifier to issue the root credential. The
//! root credential is used to issue the credential schema and the credential
//! definition.
//!
//! ### Root Issuer Configuration
//!
//! To make a root issuer, you need to create a `RootIssuerConfig` struct. This
//! struct contains the following fields:
//!
//! - `name`: The name of the root issuer.
//!
//! ## Credential Issuer
//!
//!

/// Default Max Attributes: The maximum number of attribute entries allowed in a credential.
pub const DEFAULT_MAX_ENTRIES: usize = 6;
/// Default Max Cardinality: The maximum number of total attribute elements allowed in a credential. The Default os 12 is chosen as it is the maximum number tha will fit into an Issuer QR Code.
pub const DEFAULT_MAX_CARDINALITY: usize = 12;

pub const CHALLENGE_STATE_NAME: &str = "schnorr";
