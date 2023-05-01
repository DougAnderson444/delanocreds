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
