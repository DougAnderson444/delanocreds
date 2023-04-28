//! # Delano Creds API
//!
//! Roles:
//!
//! ## Root issuer.
//!
//! You are the issuer and your public key will be the only one seen in the credentials process.
//!
//! Choices to make, Summary of choices/options:
//! - Attributes: Maximum number of attributes (message_l), maximum number of items per attribute (cardinality),
//! how many attributes can be added (0 to k_prime, k_prime is at most message_l),
//! which attributes to show (n of cardinality), which attributes to aggregate.
//! - Delegation: Whether cred can be re-delegated or not (update_key).
//!
//! Every delegator can control how far delegations can go by further restricting the update key
//! and a delegator can also restrict the possibility to show attributes from a certain level in
//! the hierarchy (which corresponds to a commitment in the commitment vector) by not providing
//! the opening of the commitment to the delegatee.
//!
//! ## Showing a credential
//!
//! Adapt the signature to a re-randomized signature for a re-randomized commitment vector and
//! providing subset openings of the respective commitments. multiple commitments can also be aggregated
//! by using a cross-commitment.
//!
//!
//! Building credentials is a multiple step process:
//! 1. First you generate the Verification keys by choosing the max cardinality and max number of
//! attributes. Those verification keys (VK) can only be used up to those lengths. If you need longer
//! attributes, you need to generate new VKs.
//!
//! 2. Second, you take the Issuer and add credential attributes, within the maxium allowed by the VK.
//!
//! 3. Lastly you then issue the credential to a user.
//!
//! A Credential Builder.
//!
//! Issue Builder Options you can set:
//! - Max number of attributes (defaults to 10)
//! - Max cardinality (defaults to 5)
//!
//! Credential Builder Options you can set:
//! - Attributes (defaults to empty)
//! - Delegatable (defaults to false)
//! - Can add attributes (defaults to false)
//!

use spseq_uc::{AttributesLength, MaxCardinality};

pub mod dac;
pub mod set_commits;
pub mod spseq_uc;
pub mod types;
pub mod utils;
pub mod zkp;

/// Defaults
const DEFAULT_MAX_ATTRIBUTES: usize = 10;
const DEFAULT_MAX_CARDINALITY: usize = 5;

#[derive(Debug)]
/// The Root Issuer, the one with the Verification Key that issues the first credential.
pub struct RootIssuer {
    max_attrs: AttributesLength,
    max_card: MaxCardinality,
}

impl Default for RootIssuer {
    fn default() -> Self {
        Self::new()
    }
}

impl RootIssuer {
    pub fn new() -> Self {
        Self {
            max_attrs: AttributesLength(DEFAULT_MAX_ATTRIBUTES),
            max_card: MaxCardinality(DEFAULT_MAX_CARDINALITY),
        }
    }

    /// Add attributes to the credential. Attribute Type checks to ensure it is within the
    /// maximum number of attributes and maximum cardinality.
    pub fn max_attributes(&mut self, attributes: AttributesLength) -> &mut Self {
        self.max_attrs = attributes;
        self
    }

    /// Add cardinality to the credential. Attribute Type checks to ensure it is within the
    /// maximum number of attributes and maximum cardinality.
    pub fn max_cardinality(&mut self, cardinality: MaxCardinality) -> &mut Self {
        self.max_card = cardinality;
        self
    }

    /// Terminal function to build CrentialBuilder
    pub fn build(&self) -> CredentialBuilder {
        // generate signing keys
        // let dac = dac::Dac::new(self.max_card, self.max_attrs);

        CredentialBuilder::new(self)
    }
}

/// The Credential Builder, the one that builds the credential.
/// Constructor takes a RootIssuer
#[derive(Debug)]
pub struct CredentialBuilder<'a> {
    root_issuer: &'a RootIssuer,
    attributes: Vec<Attribute>,
    delegatable: bool,
    can_add_attributes: bool,
}

/// Attribute type
pub type Attribute = String;

impl<'a> CredentialBuilder<'a> {
    pub fn new(root_issuer: &'a RootIssuer) -> Self {
        Self {
            root_issuer,
            attributes: Vec::new(),
            delegatable: false,
            can_add_attributes: false,
        }
    }

    /// Add attributes to the credential. Attribute Type checks to ensure it is within the
    /// maximum number of attributes and maximum cardinality.
    pub fn attributes(&mut self, attributes: Vec<Attribute>) -> &mut Self {
        self.attributes = attributes;
        self
    }

    /// Set the credential to be delegatable.
    pub fn delegatable(&mut self, delegatable: bool) -> &mut Self {
        self.delegatable = delegatable;
        self
    }

    /// Set the credential to be able to add attributes.
    pub fn can_add_attributes(&mut self, can_add_attributes: bool) -> &mut Self {
        self.can_add_attributes = can_add_attributes;
        self
    }

    /// Terminal function to issue (build) the Credential
    pub fn issue(&self) -> Credential {
        Credential::new(self)
    }
}

pub struct Credential;

impl Credential {
    pub fn new(credential_builder: &CredentialBuilder) -> Self {
        Self
    }
}

#[cfg(test)]
mod test_api {
    use super::*;

    #[test]
    fn test_root_issuer() {
        let mut root_issuer = RootIssuer::new();

        // check defaults
        assert_eq!(root_issuer.max_attrs.0, DEFAULT_MAX_ATTRIBUTES);
        assert_eq!(root_issuer.max_card.0, DEFAULT_MAX_CARDINALITY);

        // set new ones
        let attributes = 12;
        let cardinality = 8;

        root_issuer.max_attributes(AttributesLength(attributes));
        root_issuer.max_cardinality(MaxCardinality(cardinality));

        assert_eq!(root_issuer.max_attrs, AttributesLength(attributes));
        assert_eq!(root_issuer.max_card, MaxCardinality(cardinality));
    }

    #[test]
    fn test_credential_builder() {
        let root_issuer = RootIssuer::new();
        let mut credential_builder = CredentialBuilder::new(&root_issuer);

        // check defaults
        assert_eq!(credential_builder.attributes, Vec::<String>::new());
        assert_eq!(credential_builder.delegatable, false);
        assert_eq!(credential_builder.can_add_attributes, false);

        // set new ones
        let attributes = vec!["name".to_string(), "age".to_string()];
        let delegatable = true;
        let can_add_attributes = true;

        credential_builder
            .attributes(attributes.clone())
            .delegatable(delegatable)
            .can_add_attributes(can_add_attributes);

        assert_eq!(credential_builder.attributes, attributes);
        assert_eq!(credential_builder.delegatable, delegatable);
        assert_eq!(credential_builder.can_add_attributes, can_add_attributes);
    }
}
