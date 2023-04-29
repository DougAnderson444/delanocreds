//! # Delanocreds API
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
//! providing subset openings of the respective commitments. Multiple commitments can also be aggregated
//! by using a cross-commitment.
//!
//! Building credentials is a multiple step process:
//! 1. First you generate the Verification keys by choosing the max cardinality (total individual credentials)
//! and max number of credential sets. Those verification keys (VK) can only be used up to those lengths. If you need longer
//! attributes, you need to generate new VKs.
//!
//! 2. Second, you take the Issuer and add credential attributes, within the maxium allowed by the VK.
//!
//! 3. Lastly you then issue the credential to a user.
//!
//! A Credential Builder.
//!
//! Issue Builder Options you can set:
//! - Max number of attributes (defaults to 5)
//! - Max cardinality (defaults to 10)
//!
//! Credential Builder Options you can set:
//! - Attributes (defaults to empty)
//! - Delegatable (no opening information provided by default)
//! - Can add attributes (defaults to false)
//!
//! Show a credential:
//! - Re-randomize the signature for an updated commitment vector
//! - Provide subset openings of the respective commitments

use std::fmt;

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
        // generate keys for the root issuer

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
    pub fn build(self) -> CredentialBuilder {
        // generate signing keys
        // let dac = dac::Dac::new(self.max_card, self.max_attrs);

        CredentialBuilder::new(self)
    }
}

/// The Credential Builder, the one that builds the credential.
/// Constructor takes a RootIssuer
#[derive(Debug)]
pub struct CredentialBuilder {
    root_issuer: RootIssuer,
    attributes: Vec<Vec<Attribute>>,
    delegatable: bool,
    can_add_attributes: bool,
}

/// Attribute type
pub type Attribute = String;

impl CredentialBuilder {
    pub fn new(root_issuer: RootIssuer) -> Self {
        Self {
            root_issuer,
            attributes: Vec::new(),
            delegatable: false,
            can_add_attributes: false,
        }
    }

    /// Set the attributes for the credential.
    /// An attribute is vectors of strings up to max cardinality in length.
    /// Attributes are vectors of strings up to max attributes in length.
    ///
    /// # Returns
    /// `CredentialBuilder` if the attributes are within the max attributes and max cardinality.
    /// `LengthError` if the attributes are not within the max attributes and max cardinality.
    pub fn with_attributes(
        &mut self,
        attributes: Vec<Vec<String>>,
    ) -> Result<&mut Self, LengthError> {
        // check both length of attributes <= max_length,
        if attributes.len() > *self.root_issuer.max_attrs {
            return Err(LengthError::new(attributes.len(), 0));
        }
        // and the cardinality of each attribute <= max_cardinality
        for (i, attribute) in attributes.iter().enumerate() {
            if attribute.len() > *self.root_issuer.max_card {
                return Err(LengthError::new(i, attribute.len()));
            }
        }
        self.attributes = attributes;
        Ok(self)
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
    pub fn issue(&self) -> spseq_uc::EqcSign {
        spseq_uc::EqcSign::new(self.root_issuer.max_card.clone())
    }
}

/// Make a LengthError that tells the user which Attribute or Attributes was too long
/// or had too high of a cardinality
#[derive(Debug)]
pub struct LengthError {
    pub kind: LengthErrorKind,
    pub attribute: usize,
    pub cardinality: usize,
}

/// Error if the attributes are too long or have too high of a cardinality
#[derive(Debug)]
pub enum LengthErrorKind {
    TooManyAttributes,
    TooLongCardinality(usize),
}

/// Error kind depends on if Some(cardinality) is included, then it's a TooLongCardinality
/// otherwise it's a TooManyAttributes
impl LengthError {
    pub fn new(attribute: usize, cardinality: usize) -> Self {
        // guard on cardinality (if 0, then TooManyAttributes)
        if cardinality == 0 {
            Self {
                kind: LengthErrorKind::TooManyAttributes,
                attribute,
                cardinality,
            }
        } else {
            Self {
                kind: LengthErrorKind::TooLongCardinality(cardinality),
                attribute,
                cardinality,
            }
        }
    }
}

/// impl fmt for display to show reasonable error message
impl fmt::Display for LengthError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self.kind {
            LengthErrorKind::TooManyAttributes => {
                write!(f, "too many attributes, max is {}", self.attribute)
            }
            LengthErrorKind::TooLongCardinality(cardinality) => write!(
                f,
                "attribute {} has too long of a cardinality of {}",
                self.attribute, cardinality
            ),
        }
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
    fn test_credential_builder() -> Result<(), LengthError> {
        let root_issuer = RootIssuer::new();
        let mut credential_builder = CredentialBuilder::new(root_issuer);

        // empty Vec<Vec::<String>::new()>
        let empty = Vec::<Vec<String>>::new();
        // check defaults
        assert_eq!(credential_builder.attributes, empty);
        assert!(!credential_builder.delegatable);
        assert!(!credential_builder.can_add_attributes);

        // set new ones
        let attributes = vec![
            vec!["name".to_string(), "age".to_string()];
            *credential_builder.root_issuer.max_attrs
        ];
        let delegatable = true;
        let can_add_attributes = true;

        credential_builder
            .with_attributes(attributes.clone())?
            .delegatable(delegatable)
            .can_add_attributes(can_add_attributes);

        assert_eq!(credential_builder.attributes, attributes);
        assert_eq!(credential_builder.delegatable, delegatable);
        assert_eq!(credential_builder.can_add_attributes, can_add_attributes);

        Ok(())
    }

    #[test]
    fn test_attributes_too_long() {
        // fails when too long of an attributes vctor is passed > max attributes
        let root_issuer = RootIssuer::new();
        let mut credential_builder = CredentialBuilder::new(root_issuer);

        // create attrs that are max_attrs +1
        let attribute = vec!["name".to_string(), "age".to_string()];
        let attributes = vec![attribute; *credential_builder.root_issuer.max_attrs + 1];

        // add with_attributes
        let result = credential_builder.with_attributes(attributes);

        // check that it fails
        assert!(result.is_err());
    }

    #[test]
    fn test_too_long_cardinality() {
        // fails when too long of a cardinality is passed > max cardinality
        let root_issuer = RootIssuer::new();
        let mut credential_builder = CredentialBuilder::new(root_issuer);

        // create attrs that are max_attrs +1
        let attribute = vec!["name".to_string(); *credential_builder.root_issuer.max_card + 1];
        let attributes = vec![attribute];

        // add with_attributes
        let result = credential_builder.with_attributes(attributes);

        // check that it fails
        assert!(result.is_err());
    }

    #[test]
    fn test_delegatable() {}
}
