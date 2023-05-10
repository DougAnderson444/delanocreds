//! # Delanocreds API
//!
//! **Del**egatable **Ano**nymous **Cred**ential**s**: Based on the Crypto paper
//! [Practical Delegatable Anonymous Credentials From Equivalence Class Signatures](https://eprint.iacr.org/2022/680)
//!
//! This library enables you to create, issue, delegate, and verify credentials in an anonymous way.
//!
//! # Roles
//!
//! The roles start with a Root Issuer, then delegated Credential Holder(s), then a Prover(s) and Verifier(s).
//!
//! ## Root Issuer
//!
//! You are the issuer and your verification key (public key) will be the only non-anonymous key in the credentials process.
//!
//! #### Root Issuer Summary of Choices/Options:
//!
//! - **Attribute Entries**: There can be a maximum number of attribute entries (`message_l`)
//! - **Total Entries Elements**: There is a set maximum number of items total (`cardinality`)
//! - **Additonal Entries**: There can be a maximum number of additional entries (current entries length up to `k_prime`, `k_prime` is at most `message_l`),
//! - **Delegation**: Whether cred can be re-delegated or not (update_key).
//!
//! Below is a markdown table with an example of attribute entries, and attributes in each entry, with yes/no for each feature
//!
//! ```md
//! Attribute Entries:
//! ==> Entry Level 0: [Element, Element, Element, Element]
//! ==> Entry Level 1: [Element, Element, Element, Element, Element]
//! ==> Entry Level 2: [Element, Element]
//! ==> Additonal Entry? Only if 3 < k_prime < message_l
//! ```
//!
//! - Max Entries: `message_l`
//! - Max total elements: `max_cardinality`
//!
//! ```md
//! Opening Information
//!
//! ==> Entry Level 0: Valid opening information
//! ==> Entry Level 1: Valid opening information
//! ==> Entry Level 2: Zeroized opening information
//! ```
//!
//! #### Delegated Credential Holder(s) Choice of Options:
//!
//! Delegation in the sence of DAC means the adding or generating proofs of attributes to a credential.
//!
//! Thus holders have the option to restrict:
//!
//! - **Restrict Adding Attributes**: Restrict adding attributes to the credential (by reducing `k_prime`).
//! - **Restrict Showing certin Attribute Entry levels**: By zeroizing the opening information  corresponding
//! to the attribute entry level you want to restrict.
//!
//! Every delegator can control how far delegations can go by further restricting the `update key`
//! and a delegator can also restrict the possibility to show attributes from a certain level in
//! the hierarchy (which corresponds to a commitment in the commitment vector) by not providing
//! the opening of the commitment to the delegatee.
//!
//! Likewise, holders have the ability to extend the credential by adding attributes to the credential,
//! as long as the total number of attributes doesn't exceed `k_prime`.
//!
//! ## Showing a credential
//!
//! Once a holder wants to show a credential, with any combination of attributes (as long as the opening information is available),
//! the holder selects which attributes they want to prove, then they run `proof_cred` to generate a proof.
//!
//! Holders can only prove up to `max_cardinality` attributes at a time.
//!
//! ## Building a Credential
//!
//! Building credentials is a multiple step process:
//!
//! 1. First you generate the Verification Keys by choosing the max cardinality (total individual credentials)
//! and max number of credential sets. Those verification keys (VK) can only be used up to those lengths. If you need longer
//! attributes, you need to generate new VKs.
//!
//! 2. Second, you take the Issuer and add credential attributes, within the maxium allowed by the VK.
//!
//! 3. Lastly you then issue the credential to a user.
//!
//! A Credential Builder.
//!
//! Root Issuer Builder Options you can set:
//! - Max number of attributes (defaults to 5)
//! - Max cardinality (defaults to 10)
//!
//! Credential Builder Options you can set:
//! - Attributes (defaults to empty)
//! - Delegatable (defaults to no `opening information` provided [false])
//! - Can add attributes (defaults to no `update key` provided [false])
//! - How many attributes can be added (`k_prime` defaults to zero(0) [none])
//!
//! Show a credential proof:
//! - Randomize your public key into a pseudonym
//! - Choose which attributes to show, even if they were issued by separate delegators
//! - Generate a proof from the credential and
//!
//! Credential Constraints:
//! - You can only add attributes if the current number of attributes is below `message_l`.
//! - You can only issue a credential if the current number of attributes is below `max_cardinality`.
//!
//! If you want to restrict delegatees from showing proofs for attributes from
//! a certain level in the hierarchy (which corresponds to a commitment in the
//! commitment vector) by not providing the opening of the commitment to the delegatee.
//!
//! In Practical terms, this means that when the Root Level commit hold C.R.U.D.,
//! the way to restrict the delegatee from showing the proof is to add a second
//! level commit that holds only R.U.D., and not provide the opening of the first level.
//! This way, the delegatee can only show the proof for the second level thus can only
//! prove the ability to Read, Update, and Delete, but not Create.
//!
//! States and Sub-states:
//! - State: Sub-states.
//! - Configuration: Unconfigured, configured
//! - Credential: Unissued, issued, delegated
//! - Delegatable: True, False. A credential is only delegatable if `update_key` is provided.
//! - Extendable: True, False. Only extendable if number of attribute commits is less than k_prime
//! - Showable: Up to the number of attributes in the credential. restricted by `opening_info `
//!
//! BLS12-381 public keys are 48 bytes long. Private keys are 32 bytes long.

/// Given all the the documentation above, the following code is a possible API and usage for Delanocreds in Rust:
///
/// 1. Root Issuer builds Root Credential with:
/// - max attributes,
/// - max cardinality,
/// - initial attribute entries,
/// - extendable attributes (k_prime),
/// - fully provable atrributes (all opening information provided)
/// - delegatable attributes (update key provided)
///
/// 2. Root Issuer issues Root Credential to Credential Holder Alice's pseudonym (nym).
/// Alice is the first holder of the Credential.
///
/// 3. Alice take credential bytes and loads them into the Credential structure. With the Root Credential, Alice can:
/// - generate proof
/// - delegate to another nym (if allowed by the cred update_key)
/// - add attributes (if allowed by the cred update_key)
///
/// 3a. Alice generates a proof for the Root Credential with:
/// - a list of attributes to prove
///
/// 3b. Alice delegates to another nym with:
/// - a list of attributes to delegate
/// - a potentially shorter update key to restrict the delegatee from adding attribute entries
/// - potentially redacted opening information to restrict the delegatee from showing attributes
///
/// 4. Credential Holder Bob takes the delegated credential bytes and loads them into the Credential structure.
/// With the delegated credential, Bob can do the same as Alice within the bounds of the update key and opening information.
use std::fmt;

use spseq_uc::{AttributesLength, MaxCardinality};

pub mod attributes;
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
