//! # Delanocreds API
//!
//! **Del**egatable **Ano**nymous **Cred**ential**s**: Based on the Crypto paper
//! [Practical Delegatable Anonymous Credentials From Equivalence Class Signatures](https://eprint.iacr.org/2022/680)
//!
//! This library enables you to create, issue, delegate/extend/restrict/transfer, and verify credentials in an anonymous way.
//!
//! # Roles
//!
//! The roles start with a Root Issuer, then delegated Credential Holder/Prover and Verifier.
//!
//! ## Root Issuer
//!
//! You are the issuer and your verification key (public key) will be the only non-anonymous key in the credentials process.
//!
//! #### Root Issuer Summary of Choices/Options:
//!
//! - **Maxiumum Attribute Entries**: Credntials have a maximum number of entries.
//! Each entry holds up to MaxCardinality of Attributes.
//! The Root Issuer sets a maximum number of entries (`message_l`)
//! - **Maximum Cardinality (Attributes per Entry)**: There is a set maximum number of items total (`cardinality`, `message_l[n].len()` <= `cardinality`)
//! - **Extendable Limit**: What the maximum number of additional entries may be (current entries length up to `k_prime`, `k_prime` is at most `message_l`.
//! Or in other words: `current < k_prime < message_l`),
//!
//! Below is a markdown table with an example of attribute entries, and attributes in each entry, with yes/no for each feature
//!
//! ```md
//! Attribute Entries:
//! ==> Entry Level 0: [Attribute, Attribute, Attribute]
//! ==> Entry Level 1: [Attribute]
//! ==> Entry Level 2: [Attribute, Attribute]
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
//! - **Restrict Adding Attributes**: Restrict adding attributes to the credential (by reducing the length of `Credential { UpdateKey } `).
//! - **Restrict Showing certain `Attribute` Entry levels**: By zeroizing the opening information  corresponding
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
//! - How many attributes can be added (`k_prime` defaults to zero(0))
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

//! Given all the the documentation above, the following code is a possible API and usage for Delanocreds in Rust:
//!
//! 1. Root Issuer builds Root Credential with:
//! - max attributes,
//! - max cardinality,
//! - initial attribute entries,
//! - extendable attributes (),
//! - fully provable atrributes (all opening information provided)
//! - k_prime set the number of additonal attributes available from the `update_key`
//!
//! 2. Root Issuer issues Root Credential to Credential Holder Alice's pseudonym (nym).
//! Alice is the first holder of the Credential.
//!
//! 3. Alice take credential bytes and loads them into the Credential structure. With the Root Credential, Alice can:
//! - generate proof
//! - delegate to another nym (if allowed by the cred update_key)
//! - add attributes (if allowed by the cred update_key)
//!
//! 3a. Alice generates a proof for the Root Credential with:
//! - a list of attributes to prove
//!
//! 3b. Alice delegates to another nym with:
//! - a list of attributes to delegate
//! - a potentially shorter update key to restrict the delegatee from adding attribute entries
//! - potentially redacted opening information to restrict the delegatee from showing attributes
//!
//! 4. Credential Holder Bob takes the delegated credential bytes and loads them into the Credential structure.
//! With the delegated credential, Bob can do the same as Alice within the bounds of the update key and opening information.

use crate::attributes::Attribute;
use amcl_wrapper::field_elem::FieldElement;
use keypair::{MaxCardinality, MaxEntries, VK};
use utils::Entry;

pub mod attributes;
pub mod keypair;
pub mod set_commits;
pub mod types;
pub mod utils;
pub mod zkp;

/// Default Max Attributes: The maximum number of attribute entries allowed in a credential.
const DEFAULT_MAX_ATTRIBUTES: usize = 10;
/// Default Max Cardinality: The maximum number of total attribute elements allowed in a credential.
const DEFAULT_MAX_CARDINALITY: usize = 5;

// Test the README.md code snippets
// #[doc = include_str!("../README.md")]
// #[cfg(doctest)]
// pub struct ReadmeDoctests;

#[derive(Debug)]
/// The Root Issuer, the one with the Verification Key that issues the first credential.
pub struct RootIssuerBuilder {
    max_entries: MaxEntries,
    max_card: MaxCardinality,
}

impl Default for RootIssuerBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl RootIssuerBuilder {
    pub fn new() -> Self {
        // generate keys for the root issuer

        Self {
            max_entries: MaxEntries(DEFAULT_MAX_ATTRIBUTES),
            max_card: MaxCardinality(DEFAULT_MAX_CARDINALITY),
        }
    }

    /// Add attributes to the credential. Attribute Type checks to ensure it is within the
    /// maximum number of attributes and maximum cardinality.
    pub fn max_entries(&mut self, attributes: MaxEntries) -> &mut Self {
        self.max_entries = attributes;
        self
    }

    /// Add cardinality to the credential. Attribute Type checks to ensure it is within the
    /// maximum number of attributes and maximum cardinality.
    pub fn max_cardinality(&mut self, cardinality: MaxCardinality) -> &mut Self {
        self.max_card = cardinality;
        self
    }

    // /// Terminal function to build CrentialBuilder
    // pub fn build(self) -> RootIssuer {
    //     // generate signing keys
    //     // let dac = dac::Dac::new(self.max_card, self.max_attrs);

    //     // RootIssuer::new(self)
    // }
}

#[derive(Debug)]
/// The Root Issuer, the one with the Verification Key that issues the first credential.
pub struct RootIssuer {
    max_entries: MaxEntries,
    max_card: MaxCardinality,
    entries: Vec<Entry>,
    extendable_limit: usize,
    vk_ca: Vec<VK>,
    sk_ca: Vec<FieldElement>,
}

impl RootIssuer {
    // pub fn new(root_issuer_builder: RootIssuerBuilder) -> Self {
    //     let dac = Dac::new(MaxCardinality(*root_issuer_builder.max_card));
    //     let (sk_ca, vk_ca) = dac.spseq_uc.sign_keygen(root_issuer_builder.max_entries);

    //     Self {
    //         max_entries: root_issuer_builder.max_entries,
    //         max_card: root_issuer_builder.max_card,
    //         entries: Vec::new(),
    //         extendable_limit: 0,
    //         vk_ca,
    //         sk_ca,
    //     }
    // }

    // /// Terminal function to build CrentialBuilder
    // pub fn entry_builder(self) -> EntryBuilder {
    //     EntryBuilder::new(self)
    // }

    // /// Set the current entries for th Root Credential.
    // pub fn entries(self, entries: Vec<Entry>) -> Self {
    //     Self { entries, ..self }
    // }

    // /// Set the Root Credential as extendable to the given limit
    // /// Limit must be no more then max_entries - `entries.len()`
    // pub fn extendable(self, limit: usize) -> Self {
    //     Self {
    //         extendable_limit: limit,
    //         ..self
    //     }
    // }

    // /// Issues (Builds) the Root Credential.
    // /// # Returns
    // /// - [`Credential`]: The Root Credential
    // pub fn issue_to(self, proof: NymProof) -> Credential {
    //     // use `dac.issue_cred()` to build the credential
    //     let dac = Dac::new(MaxCardinality(*self.max_card));

    //     match dac.issue_cred(
    //         &self.vk_ca,
    //         &self.entries,
    //         &self.sk_ca,
    //         Some(self.extendable_limit),
    //         proof,
    //     ) {
    //         Ok(cred) => cred,
    //         Err(e) => panic!("Error issuing credential: {:?}", e),
    //     }
    // }
}

/// Builds the entries for the Root Credential. Ensures that the number of attributes
/// in each entry are within the max cardinality. Ensures the number of entries are
/// within the max entries.
/// - `entry_count`: The current number of entries in the credential.
/// - `root_issuer`: The Root Issuer that issued the credential.
///
pub struct EntryBuilder {
    entry_count: usize,
    entries: Vec<Entry>,
    root_issuer: RootIssuer,
}

impl EntryBuilder {
    pub fn new(root_issuer: RootIssuer) -> Self {
        Self {
            entry_count: 0,
            entries: Vec::new(),
            root_issuer,
        }
    }

    /// Wraps the value as an Attribute for an entry.
    /// An attribute is vectors of strings up to max cardinality in length.
    /// Attributes are vectors of strings up to max attributes in length.
    /// # Returns
    /// - `Attibute`
    pub fn attribute(&mut self, attribute: String) -> Attribute {
        attributes::attribute(attribute)
    }

    /// Builds an Entry out of a vector of attributes
    /// # Returns
    /// `Some(Entry)` if the attributes are within the max entries.
    /// `None` if the attributes are not within the max entries.
    pub fn entry(&mut self, attributes: &[Attribute]) -> Option<Entry> {
        // check if entries are within max entries
        // if not, return None
        if self.entry_count == self.root_issuer.max_card.0 {
            return None;
        }

        // increment entry count
        self.entry_count += 1;

        if attributes.len() < self.root_issuer.max_entries.0 {
            Some(Entry(attributes.to_vec()))
        } else {
            None
        }
    }

    /// Build all entires from each entry
    /// # Returns
    /// - `Entries`
    pub fn drain(&mut self) -> Vec<Entry> {
        // reset count
        self.entry_count = 0;
        // return ownership of entries
        self.entries.drain(..).collect()
    }
}

#[cfg(test)]
mod test_api {
    use super::*;

    #[test]
    fn test_root_issuer() {
        let mut root_issuer = RootIssuerBuilder::new();

        // check defaults
        assert_eq!(root_issuer.max_entries.0, DEFAULT_MAX_ATTRIBUTES);
        assert_eq!(root_issuer.max_card.0, DEFAULT_MAX_CARDINALITY);

        // set new ones
        let attributes = 12;
        let cardinality = 8;

        root_issuer.max_entries(MaxEntries(attributes));
        root_issuer.max_cardinality(MaxCardinality(cardinality));

        assert_eq!(root_issuer.max_entries, MaxEntries(attributes));
        assert_eq!(root_issuer.max_card, MaxCardinality(cardinality));
    }
}
