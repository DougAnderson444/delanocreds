use crate::attributes::Attribute;
use amcl_wrapper::field_elem::FieldElement;
use entry::Entry;
use keypair::{MaxCardinality, MaxEntries, VK};

pub mod attributes;
pub mod entry;
pub mod keypair;
pub mod set_commits;
pub mod types;
pub mod zkp;

/// Default Max Attributes: The maximum number of attribute entries allowed in a credential.
const DEFAULT_MAX_ATTRIBUTES: usize = 10;
/// Default Max Cardinality: The maximum number of total attribute elements allowed in a credential.
const DEFAULT_MAX_CARDINALITY: usize = 5;

// Test the README.md code snippets
// #![doc = include_str!("../README.md")]
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

// create a `selected_attrs` from `all_attributes` where the given selections match, make all other entries empty
fn select_attrs(all_attributes: &[Entry], selections: &[Attribute]) -> Vec<Entry> {
    all_attributes
        .iter()
        .map(|entry| {
            Entry(
                entry
                    .0
                    .iter()
                    .filter(|attr| selections.contains(attr))
                    .cloned()
                    .collect::<Vec<_>>(),
            )
        })
        .collect::<Vec<_>>()
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
