//! #[Entry]
//!
//! - A Vector of [Attribute] entries, a hierarchy starts with Root Issuer entry/entries
//! - can be extended up to `k_prime` if `update_key` is provided
//! - proving [Entry] [Attribute]s can be restricted by zeroizing opening information
//! - each [Entry] can hold up to a total of `MaxCardinality` attributes
//! - There can be up to `message_l` entries in each [Entry] vector
//! - Each entry in [Entry] is a vector holding a number of Attributes
//! - You can select subsets of AttributesVectors, by indicating which indexes you want to select, a 2D vector matix
//! - When opening information is zeroized, then the corresponding entry in [Entry] cannot be selected,
//! thus opening and atrributes have a relationship with each other. The opening vector is held in the credential,
//! ths the credential and the attributes have a relationship with each other.
//!
use crate::attributes::Attribute;
use crate::ec::curve::FieldElement;
use crate::error::CurveError;
use std::ops::Deref;

/// Entry is a vector of Attributes
#[derive(Clone, Debug, PartialEq)]
pub struct Entry(pub Vec<Attribute>);

impl Entry {
    /// Returns a new Entry with the given attributes
    pub fn new(attributes: &[Attribute]) -> Self {
        Entry(attributes.to_vec())
    }
}

pub fn entry(attributes: &[Attribute]) -> Entry {
    Entry(attributes.to_vec())
}

impl Deref for Entry {
    type Target = Vec<Attribute>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl IntoIterator for Entry {
    type Item = Attribute;
    type IntoIter = ::std::vec::IntoIter<Attribute>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

// implement `std::iter::FromIterator<attributes::Attribute>` for `entry::Entry`
impl std::iter::FromIterator<Attribute> for Entry {
    fn from_iter<I: IntoIterator<Item = Attribute>>(iter: I) -> Self {
        Entry(iter.into_iter().collect())
    }
}

/// Iterates through each Attribute in the Entry and converts it to a FieldElement
pub fn convert_entry_to_bn(input: &Entry) -> Result<Vec<FieldElement>, CurveError> {
    input
        .iter()
        .map(|attr| FieldElement::from_bytes(attr.digest()))
        .collect()
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct MaxEntries(pub usize);

impl From<usize> for MaxEntries {
    fn from(item: usize) -> Self {
        MaxEntries(item)
    }
}

// from u8
impl From<u8> for MaxEntries {
    fn from(item: u8) -> Self {
        MaxEntries(item as usize)
    }
}

impl From<MaxEntries> for usize {
    fn from(item: MaxEntries) -> Self {
        item.0
    }
}

impl Deref for MaxEntries {
    type Target = usize;
    fn deref(&self) -> &usize {
        &self.0
    }
}

impl Default for MaxEntries {
    fn default() -> Self {
        MaxEntries(crate::config::DEFAULT_MAX_ENTRIES)
    }
}

impl MaxEntries {
    pub fn new(item: usize) -> Self {
        MaxEntries(item)
    }
}

impl std::cmp::PartialEq<MaxEntries> for usize {
    fn eq(&self, other: &MaxEntries) -> bool {
        self == &other.0
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_entry() {
        // check whether Entry can be checked for is_empty
        let entry = Entry(vec![]);
        assert!(entry.is_empty());
    }
}
