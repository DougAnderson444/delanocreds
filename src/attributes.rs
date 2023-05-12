//! A module for commitments, attributes and opening information management.
//!
//! - AttributeEntries (a Vector of attribute entries) hierarchy starts with Root Issuer entry/entries
//! - AttributeEntries can be extended up to `k_prime`
//! - AttributeEntries can be restricted by zeroizing opening information
//! - AttributeEntries can hold up to a cumulative total of `max_cardinality` attribute entries
//! - There can be up to `message_l` entries in each AttributeEntries vector
//! - Each entry in AttributeEntries is a vector holding a number of Attributes
//! - You can select subsets of AttributesVectors, by indicating which indexes you want to select, a 2D vector matix
//! - When opening information is zeroized, then the corresponding entry in AttributeEntries cannot be selected,
//! thus opening and atrributes have a relationship with each other. The opening vector is held in the credential,
//! ths the credential and the attributes have a relationship with each other.
//!
//! # API
//!
//! // create a new commitment vector
//! let mut attributes = AttributesVector::new();
//!
//! // push attributes (vectors of strings) to the vector
//! attributes.push(vec!["a".to_string(), "b".to_string(), "c".to_string()]);
//!
//! // select from the attributes
//! let selected_attrs = attributes.select(vec![vec![], vec![0, 1], vec![0, 1]]);
use std::ops::Deref;

use wa_serde_derive::{Deserialize, Serialize};

use crate::spseq_uc::{AttributesLength, MaxCardinality};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttributeName(String);

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttributeValue(String);

impl Deref for AttributeName {
    type Target = String;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Deref for AttributeValue {
    type Target = String;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Attribute {
    name: String,
    value: String,
}

impl Attribute {
    /// New attribute from name and value
    pub fn new(name: AttributeName, value: AttributeValue) -> Self {
        Attribute {
            name: name.0,
            value: value.0,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttributeEntry {
    name: String,
    attributes: Vec<Attribute>,
    max_cardinality: usize,
}

impl AttributeEntry {
    /// New attribute entry from name and attributes
    pub fn new(name: String, attributes: Vec<Attribute>, max_cardinality: &MaxCardinality) -> Self {
        AttributeEntry {
            name,
            attributes,
            max_cardinality: max_cardinality.0,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttributeEntries(Vec<AttributeEntry>);

impl Default for AttributeEntries {
    fn default() -> Self {
        Self::new()
    }
}

impl AttributeEntries {
    /// New attribute entries
    pub fn new() -> Self {
        AttributeEntries(Vec::new())
    }

    /// Select Attribute Entry/Entries by name of AttributeEntry
    /// Returns a vector of AttributeEntry
    pub fn select_entries_by_name(&self, names: Vec<String>) -> Vec<AttributeEntry> {
        self.0
            .iter()
            .filter(|entry| names.contains(&entry.name))
            .cloned()
            .collect()
    }

    /// Select Attribute by name from Entry within Entries
    /// Returns a vector of attributes
    pub fn select_attributes_by_name(&self, names: Vec<String>) -> Vec<Attribute> {
        self.0
            .iter()
            .filter(|entry| names.contains(&entry.name))
            .flat_map(|entry| entry.attributes.clone())
            .collect()
    }
}

/// AttributeEntriesBuilder is a state machine (for constraints) and a Builder (for adding optional values).
/// It starts in the <Vacancy> state and takes max_entries.
/// Once max_entries is hit, it changes state to <Full>
/// Full: The AttributeEntriesBuilder.entries has reached `max_entries`
/// Vacancy: The AttributeEntriesBuilder has not reached its maximum number of entries
/// There is a Builder trait which defines remove_entry and build
/// There is AttrBuilder which implements Builder
/// AttrBuilder<Vacancy> has a add_entry fn which returns impl Builder (AttrBuilder<Vacancy> or AttrBuilder<Full>) depending on whether it hit max_entries or not
struct AttrBuilder<S = Vacancy> {
    state: std::marker::PhantomData<S>,
    entries: Vec<AttributeEntry>,
    max_entries: usize,
    max_cardinality: usize,
}
enum State {
    Vacancy(AttrBuilder<Vacancy>),
    Full(AttrBuilder<Full>),
}
struct Vacancy;
struct Full;

impl AttrBuilder<Vacancy> {
    /// New AttrBuilder
    pub fn new(max_entries: &AttributesLength, max_cardinality: &MaxCardinality) -> Self {
        AttrBuilder {
            state: std::marker::PhantomData::<Vacancy>,
            entries: Vec::new(),
            max_entries: max_entries.0,
            max_cardinality: max_cardinality.0,
        }
    }

    pub fn full(self) -> AttrBuilder {
        self.into()
    }

    /// Add entry to AttrBuilder
    /// Returns State as this could potentially alter the State
    pub fn add_entry(mut self, entry: AttributeEntry) -> AttrBuilder {
        self.entries.push(entry);
        if self.entries.len() == self.entries.capacity() {
            // Long way:
            // AttrBuilder {
            //     state: std::marker::PhantomData::<Vacancy>,
            //     entries: self.entries,
            // }
            // Short way:
            State::Vacancy(self).into()
        } else {
            State::Full(self.into()).into()
        }
    }

    /// Remove entry, no state change
    fn remove_entry(mut self, index: usize) -> Self {
        self.entries.remove(index);
        self
    }
}

impl AttrBuilder<Full> {
    /// Remove entry, set state Vacancy
    fn remove_entry(mut self, index: usize) -> AttrBuilder<Vacancy> {
        self.entries.remove(index);
        self.into()
    }
}

impl<S> AttrBuilder<S> {
    fn build(self) -> AttributeEntries {
        AttributeEntries(self.entries)
    }
}

impl From<AttrBuilder<Vacancy>> for AttrBuilder<Full> {
    fn from(builder: AttrBuilder<Vacancy>) -> AttrBuilder<Full> {
        AttrBuilder {
            state: std::marker::PhantomData::<Full>,
            entries: builder.entries,
            max_entries: builder.max_entries,
            max_cardinality: builder.max_cardinality,
        }
    }
}

impl From<AttrBuilder<Full>> for AttrBuilder<Vacancy> {
    fn from(builder: AttrBuilder<Full>) -> AttrBuilder<Vacancy> {
        AttrBuilder {
            state: std::marker::PhantomData::<Vacancy>,
            entries: builder.entries,
            max_entries: builder.max_entries,
            max_cardinality: builder.max_cardinality,
        }
    }
}

impl From<State> for AttrBuilder<Vacancy> {
    fn from(state: State) -> AttrBuilder<Vacancy> {
        match state {
            State::Vacancy(builder) => builder,
            State::Full(builder) => builder.into(),
        }
    }
}

impl From<State> for AttrBuilder<Full> {
    fn from(state: State) -> AttrBuilder<Full> {
        match state {
            State::Vacancy(builder) => builder.into(),
            State::Full(builder) => builder,
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_full_entry() {
        let max_card = MaxCardinality(2);
        let mut builder = AttrBuilder::new(&AttributesLength(2), &max_card);

        let attr_1 = Attribute::new(
            AttributeName("name".to_string()),
            AttributeValue("value".to_string()),
        );
        let attr_2 = Attribute::new(
            AttributeName("name".to_string()),
            AttributeValue("value".to_string()),
        );

        let attr_3 = Attribute::new(
            AttributeName("name".to_string()),
            AttributeValue("value".to_string()),
        );

        let attr_4 = Attribute::new(
            AttributeName("name".to_string()),
            AttributeValue("value".to_string()),
        );

        let entry_1 = AttributeEntry::new("entry_1".to_string(), vec![attr_1, attr_2], &max_card);
        let entry_2 = AttributeEntry::new("entry_2".to_string(), vec![attr_3, attr_4], &max_card);

        let state = builder.add_entry(entry_1).add_entry(entry_2);
        let entries = state.build();
    }
}
