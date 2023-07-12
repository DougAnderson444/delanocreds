use crate::attributes::Attribute;
use amcl_wrapper::errors::SerzDeserzError;
use amcl_wrapper::field_elem::FieldElement;
use std::ops::Deref;

#[derive(Clone, Debug, PartialEq)]
pub struct Entry(pub Vec<Attribute>);

impl Entry {
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
pub fn convert_entry_to_bn(input: &Entry) -> Result<Vec<FieldElement>, SerzDeserzError> {
    input
        .iter()
        .map(|attr| FieldElement::from_bytes(attr.digest()))
        .collect()
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
