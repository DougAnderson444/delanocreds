//! A module for creating:
//! - Individual Attibute, a Multihash generated from bytes (likely from a string)
//! - Entry, a vector of Attibutes
//!
//! - AttributeEntries (a Vector of attribute entries) hierarchy starts with Root Issuer entry/entries
//! - AttributeEntries can be extended up to `k_prime` if `update_key` is provided
//! - AttributeEntries can be restricted by zeroizing opening information
//! - AttributeEntries can hold up to a cumulative total of `max_cardinality` attributes
//! - There can be up to `message_l` entries in each AttributeEntries vector
//! - Each entry in AttributeEntries is a vector holding a number of Attributes
//! - You can select subsets of AttributesVectors, by indicating which indexes you want to select, a 2D vector matix
//! - When opening information is zeroized, then the corresponding entry in AttributeEntries cannot be selected,
//! thus opening and atrributes have a relationship with each other. The opening vector is held in the credential,
//! ths the credential and the attributes have a relationship with each other.
//!
//! # API
//!
//! // create a new Attribute
//! let attribute: Attribute = attribute("age>21")
//!
//! // attributes have a `digest()` method which returns a &[u8]
//! attributes.push(vec!["a".to_string(), "b".to_string(), "c".to_string()]);
//!
//! // select from the attributes
//! let selected_attrs = attributes.select(vec![vec![], vec![0, 1], vec![0, 1]]);
use std::{fmt::Display, ops::Deref};

// use wa_serde_derive::{Deserialize, Serialize};

use amcl_wrapper::field_elem::FieldElement;
use cid::multibase;

const RAW: u64 = 0x55;
const SHAKE256_LEN: usize = 48;

#[derive(Debug, Clone, PartialEq)]
pub struct Attribute(cid::Cid);

impl Attribute {
    pub fn new(val: impl AsRef<[u8]>) -> Self {
        attribute(val)
    }

    pub fn hash(&self) -> &multihash::Multihash {
        self.0.hash()
    }

    pub fn to_string_of_base(
        &self,
        base: multibase::Base,
    ) -> core::result::Result<String, cid::Error> {
        self.0.to_string_of_base(base)
    }
}

// implement trait `Display` for type `attributes::Attribute`
impl Display for Attribute {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0.to_string())
    }
}

/// Converts any type that can be converted to a byte slice into a Content Identifier (CID)
/// using the SHAKE256 hash function with length 48.
///
/// This is an efficiency step to avoid re-hashing the raw input.
pub fn attribute(attribute: impl AsRef<[u8]>) -> Attribute {
    // pre hash the input
    let mut digest = [0u8; SHAKE256_LEN];
    let mhash = shake_multihash::shake256_mhash(attribute.as_ref(), &mut digest).unwrap();
    Attribute(cid::Cid::new_v1(RAW, mhash))
}

/// Generate an attribute from a CID
/// Check to verify that the CID is a SHAKE256 hash with length 48
///
/// Alternatively, use `TryFrom` to convert from a `CID` to an `Attribute`:
/// ```rs
/// use std::convert::TryFrom;
/// let attribute = Attribute::try_from(cid)?;
/// ```
pub fn from_cid(cid: cid::Cid) -> Option<Attribute> {
    if cid.codec() == RAW
        && cid.hash().code() == shake_multihash::SHAKE_256_HASH_CODE
        && cid.hash().digest().len() == SHAKE256_LEN
    {
        Some(Attribute(cid))
    } else {
        None
    }
}

// implement TryFrom Cid to Attribute
impl TryFrom<cid::Cid> for Attribute {
    type Error = &'static str;

    fn try_from(cid: cid::Cid) -> Result<Self, Self::Error> {
        if cid.codec() == RAW
            && cid.hash().code() == shake_multihash::SHAKE_256_HASH_CODE
            && cid.hash().digest().len() == SHAKE256_LEN
        {
            Ok(Attribute(cid))
        } else {
            Err("Invalid Cid")
        }
    }
}

// deref convert `&Attribute` to `&[u8]`
impl Deref for Attribute {
    type Target = [u8];
    fn deref(&self) -> &Self::Target {
        self.0.hash().digest()
    }
}

impl From<Attribute> for cid::Cid {
    fn from(attribute: Attribute) -> Self {
        attribute.0
    }
}

impl From<Attribute> for Vec<u8> {
    fn from(attribute: Attribute) -> Self {
        attribute.0.to_bytes()
    }
}

impl From<Attribute> for String {
    fn from(attribute: Attribute) -> Self {
        attribute.0.to_string()
    }
}

impl From<Attribute> for multihash::Multihash {
    fn from(attribute: Attribute) -> Self {
        multihash::Multihash::from_bytes(attribute.0.hash().digest()).unwrap()
    }
}

impl TryFrom<Attribute> for FieldElement {
    type Error = amcl_wrapper::errors::SerzDeserzError;

    fn try_from(attribute: Attribute) -> Result<Self, Self::Error> {
        FieldElement::from_bytes(attribute.0.hash().digest())
    }
}

impl AsRef<[u8]> for Attribute {
    fn as_ref(&self) -> &[u8] {
        self.0.hash().digest()
    }
}

impl std::str::FromStr for Attribute {
    type Err = cid::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Attribute::new(s))
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn test_create_attribute() {
        let some_test_attr = "read";
        let read_attr = Attribute::new(some_test_attr); // using the new method
        let create_attr = Attribute::from_str(some_test_attr).unwrap(); // using the from method
        let update_attr = attribute(some_test_attr); // using the attribute convenience method

        // all CIDs shoudl match
        assert_eq!(read_attr, create_attr);
        assert_eq!(read_attr, update_attr);
        assert_eq!(create_attr, update_attr);
    }
}
