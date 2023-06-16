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
//! # Attributes API
//! ```rust
//! use delanocreds::attributes::{Attribute, attribute};
//!
//! // create a new Attribute
//! let some_test_attr = "read";
//! let read_attr = Attribute::new(some_test_attr); // using the new method
//! let create_attr = Attribute::from(some_test_attr); // using the from method
//! let update_attr = attribute(some_test_attr); // using the attribute convenience method
//!
//! // Try Attribute from cid. Fails if not SHAKE256 hash with length 48
//! let attr_from_cid = Attribute::try_from(read_attr.cid()).unwrap();
//! assert_eq!(read_attr, attr_from_cid);
//!
//! // Attribute from_cid
//! let attr_from_cid = Attribute::from_cid(&read_attr).unwrap();
//! assert_eq!(read_attr, attr_from_cid);
//! ```
//!
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
    /// Create a new Attribute from a string
    pub fn new(val: impl AsRef<[u8]>) -> Self {
        attribute(val)
    }

    /// Returns the Multihash of the Attribute
    pub fn hash(&self) -> &multihash::Multihash {
        self.0.hash()
    }

    /// Returns the bytes representation of the hash digest
    pub fn digest(&self) -> &[u8] {
        self.0.hash().digest()
    }

    /// Returns teh CID of the Attribute
    pub fn cid(&self) -> &cid::Cid {
        &self.0
    }

    /// Returns the string representation of the Attribute CID
    /// given the specified base (base64, base58, base36, etc)
    pub fn to_string_of_base(
        &self,
        base: multibase::Base,
    ) -> core::result::Result<String, cid::Error> {
        self.0.to_string_of_base(base)
    }

    /// Generate an attribute from a CID
    /// Check to verify that the CID is a SHAKE256 hash with length 48
    ///
    /// Alternatively, use `TryFrom` to convert from a `CID` to an `Attribute`:
    /// ```rs
    /// use std::convert::TryFrom;
    /// let attribute = Attribute::try_from(cid)?;
    /// ```
    pub fn from_cid(cid: &cid::Cid) -> Option<Self> {
        if cid.codec() == RAW
            && cid.hash().code() == shake_multihash::SHAKE_256_HASH_CODE
            && cid.hash().digest().len() == SHAKE256_LEN
        {
            Some(Attribute(*cid))
        } else {
            None
        }
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
pub fn attribute(bytes: impl AsRef<[u8]>) -> Attribute {
    // pre hash the input
    let mut digest = [0u8; SHAKE256_LEN];
    let mhash = shake_multihash::shake256_mhash(bytes.as_ref(), &mut digest).expect(
        "SHAKE256_LEN to be 48, which is less then 64 required by multihash::MultihashGeneric<64>",
    );
    Attribute(cid::Cid::new_v1(RAW, mhash))
}

// implement TryFrom Cid to Attribute
impl TryFrom<&cid::Cid> for Attribute {
    type Error = &'static str;

    fn try_from(cid: &cid::Cid) -> Result<Self, Self::Error> {
        if cid.codec() == RAW
            && cid.hash().code() == shake_multihash::SHAKE_256_HASH_CODE
            && cid.hash().digest().len() == SHAKE256_LEN
        {
            Ok(Attribute(*cid))
        } else {
            Err("Invalid Cid")
        }
    }
}

impl Deref for Attribute {
    type Target = cid::Cid;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<String> for Attribute {
    fn from(s: String) -> Self {
        Attribute::new(s)
    }
}

impl From<&str> for Attribute {
    fn from(s: &str) -> Self {
        Attribute::new(s)
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

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_create_attribute() {
        let some_test_attr = "read";
        let read_attr = Attribute::new(some_test_attr); // using the new method
        let create_attr = Attribute::from(some_test_attr); // using the from method
        let update_attr = attribute(some_test_attr); // using the attribute convenience method

        // Try Attribute from cid
        let attr_from_cid = Attribute::try_from(read_attr.cid()).unwrap();
        assert_eq!(read_attr, attr_from_cid);

        // Attribute from_cid
        let attr_from_cid = Attribute::from_cid(&read_attr).unwrap();
        assert_eq!(read_attr, attr_from_cid);

        // all CIDs shoudl match
        assert_eq!(read_attr, create_attr);
        assert_eq!(read_attr, update_attr);
        assert_eq!(create_attr, update_attr);
    }
}
