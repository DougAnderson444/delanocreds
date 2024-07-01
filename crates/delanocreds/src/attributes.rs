//! A crate for creating:
//! - Individual [Attribute], a 32 byte Sha2-256 [cid::Cid] (<https://cid.ipfs.tech/>) generated from bytes (likely from a string, could be an image or doc)
//! - [crate::entry::Entry] is a vector of [Attribute]s up to [crate::keypair::MaxCardinality]
//!
//! # Attributes API
//! ```rust
//! use delanocreds::Attribute;
//!
//! // create a new Attribute
//! let some_test_attr = "read";
//! let read_attr = Attribute::new(some_test_attr); // using the new method
//! let create_attr = Attribute::from(some_test_attr); // using the from method
//! let update_attr = Attribute::from(some_test_attr);
//!
//! // Try Attribute from cid. Fails if not SHA2-256 hash with length 48
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
//! `attributes.push(vec!["a".to_string(), "b".to_string(), "c".to_string()]);`
//!
//! // select from the attributes
//! `let selected_attrs = attributes.select(vec![vec![], vec![0, 1], vec![0, 1]]);`
use crate::error::Error;
use cid::multibase;
use cid::multihash;
use cid::multihash::{Code, MultihashDigest};
use cid::Cid;
use std::{fmt::Display, ops::Deref};

const RAW: u64 = 0x55;
const DIGEST_LEN: usize = 32;
const SHA2_256: u64 = 0x12;

/// Attribute is wrapper around a [Cid] of the bytes of the attribute
#[derive(Debug, Clone, PartialEq, Default)]
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
            && cid.hash().code() == SHA2_256
            && cid.hash().digest().len() == DIGEST_LEN
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
        write!(f, "{}", self.0)
    }
}

/// Converts any type that can be converted to a byte slice into a Content Identifier (CID)
/// using the SHAKE256 hash function with length 48.
pub fn attribute(bytes: impl AsRef<[u8]>) -> Attribute {
    let mhash = Code::Sha2_256.digest(bytes.as_ref());
    Attribute(Cid::new_v1(RAW, mhash))
}

// implement TryFrom Cid to Attribute
impl TryFrom<&cid::Cid> for Attribute {
    type Error = &'static str;

    fn try_from(cid: &cid::Cid) -> Result<Self, Self::Error> {
        if cid.codec() == RAW
            && cid.hash().code() == SHA2_256
            && cid.hash().digest().len() == DIGEST_LEN
        {
            Ok(Attribute(*cid))
        } else {
            Err("Invalid Cid")
        }
    }
}

/// Try from an arbitrary vector of bytes
impl TryFrom<Vec<u8>> for Attribute {
    type Error = Error;

    fn try_from(bytes: Vec<u8>) -> Result<Self, Self::Error> {
        let cid = Cid::try_from(bytes)?;
        Ok(Attribute(cid))
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
        multihash::Multihash::from_bytes(attribute.0.hash().digest())
            .expect("correct length of digest for this multihash")
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
