//! The Protocol for creating a Key from AttributeKOV and Issuer Key
//! Hash the serialized value of the Key struct which holds the AttributeKOV and Issuer Key
use cid::multibase;
use cid::multihash::{Code, MultihashDigest};
use cid::Cid;

/// A Key for publishing an AttributeKOV and Issuer Key
/// The Key is hashed to a CID, which can be published to a network for discovery.
///
/// # Example
///
/// ```
/// use delano_keys::publish::PublishingKey;
/// let key = PublishingKey::default()
///    .with_attributes(&vec![vec![b"hello".to_vec(), b"world".to_vec()]])
///    .with_issuer_key(&vec![b"123".to_vec()])
///    .cid();
///
/// assert_eq!(key.to_string().starts_with("baf"), true);
/// ```
#[derive(serde::Serialize, PartialEq, Eq, Debug)]
pub struct PublishingKey<'a, T>
where
    T: AsRef<[u8]>,
{
    // Attribute preimages, a Vec of Vac of any type that impls AsRef<[u8]>
    attributes: Option<&'a Vec<Vec<T>>>,
    issuer_key: Option<&'a Vec<Vec<u8>>>,
}

impl<'a, T> Default for PublishingKey<'a, T>
where
    T: AsRef<[u8]>,
{
    fn default() -> Self {
        Self {
            attributes: None,
            issuer_key: None,
        }
    }
}

impl<'a, T> PublishingKey<'a, T>
where
    T: AsRef<[u8]> + serde::Serialize,
{
    /// Creates a new PublishingKey builder
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the attributes
    pub fn with_attributes(mut self, attributes: &'a Vec<Vec<T>>) -> Self {
        self.attributes = Some(attributes);
        self
    }

    /// Set the issuer key
    pub fn with_issuer_key(mut self, issuer_key: &'a Vec<Vec<u8>>) -> Self {
        self.issuer_key = Some(issuer_key);
        self
    }

    // Hashes the Serialized value of Self using Borsh bytes
    pub fn cid(&self) -> Cid {
        const RAW: u64 = 0x55;
        let bytes = bincode::serialize(self).unwrap();
        let hash = Code::Sha2_256.digest(&bytes);
        Cid::new_v1(RAW, hash)
    }

    /// Returns the string representation of the Attribute CID
    /// given the specified base (base64, base58, base36, etc)
    pub fn to_string_of_base(
        &self,
        base: multibase::Base,
    ) -> core::result::Result<String, cid::Error> {
        self.cid().to_string_of_base(base)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_with() {
        let attrs = vec![b"a".to_vec(), "b".as_bytes().to_vec()];
        let entry = vec![attrs.clone()];
        let issuer_key = vec![b"123".to_vec()];
        let cid = PublishingKey::default()
            .with_attributes(&entry)
            .with_issuer_key(&issuer_key)
            .cid();

        assert_eq!(cid.to_string().starts_with("baf"), true);
    }
}
