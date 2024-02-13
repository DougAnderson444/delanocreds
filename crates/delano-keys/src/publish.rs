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
/// use delano_keys::publish::{PublishingKey, OfferedPreimages, IssuerKey};
///
/// let key = PublishingKey::new(
///                    &OfferedPreimages(&vec![b"hello".to_vec(), b"world".to_vec()]),
///                    &IssuerKey(&vec![b"123".to_vec()]))
///                    .cid();
/// assert_eq!(key.to_string().starts_with("baf"), true);
/// ```
#[derive(serde::Serialize)]
pub struct PublishingKey<'a, T> {
    preimages: &'a OfferedPreimages<'a, T>,
    /// The Issuer's Verification Key
    issuer_key: &'a IssuerKey<'a>,
}

/// Newtype wrapper to ensure client puts the correct type into the PublishingKey
/// These are the preimage attributes that were given with the invite offer.
/// The Offer preimages are only the values for the first Entry, so we only need a Vec<T>
#[derive(serde::Serialize)]
pub struct OfferedPreimages<'a, T>(pub &'a Vec<T>);

/// The Issier's verification Key, wrapped in a Newtype to ensure client puts the correct type into the PublishingKey
#[derive(serde::Serialize)]
pub struct IssuerKey<'a>(pub &'a Vec<Vec<u8>>);

impl<'a, T> PublishingKey<'a, T>
where
    T: serde::Serialize,
{
    /// Creates a new PublishingKey builder
    ///
    /// # Example
    ///
    /// ```
    /// use delano_keys::publish::{PublishingKey, OfferedPreimages, IssuerKey};
    /// let cid = PublishingKey::new(
    ///                     &OfferedPreimages(&vec![b"hello".to_vec(), b"world".to_vec()]),
    ///                     &IssuerKey(&vec![b"123".to_vec()]))
    ///                     .cid();
    ///
    /// assert_eq!(cid.to_string().starts_with("baf"), true);
    /// ```
    pub fn new(preimages: &'a OfferedPreimages<T>, issuer_key: &'a IssuerKey) -> Self {
        Self {
            preimages,
            issuer_key,
        }
    }

    // Hashes the Serialized value of Self
    pub fn cid(&self) -> Cid {
        const RAW: u64 = 0x55;
        let bytes = serde_json::to_vec(&self).unwrap_or_default();
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
        let cid = PublishingKey::new(&OfferedPreimages(&entry), &IssuerKey(&issuer_key)).cid();

        assert_eq!(cid.to_string().starts_with("baf"), true);
    }
}
