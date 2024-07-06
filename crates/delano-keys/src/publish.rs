//! The Protocol for creating a Key from AttributeKOV and Issuer Key
//! Hash the serialized value of the Key struct which holds the AttributeKOV and Issuer Key
use crate::vk::VKCompressed;
use cid::multibase;
use cid::multihash;
use cid::CidGeneric;
use sha2::{Digest, Sha256};

const SHA2_256: u64 = 0x12;

/// A Builder of the Key used for publishing. During the build process,
/// the Key is hashed to a CID, which can be published to a network for discovery with it's corresponding value.
///
/// # Example
///
/// ```
/// use delano_keys::publish::{PublishingKey, OfferedPreimages, IssuerKey};
/// use delano_keys::vk::VKCompressed;
///
/// let key = PublishingKey::new(
///                    &OfferedPreimages(&vec![b"hello".to_vec(), b"world".to_vec()]),
///                    &IssuerKey(&vec![VKCompressed::G1(b"123".to_vec()), VKCompressed::G2(b"456".to_vec())]))
///                    .cid();
/// assert_eq!(key.to_string().starts_with("baf"), true);
/// ```
#[derive(serde::Serialize, Debug)]
pub struct PublishingKey<'a, T> {
    preimages: &'a OfferedPreimages<'a, T>,
    /// The Issuer's Verification Key
    issuer_key: &'a IssuerKey<'a>,
}

/// Newtype wrapper to ensure client puts the correct type into the PublishingKey
/// These are the preimage attributes that were given with the invite offer.
/// The Offer preimages are only the values for the first Entry, so we only need a Vec<T>
#[derive(serde::Serialize, Debug)]
pub struct OfferedPreimages<'a, T>(pub &'a Vec<T>);

/// The Issuer's Compressed Verification Key (VK), wrapped in a Newtype to ensure client puts the correct type into the PublishingKey
#[derive(serde::Serialize, Debug)]
pub struct IssuerKey<'a>(pub &'a Vec<VKCompressed>);

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
    /// use delano_keys::vk::VKCompressed;
    ///
    /// let cid = PublishingKey::new(
    ///                     &OfferedPreimages(&vec![b"hello".to_vec(), b"world".to_vec()]),
    ///                     &IssuerKey(&vec![VKCompressed::G1(b"123".to_vec()), VKCompressed::G2(b"456".to_vec())]))
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

    /// Hashes the Serialized value of Self into a [CidGeneric]
    pub fn cid(&self) -> CidGeneric<32> {
        const RAW: u64 = 0x55;
        let bytes = serde_json::to_vec(&self).unwrap_or_default();
        let hash = Sha256::digest(&bytes);
        let mhash = multihash::Multihash::wrap(SHA2_256, &hash).unwrap();
        CidGeneric::new_v1(RAW, mhash)
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
        let issuer_key = vec![
            VKCompressed::G1(vec![1, 2, 3]),
            VKCompressed::G2(vec![4, 5, 6]),
        ];
        let cid = PublishingKey::new(&OfferedPreimages(&entry), &IssuerKey(&issuer_key)).cid();

        assert_eq!(
            cid.to_string(),
            "bafkreigtv7srjv6ymhh2ljxy7uteru2heti6vxf6xhcmdpgb3pzaek77uy"
        );
    }
}
