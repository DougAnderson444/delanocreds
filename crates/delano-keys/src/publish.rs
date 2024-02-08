//! The Protocol for creating a Key from AttributeKOV and Issuer Key
//! Hash the serialized value of the Key struct which holds the AttributeKOV and Issuer Key
use cid::multibase;
use cid::multihash::{Code, MultihashDigest};
use cid::Cid;

#[derive(borsh::BorshSerialize, PartialEq, Debug)]
pub struct PublishingKey<T>
where
    T: AsRef<[u8]>,
{
    // Attribute preimages, a Vec of Vac of any type that impls AsRef<[u8]>
    attributes: Vec<Vec<T>>,
    issuer_key: Vec<Vec<u8>>,
}

impl<T> Default for PublishingKey<T>
where
    T: AsRef<[u8]>,
{
    fn default() -> Self {
        Self {
            attributes: vec![],
            issuer_key: vec![],
        }
    }
}

impl<T> PublishingKey<T>
where
    T: AsRef<[u8]> + borsh::BorshSerialize,
{
    /// Set the attributes
    pub fn with_attributes(mut self, attributes: Vec<Vec<T>>) -> Self {
        self.attributes = attributes;
        self
    }

    /// Set the issuer key
    pub fn with_issuer_key(mut self, issuer_key: Vec<Vec<u8>>) -> Self {
        self.issuer_key = issuer_key;
        self
    }

    pub fn attributes(&self) -> &Vec<Vec<T>> {
        &self.attributes
    }

    pub fn issuer_key(&self) -> &Vec<Vec<u8>> {
        &self.issuer_key
    }

    // Hashes the Serialized value of Self using Borsh bytes
    pub fn cid(&self) -> Cid {
        const RAW: u64 = 0x55;
        let bytes = borsh::to_vec(self).unwrap();
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
        let key = PublishingKey::default().with_attributes(entry.clone());
        assert_eq!(key.attributes(), &entry);

        // hash to cid
        let cid = key.cid();
        // assert string starts with bafy
        println!("{}", cid.to_string());
        assert_eq!(cid.to_string().starts_with("baf"), true);
    }
}
