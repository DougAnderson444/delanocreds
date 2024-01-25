//! Module to hold external offer APIs.
//!
//! When data is passed around from the User Interface, it's going from URL to URL, and
//! from WIT component to IT component. This module holds the data structures that are
//! used to format and serialize the data as it's passed around.
//!
//! WIT interface types are kebab case, and all types must be serializable and deserializable.

use super::*;

use base64ct::{Base64UrlUnpadded, Encoding};
use serde::{Deserialize, Serialize};

/// Offers will be sent to others over the wire, and injested by Wasm Interface types.
/// When this happens, we need to serialize the bytes in accordance with WIT so they can be
/// Deserialized on the other end, in this case, kebab-case.
#[derive(Debug, Clone, Serialize, Deserialize)]
// #[serde(tag = "tag", content = "val")]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum Context {
    Offer {
        /// The Credential bytes
        cred: Vec<u8>,
        /// The Hints
        hints: Vec<Vec<attributes::AttributeKOV>>,
    },
    Proof {
        /// The proof byte vector
        proof: Vec<u8>,
        /// The selected Entry attributes, in the right sequence to be verified.
        selected: Vec<Vec<Vec<u8>>>,
        /// The selected Entry Attributes are hashes, so we can provide the preimage here. The UI
        /// can then compare these preimage hints to the selected values to verify they match.
        preimages: Vec<Vec<attributes::AttributeKOV>>,
    },
}

impl Context {
    /// Function that serializes the Context to bytes (serde_json) then encodes it as base64.
    pub fn to_urlsafe(&self) -> String {
        let serialized = serde_json::to_string(&self).unwrap_or_default();
        Base64UrlUnpadded::encode_string(serialized.as_bytes())
    }
}

#[cfg(test)]
mod tests {
    use delanocreds::CBORCodec;
    use delanocreds::{Credential, Issuer, Nym};

    use super::*;

    /// A dummy Credential for testing and development
    /// Created from [delanocreds::Credential]
    fn dummy_cred() -> Credential {
        let issuer = Issuer::default();
        let nym = Nym::new();

        let root_entry = delanocreds::Entry::new(&[]);
        let nonce = delanocreds::Nonce::default();
        // Issue the (Powerful) Root Credential to Alice
        let cred = match issuer
            .credential()
            .with_entry(root_entry.clone())
            .max_entries(&3)
            .issue_to(&nym.nym_proof(&nonce), Some(&nonce))
        {
            Ok(cred) => cred,
            Err(e) => panic!("Error issuing cred: {:?}", e),
        };
        cred
    }
    #[test]
    fn test_dummy_cred() {
        let cred = dummy_cred().to_bytes();

        // print the bytes
        println!("{:?}", cred);
    }
}
