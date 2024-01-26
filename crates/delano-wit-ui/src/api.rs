//! Module to hold external offer APIs.
//!
//! When data is passed around from the User Interface, it's going from URL to URL, and
//! from WIT component to IT component. This module holds the data structures that are
//! used to format and serialize the data as it's passed around.
//!
//! WIT interface types are kebab case, and all types must be serializable and deserializable.

use self::attributes::AttributeKOV;

use super::*;

use base64ct::{Base64UrlUnpadded, Encoding};
use serde::{Deserialize, Serialize};

/// Loaded Offers and Proofs will be sent to others over the wire, and injested by Wasm Interface types.
/// When this happens, we need to serialize the bytes in accordance with WIT so they can be
/// Deserialized on the other end, in this case, kebab-case.
#[derive(Default, Debug, Clone, Serialize, Deserialize)]
// #[serde(tag = "tag", content = "val")]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum Loaded {
    Offer {
        /// The Credential bytes
        cred: Vec<u8>,
        /// The Hints
        hints: Vec<Vec<AttributeKOV>>,
    },
    Proof {
        /// The proof byte vector
        proof: Vec<u8>,
        /// The selected Entry attributes, in the right sequence to be verified.
        selected: Vec<Vec<Vec<u8>>>,
        /// The selected Entry Attributes are hashes, so we can provide the preimage here. The UI
        /// can then compare these preimage hints to the selected values to verify they match.
        preimages: Vec<Vec<AttributeKOV>>,
    },
    #[default]
    None,
}

impl Loaded {
    /// Function that serializes the Context to bytes (serde_json) then encodes it as base64.
    pub fn to_urlsafe(&self) -> String {
        let serialized = serde_json::to_string(&self).unwrap_or_default();
        Base64UrlUnpadded::encode_string(serialized.as_bytes())
    }

    /// Decode the base64 string, then deserialize the bytes into a Context.
    pub fn from_urlsafe(base64: &str) -> Self {
        let decoded = Base64UrlUnpadded::decode_vec(base64).unwrap_or_default();
        serde_json::from_slice(&decoded).unwrap_or_default()
    }
}

impl StructObject for Loaded {
    /// Remember to add match arms for any new fields.
    fn get_field(&self, name: &str) -> Option<Value> {
        match name {
            "id" => Some(Value::from(utils::rand_id())),
            "context" => match self {
                Self::Offer { .. } => {
                    // We do this so we get the exact name of the context, any changes
                    // will trigger compile error.
                    let context_name =
                        context_types::Context::Editattribute(context_types::Kvctx {
                            ctx: context_types::Entry {
                                idx: Default::default(),
                                val: context_types::Kovindex::Key(Default::default()),
                            },
                            value: Default::default(),
                        });
                    Some(Value::from(util::variant_string(context_name)))
                }
                _ => None,
            },
            "cred" => match self {
                Self::Offer { cred, .. } => Some(Value::from(cred.clone())),
                _ => None,
            },
            "hints" => match self {
                Self::Offer { hints, .. } => Some(Value::from(hints.clone())),
                _ => None,
            },
            "proof" => match self {
                Self::Proof { proof, .. } => Some(Value::from(proof.clone())),
                _ => None,
            },
            "selected" => match self {
                Self::Proof { selected, .. } => Some(Value::from(selected.clone())),
                _ => None,
            },
            "preimages" => match self {
                Self::Proof { preimages, .. } => Some(Value::from(preimages.clone())),
                _ => None,
            },
            _ => None,
        }
    }
    /// So that debug will show the values
    fn static_fields(&self) -> Option<&'static [&'static str]> {
        Some(&["cred", "hints", "proof", "selected", "preimages"])
    }
}

impl From<Option<String>> for Loaded {
    fn from(maybe_loadables: Option<String>) -> Self {
        match maybe_loadables {
            Some(loadables) => Self::from(loadables),
            None => Self::default(),
        }
    }
}

impl From<String> for Loaded {
    fn from(base64: String) -> Self {
        // There are two places this can fail: decoding from base64, and deserializing the bytes.
        // If either fails, return Context::None
        Loaded::from_urlsafe(&base64)
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
