//! Module to hold external state for loaded offer and proof APIs.
//!
//! When data is passed around from the User Interface, it's going from URL to URL, and
//! from WIT component to WIT component. This module holds the data structures that are
//! used to format and serialize the data as it's passed around.
//!
//! WIT interface types are kebab case, and all types must be serializable and deserializable.

use self::attributes::{AttributeKOV, Hint};

use super::*;

use base64ct::{Base64UrlUnpadded, Encoding};
use chrono::prelude::*;
use delano_keys::publish::PublishingKey;
use delanocreds::Attribute;
use serde::{Deserialize, Serialize};

/// History is created when an offer is made, and is used to track the status of the offer.
/// It's a list of the offers that have been made, and the status of each offer.
#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub(crate) struct History {
    /// The attributes of this offer
    pub(crate) attributes: Vec<Vec<AttributeKOV>>,
    /// The [delano_keys::VK] used to sign the offer
    pub(crate) issuer_vk: Vec<Vec<u8>>,
    /// Publishing Key
    pub(crate) publish_key: Vec<u8>,
    /// The offer bytes as urlsafe base64
    offer: String,
    /// Timestamp
    timestamp: String,
}

/// State is the data that was [Loaded] and the [CredentialStruct] that we build using that loaded
/// and added data.
#[derive(Default, Debug, Clone)]
pub(crate) struct State {
    /// Tracks the generate history of invite offers, so we can check status and get latest values.
    pub(crate) history: Vec<History>,
    /// The loaded data
    pub(crate) loaded: Loaded,
    /// The CredentialStruct that we build from the loaded data
    pub(crate) builder: CredentialStruct,
    /// The offer
    pub(crate) offer: Option<String>,
    /// The proof, if any
    pub(crate) proof: Option<String>,
}

impl State {
    /// Creates a new State from the LAST_STATE
    pub(crate) fn from_latest() -> Self {
        let last = { LAST_STATE.lock().unwrap().clone().unwrap_or_default() };
        Self {
            history: last.state.history,
            loaded: last.state.loaded,
            builder: last.state.builder,
            // Offer is only generated when user triggers generation
            offer: Default::default(),
            // Proof is only generated when user triggers generation
            proof: Default::default(),
        }
    }

    /// Takes the given attrs and update credential entries and hints.
    pub(crate) fn update_attributes(mut self, kvctx: &context_types::Kvctx) -> Self {
        self.builder.edit_attribute(kvctx);

        // Update the hints to match the newly edited values
        if let api::Loaded::Offer { hints, cred } = &mut self.loaded {
            hints
                .iter_mut()
                .zip(self.builder.entries.iter())
                .for_each(|(hint, entry)| {
                    *hint = entry.clone();
                });
            self.loaded = api::Loaded::Offer {
                cred: cred.to_vec(),
                hints: hints.clone(),
            };
        }
        self
    }

    /// Mutates and returns Self after calling offer() and handling any results
    pub(crate) fn with_offer(mut self) -> Self {
        self.offer = self.offer().unwrap_or_default();
        self
    }

    /// Mutates and returns Self after calling proof() and handling any results
    pub(crate) fn with_proof(mut self) -> Self {
        let proof = match self.proof() {
            Ok(proof) => proof,
            Err(e) => Some(e),
        };
        println!("Proof: {:?}", proof);
        self.proof = proof;
        self
    }

    /// Generate offer from this State is there is nothing loaded.
    pub(crate) fn offer(&mut self) -> Result<Option<String>, String> {
        match self.loaded {
            Loaded::None => {
                // use self.credential
                let cred = self
                    .builder
                    .issue()
                    .map_err(|e| format!("Issue failed in offer: {}", e))?;
                let offer = self
                    .builder
                    .offer(cred)
                    .map_err(|e| format!("Offer failed in offer: {}", e))?;

                // convert the attributes to hint
                let hints: Vec<Vec<AttributeKOV>> = self
                    .builder
                    .entries
                    .iter()
                    .map(|a| {
                        a.iter()
                            .map(|a| Hint::from(a.clone()).into())
                            .collect::<Vec<_>>()
                    })
                    .collect::<Vec<_>>();

                let offer = crate::api::Loaded::Offer { cred: offer, hints };

                // We also want to track this offer in the history
                // So we can 1) Look up the key for values, and
                // 2) Remind the person with hints/attrs if needed
                //
                // We need:
                // 1) The attributes as Vec<Vec<AttributeKOV>>, for reference
                // 2) The Publishing Key from delano-keys crate, for lookups
                // 3) Timestamp (for info only), for reference
                let Ok(issuer_key) = wallet::actions::issuer_public() else {
                    return Err("Issuer public key failed".to_string());
                };
                let publish_key = PublishingKey::default()
                    .with_attributes(
                        &self
                            .builder
                            .entries
                            .iter()
                            .map(|a| a.iter().map(|a| a.into_bytes()).collect::<Vec<Vec<u8>>>())
                            .collect::<Vec<Vec<Vec<u8>>>>(),
                    )
                    .with_issuer_key(&issuer_key)
                    .cid();

                let offered = offer
                    .to_urlsafe()
                    .map_err(|e| format!("URLSafe offer failed: {:?}", e).to_string())?;

                let history = History {
                    attributes: self.builder.entries.clone(),
                    issuer_vk: issuer_key,
                    publish_key: publish_key.into(),
                    offer: offered.clone(),
                    timestamp: Utc::now().to_rfc3339(),
                };

                self.history.push(history);

                Ok(Some(offered))
            }
            _ => Ok(None),
        }
    }

    /// Generate proof from this State if there is an offer loaded.
    fn proof(&self) -> Result<Option<String>, String> {
        match &self.loaded {
            Loaded::Offer { cred, .. } => {
                let accepted = wallet::actions::accept(&cred)?;
                let cred = self.builder.extend(accepted)?;
                let proof_package = self.builder.proof_package(&cred)?;
                match proof_package.verify() {
                    Ok(true) => Ok(Some(proof_package.to_urlsafe().map_err(|e| e.to_string())?)),
                    Ok(false) => Err("That proof is invalid!".to_string()),
                    Err(e) => Err(format!("Verify function failed: {}", e)),
                }
            }
            _ => Ok(None),
        }
    }

    pub(crate) fn with_cred(mut self, builder: CredentialStruct) -> Self {
        self.builder = builder;
        self
    }
}

impl StructObject for State {
    /// Remember to add match arms for any new fields.
    fn get_field(&self, name: &str) -> Option<Value> {
        // TODO: Show issues/errors as error variant?
        // if offer or proof have messages, show them?
        match name {
            "id" => Some(Value::from(rand_id())),
            "loaded" => Some(Value::from(self.loaded.clone())),
            "credential" => Some(Value::from(self.builder.clone())),
            "offer" => match self.offer {
                Some(ref offer) => Some(Value::from(offer.clone())),
                None => Some(Value::from("No offer generated")),
            },
            "proof" => match self.proof {
                Some(ref proof) => Some(Value::from(proof.clone())),
                None => Some(Value::from("No proof generated")),
            },
            "history" => Some(Value::from_serializable(&self.history.clone())),
            _ => None,
        }
    }
    /// So that debug will show the values
    fn static_fields(&self) -> Option<&'static [&'static str]> {
        Some(&["id", "loaded", "credential", "offer", "proof"])
    }
}

impl From<String> for State {
    fn from(base64: String) -> Self {
        // Default of Loaded is None
        let decoded = Base64UrlUnpadded::decode_vec(&base64).unwrap_or_default();
        let loaded = serde_json::from_slice(&decoded).unwrap_or_default();
        Self {
            history: Default::default(),
            loaded: serde_json::from_slice(&decoded).unwrap_or_default(),
            builder: CredentialStruct::from(&loaded),
            offer: Default::default(),
            proof: Default::default(),
        }
    }
}

impl From<Option<String>> for State {
    fn from(maybe_loadables: Option<String>) -> Self {
        match maybe_loadables {
            Some(loadables) => Self::from(loadables),
            None => Self::default(),
        }
    }
}

/// Loaded Offers and Proofs will be serialized, encoded as base64, and sent to others over the wire, and injested by the reciever.
/// We can keep th codec and serde here in the component rather than handling it in JavaScript.
/// It'll be faster and cleaner, and minimize the amount of code we need to write in JavaScript.
#[derive(Default, Debug, Clone, Serialize, Deserialize)]
// #[serde(tag = "tag", content = "val")]
// #[serde(rename_all = "kebab-case")]
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
        /// The selected Entry attributes, as CID bytes, in the right sequence.
        selected: Vec<Vec<Vec<u8>>>,
        /// The selected Entry Attributes are hashes, so we can provide the preimage here. The UI
        /// can then compare these preimage hints to the selected values to verify they match.
        preimages: Vec<Vec<AttributeKOV>>,
        /// We will also include the Issuer's Public Parameters from the Credential, so the holder
        /// can verify against the Issuer's public key.
        issuer_public: Vec<u8>,
    },
    #[default]
    None,
}

impl Base64JSON for Loaded {}

impl Loaded {
    /// Verify if self is Loaded::Proof
    pub fn verify(&self) -> Result<bool, String> {
        // To verify proofs, selected, and preimages to be validated, we need:
        // 1) The preimages need to be hashed and compared to the selected. If they match,
        //    preimages are valid.
        // 2) The proof and selected need to be run through wallet:;actions::verify to see if
        //    they are valid.
        // 3) TODO: The user should also check the Issuer's public key included in the proof
        //    against the Issuer's public key they have on file / find online (web resolve).
        match self {
            Self::Proof {
                selected,
                preimages,
                proof,
                issuer_public,
            } => {
                // Step 1) Hash preimages & compare to selected
                // Iterate through each preimage converting them into delanocreds::Attribute,
                // then compare them to the selected.
                let preimages_valid =
                    preimages
                        .iter()
                        .zip(selected.iter())
                        .all(|(preimage, selected)| {
                            // Convert the preimage into a delanocreds::Attribute
                            let preimage = preimage
                                .iter()
                                .map(|kov| Attribute::from(kov.to_string()).to_bytes())
                                .collect::<Vec<Vec<u8>>>();

                            // Hash the preimage
                            // Compare the preimage hash to the selected
                            preimage == *selected
                        });

                // Step 2) Verify the proof using wallet::actions::verify
                let verifiables = wallet::actions::Verifiables {
                    proof: proof.clone(),
                    issuer_public: issuer_public.clone(),
                    nonce: None,
                    selected: selected.clone(),
                };
                let Ok(verification_result) = wallet::actions::verify(&verifiables) else {
                    return Err("Verify failed. Were your verifiables valid?".to_string());
                };
                // If both are true, then the proof is valid.
                Ok(preimages_valid && verification_result)
            }
            _ => Err("Loaded is not a Proof".to_string()),
        }
    }
}

impl StructObject for Loaded {
    /// Remember to add match arms for any new fields.
    fn get_field(&self, name: &str) -> Option<Value> {
        match name {
            "id" => Some(Value::from(rand_id())),
            "context" => match self {
                // Offer is the only Loaded context that can be edited
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
            "hints" => match self {
                Self::Offer { hints, .. } => Some(Value::from(hints.clone())),
                _ => None,
            },
            "preimages" => match self {
                Self::Proof { preimages, .. } => Some(Value::from(preimages.clone())),
                _ => None,
            },
            "verified" => match self.verify() {
                Ok(verified) => Some(Value::from(verified)),
                Err(e) => Some(Value::from(e)),
            },
            _ => None,
        }
    }
    /// So that debug will show the values
    fn static_fields(&self) -> Option<&'static [&'static str]> {
        Some(&["context", "hints", "preimages", "verified"])
    }
}

impl From<Loaded> for wurbo::prelude::Value {
    fn from(loaded: Loaded) -> Self {
        Value::from_struct_object(loaded)
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
        // If either fails, return the default of `None`
        Loaded::from_urlsafe(&base64).unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use delanocreds::CBORCodec;
    use delanocreds::{Credential, Issuer, Nym};

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
