//! Module to hold external state for loaded offer and proof APIs.
//!
//! When data is passed around from the User Interface, it's going from URL to URL, and
//! from WIT component to WIT component. This module holds the data structures that are
//! used to format and serialize the data as it's passed around.
//!
//! WIT interface types are kebab case, and all types must be serializable and deserializable.
use self::{
    attributes::{AttributeKOV, Hint},
    util::{try_cbor, try_from_cbor},
    wallet::types,
};

use super::*;

use chrono::prelude::*;
use delano_events::{Context, Events, Provables, Publishables, SubscribeTopic};
use delano_keys::{
    publish::{IssuerKey, OfferedPreimages, PublishingKey},
    vk::VKCompressed,
};
use delanocreds::{
    keypair::{
        CredProofCompressed, IssuerPublicCompressed, NymProofCompressed, SignatureCompressed,
    },
    set_commits::ParamSetCommitmentCompressed,
    zkp::{DamgardTransformCompressed, PedersenCompressed, PedersenOpenCompressed},
    Attribute,
};
use serde::{Deserialize, Serialize};

/// History is created when an offer is made, and is used to track the status of the offer.
/// It's a list of the offers that have been made, and the status of each offer.
#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub(crate) struct History {
    /// The attributes of this offer
    pub(crate) attributes: Vec<Vec<AttributeKOV>>,
    /// The [delano_keys::VK] used to sign the offer
    pub(crate) issuer_vk: Vec<VKCompressed>,
    /// Publishing Key
    pub(crate) publish_key: String,
    /// The offer bytes as urlsafe base64
    offer: String,
    /// Timestamp
    timestamp: String,
    /// Latest data from the network messages
    latest: Value,
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
    pub(crate) proof: Option<Loaded>,
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
            Err(e) => {
                println!("Error generating proof: {}", e);
                return self;
            }
        };
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
                    .offer(&cred)
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

                let offer = crate::api::Loaded::Offer {
                    cred: try_cbor(&offer)?,
                    hints,
                };

                // serde_json serialize and emit offer
                let serialized = serde_json::to_string(&offer)
                    .map_err(|e| format!("Serialize offer failed: {}", e))?;

                wurbo_in::emit(&serialized);

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

                let issuer_vk = issuer_key
                    .vk
                    .iter()
                    .map(|vk| vk.into())
                    .collect::<Vec<VKCompressed>>();

                let publish_key = PublishingKey::new(
                    &delano_keys::publish::OfferedPreimages::<AttributeKOV>(
                        &self.builder.entries[0],
                    ),
                    &delano_keys::publish::IssuerKey(&issuer_vk),
                )
                .cid();

                let offered = offer
                    .to_urlsafe()
                    .map_err(|e| format!("URLSafe offer failed: {:?}", e).to_string())?;

                let history = History {
                    attributes: self.builder.entries.clone(),
                    issuer_vk,
                    publish_key: publish_key.into(),
                    offer: offered.clone(), // TODO: Why would this need to be serialized and encoded??
                    timestamp: Utc::now().to_rfc3339(),
                    latest: Default::default(),
                };

                self.history.push(history);

                subscribe_to_topic(publish_key);

                Ok(Some(offered))
            }
            _ => Ok(None),
        }
    }

    /// Generate proof from this State if there is an offer loaded.
    fn proof(&self) -> Result<Option<Loaded>, String> {
        match &self.loaded {
            Loaded::Offer { cred, .. } => {
                let accepted = wallet::actions::accept(&try_from_cbor(cred)?)?;
                let cred = self.builder.extend(accepted)?;
                let proof_package = self.builder.proof_package(&cred)?;
                match proof_package.verify() {
                    // TODO: move url fn to with_proof fn
                    Ok(true) => Ok(Some(proof_package)),
                    Ok(false) => Err("That proof is invalid!".to_string()),
                    Err(e) => Err(format!("Verify function failed: {}", e)),
                }
            }
            _ => Ok(None),
        }
    }

    // pub(crate) fn with_cred(mut self, builder: CredentialStruct) -> Self {
    //     self.builder = builder;
    //     self
    // }

    /// Publish the proof to the network by emiting a serialized message of the Key and Provables
    pub(crate) fn publish_proof(self) -> Self {
        // TODO: Handle failures better
        let Ok(Some(Loaded::Proof(ref provables))) = self.proof() else {
            println!("No proof to publish");
            return self;
        };
        let vk = provables.issuer_public.vk.clone();

        // Emit key-value pair.
        // The key is a delano-keys::PublishingKey using only the first Entry of attributes in the
        // offered credential (entry zero).
        // The value is proof with provables
        let publishables = delano_events::Publishables::new(
            PublishingKey::new(
                &OfferedPreimages::<AttributeKOV>(&self.builder.entries[0]),
                &IssuerKey(&vk),
            ),
            provables.clone(),
        );

        // First, subscribe to the key
        subscribe_to_topic(publishables.key());

        let message_data = Context::Event(Events::Publish(publishables.build()));
        let message = serde_json::to_string(&message_data).unwrap_or_default();
        wurbo_in::emit(&message);
        self
    }

    /// Processes the imconing message and updates the [History] accordingly.
    pub(crate) fn process_message(mut self, message: &Message) -> Self {
        // deserialize the message bytes into delano_events::Provables<T>
        let Ok(published): Result<Publishables<AttributeKOV>, _> =
            (&delano_events::PublishMessage {
                key: message.topic.clone(),
                value: message.data.clone(),
            })
                .try_into()
        else {
            return self;
        };

        // if the publish.key matches any of the History.publish_key, then update the History.latest
        // with the published value.
        for h in self.history.iter_mut() {
            if h.publish_key == published.key() {
                // First, verify the proof
                let provables = published.value();
                let proof = Loaded::Proof(provables.clone());

                // if proof.verify is Ok(true), then update the History.latest with the published value
                if proof.verify().unwrap_or_default() {
                    // turn vec<vec<T>> into vec<vec<AttributeKOV.to_string()>>
                    h.latest = Value::from(
                        published
                            .value()
                            .selected_preimages
                            .iter()
                            .map(|entry| {
                                entry
                                    .iter()
                                    .map(|attr| {
                                        AttributeKOV::try_from(attr.clone())
                                            .unwrap_or_default()
                                            .to_string()
                                    })
                                    .collect::<Vec<_>>()
                            })
                            .collect::<Vec<_>>(),
                    );
                } else {
                    println!("Proof failed to verify");
                }
            }
        }

        self
    }
}

/// Helper function that subscribes to a key
fn subscribe_to_topic(key: impl ToString) {
    let message_data = Context::Event(Events::Subscribe(SubscribeTopic::new(key)));
    let message = serde_json::to_string(&message_data).unwrap_or_default();
    wurbo_in::emit(&message);
}

impl Object for State {
    /// Remember to add match arms for any new fields.
    fn get_value(self: &Arc<Self>, key: &Value) -> Option<Value> {
        // TODO: Show issues/errors as error variant?
        // if offer or proof have messages, show them?
        match key.as_str()? {
            "id" => Some(Value::from(rand_id())),
            "loaded" => Some(Value::from(self.loaded.clone())),
            "credential" => Some(Value::from(self.builder.clone())),
            "offer" => match self.offer {
                Some(ref offer) => Some(Value::from(offer.clone())),
                None => Some(Value::from("No offer generated")),
            },
            "proof" => match self.proof {
                Some(ref proof) => match proof.to_urlsafe() {
                    Ok(urlsafe_proof) => Some(Value::from(urlsafe_proof)),
                    Err(e) => Some(Value::from(e.to_string())),
                },
                None => Some(Value::from("Click to generate a proof.")),
            },
            "history" => Some(Value::from_serialize(&self.history.clone())),
            _ => None,
        }
    }
}

impl From<String> for State {
    fn from(data: String) -> Self {
        let loaded: Loaded = serde_json::from_str(&data).unwrap_or_default();
        Self {
            history: Default::default(),
            loaded: loaded.clone(),
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
    Proof(Provables<AttributeKOV>),
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
            Self::Proof(Provables::<AttributeKOV> {
                selected,
                selected_preimages: preimages,
                proof,
                issuer_public,
            }) => {
                // Step 1) Hash preimages & compare to selected
                // Iterate through each preimage converting them into delanocreds::Attribute,
                // then compare them to the selected.
                let preimages_valid =
                    preimages
                        .iter()
                        .zip(selected.iter())
                        .all(|(preimage, selected)| {
                            // Convert the preimage into a delanocreds::Attribute
                            // Hash the preimage
                            // Compare the preimage hash to the selected
                            *selected
                                == preimage
                                    .iter()
                                    .map(|kov| {
                                        Attribute::from(
                                            AttributeKOV::try_from(kov.clone()).unwrap_or_default(),
                                        )
                                        .to_bytes()
                                    })
                                    .collect::<Vec<Vec<u8>>>()
                        });

                // Step 2) Verify the proof using wallet::actions::verify
                let verifiables = wallet::actions::Verifiables {
                    proof: proof.into(),
                    issuer_public: issuer_public.into(),
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

impl Object for Loaded {
    fn get_value(self: &Arc<Self>, key: &Value) -> Option<Value> {
        match key.as_str()? {
            "id" => Some(Value::from(rand_id())),
            "context" => match **self {
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
            "hints" => match **self {
                Self::Offer { ref hints, .. } => Some(Value::from(hints.clone())),
                _ => None,
            },
            "preimages" => match **self {
                Self::Proof(Provables::<AttributeKOV> {
                    selected_preimages: ref preimages,
                    ..
                }) => {
                    let de_preimages: Vec<Vec<AttributeKOV>> = preimages
                        .iter()
                        .map(|entry| {
                            entry
                                .iter()
                                .map(|a| AttributeKOV::try_from(a.clone()).unwrap_or_default())
                                .collect::<Vec<_>>()
                        })
                        .collect::<Vec<_>>();

                    Some(Value::from(de_preimages.clone()))
                }
                _ => None,
            },
            "verified" => match self.verify() {
                Ok(verified) => Some(Value::from(verified)),
                Err(e) => Some(Value::from(e)),
            },
            _ => None,
        }
    }
}

impl From<Loaded> for wurbo::prelude::Value {
    fn from(loaded: Loaded) -> Self {
        Value::from_object(loaded)
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
    use delanocreds::{Credential, CredentialCompressed, Issuer, Nym};

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
        let cred = CredentialCompressed::from(dummy_cred());

        // print the bytes
        println!("Compressed Dumy Cred {:?}", cred);
    }
}

/// delanocreds::keypair::CredProofCompressed: From<types::CredProofCompressed>
impl From<types::CredProofCompressed> for CredProofCompressed {
    fn from(cred_proof: types::CredProofCompressed) -> Self {
        CredProofCompressed {
            sigma: cred_proof.sigma.into(),
            commitment_vector: cred_proof.commitment_vector,
            witness_pi: cred_proof.witness_pi,
            nym_proof: cred_proof.nym_proof.into(),
        }
    }
}

/// delanocreds::keypair::SignatureCompressed: From<types::SignatureCompressed>
impl From<types::SignatureCompressed> for SignatureCompressed {
    fn from(signature: types::SignatureCompressed) -> Self {
        SignatureCompressed {
            z: signature.z,
            y_g1: signature.y_g1,
            y_hat: signature.y_hat,
            t: signature.t,
        }
    }
}

/// NymProofCompressed: From<types::NymProofCompressed>
impl From<types::NymProofCompressed> for NymProofCompressed {
    fn from(nym_proof: types::NymProofCompressed) -> Self {
        NymProofCompressed {
            challenge: nym_proof.challenge,
            pedersen_open: nym_proof.pedersen_open.into(),
            pedersen_commit: nym_proof.pedersen_commit,
            public_key: nym_proof.public_key,
            response: nym_proof.response,
            damgard: nym_proof.damgard.into(),
        }
    }
}

/// delanocreds::zkp::DamgardTransformCompressed: From<types::DamgardTransformCompressed>
impl From<types::DamgardTransformCompressed> for DamgardTransformCompressed {
    fn from(damgard: types::DamgardTransformCompressed) -> Self {
        DamgardTransformCompressed {
            pedersen: damgard.pedersen.into(),
        }
    }
}

/// delanocreds::zkp::PedersenCompressed: From<types::PedersenCompressed>
impl From<types::PedersenCompressed> for PedersenCompressed {
    fn from(pedersen: types::PedersenCompressed) -> Self {
        PedersenCompressed::from(pedersen.h)
    }
}

/// PedersenOpenCompressed: From<types::PedersenOpenCompressed>
impl From<types::PedersenOpenCompressed> for PedersenOpenCompressed {
    fn from(pedersen_open: types::PedersenOpenCompressed) -> Self {
        PedersenOpenCompressed {
            open_randomness: pedersen_open.open_randomness,
            announce_randomness: pedersen_open.announce_randomness,
            announce_element: pedersen_open.announce_element,
        }
    }
}

/// IssuerPublicCompressed: From<types::IssuerPublicCompressed>
impl From<types::IssuerPublicCompressed> for IssuerPublicCompressed {
    fn from(issuer_public: types::IssuerPublicCompressed) -> Self {
        IssuerPublicCompressed {
            parameters: issuer_public.parameters.into(),
            vk: issuer_public.vk.iter().map(|vk| vk.into()).collect(),
        }
    }
}

/// VKCompressed: From<&types::VkCompressed>
impl From<&types::VkCompressed> for VKCompressed {
    fn from(vk: &types::VkCompressed) -> Self {
        match vk {
            types::VkCompressed::G1(g1) => VKCompressed::G1(g1.to_vec()),
            types::VkCompressed::G2(g2) => VKCompressed::G2(g2.to_vec()),
        }
    }
}

/// ParamSetCommitmentCompressed: From<types::ParamSetCommitmentCompressed>
impl From<types::ParamSetCommitmentCompressed> for ParamSetCommitmentCompressed {
    fn from(param_set_commitment: types::ParamSetCommitmentCompressed) -> Self {
        ParamSetCommitmentCompressed {
            pp_commit_g1: param_set_commitment.pp_commit_g1,
            pp_commit_g2: param_set_commitment.pp_commit_g2,
        }
    }
}

/// types::CredProofCompressed: From<&delanocreds::keypair::CredProofCompressed>
impl From<&CredProofCompressed> for types::CredProofCompressed {
    fn from(cred_proof: &CredProofCompressed) -> Self {
        types::CredProofCompressed {
            sigma: cred_proof.sigma.clone().into(),
            commitment_vector: cred_proof.commitment_vector.clone(),
            witness_pi: cred_proof.witness_pi.clone(),
            nym_proof: cred_proof.nym_proof.clone().into(),
        }
    }
}

/// types::SignatureCompressed: From<delanocreds::keypair::SignatureCompressed>
impl From<SignatureCompressed> for types::SignatureCompressed {
    fn from(signature: SignatureCompressed) -> Self {
        types::SignatureCompressed {
            z: signature.z,
            y_g1: signature.y_g1,
            y_hat: signature.y_hat,
            t: signature.t,
        }
    }
}

/// types::NymProofCompressed: From<delanocreds::keypair::NymProofCompressed>a
impl From<NymProofCompressed> for types::NymProofCompressed {
    fn from(nym_proof: NymProofCompressed) -> Self {
        types::NymProofCompressed {
            challenge: nym_proof.challenge,
            pedersen_open: nym_proof.pedersen_open.clone().into(),
            pedersen_commit: nym_proof.pedersen_commit,
            public_key: nym_proof.public_key,
            response: nym_proof.response,
            damgard: nym_proof.damgard.clone().into(),
        }
    }
}

/// types::DamgardTransformCompressed: From<delanocreds::zkp::DamgardTransformCompressed>
impl From<DamgardTransformCompressed> for types::DamgardTransformCompressed {
    fn from(damgard: DamgardTransformCompressed) -> Self {
        types::DamgardTransformCompressed {
            pedersen: damgard.pedersen.clone().into(),
        }
    }
}

/// types::PedersenCompressed: From<delanocreds::zkp::PedersenCompressed>
impl From<PedersenCompressed> for types::PedersenCompressed {
    fn from(pedersen: PedersenCompressed) -> Self {
        types::PedersenCompressed { h: pedersen.h() }
    }
}

/// types::PedersenOpenCompressed: From<delanocreds::zkp::PedersenOpenCompressed>
impl From<PedersenOpenCompressed> for types::PedersenOpenCompressed {
    fn from(pedersen_open: PedersenOpenCompressed) -> Self {
        types::PedersenOpenCompressed {
            open_randomness: pedersen_open.open_randomness.clone().into(),
            announce_randomness: pedersen_open.announce_randomness,
            announce_element: pedersen_open.announce_element,
        }
    }
}

/// types::IssuerPublicCompressed: From<&delanocreds::keypair::IssuerPublicCompressed>
impl From<&IssuerPublicCompressed> for types::IssuerPublicCompressed {
    fn from(issuer_public: &IssuerPublicCompressed) -> Self {
        types::IssuerPublicCompressed {
            parameters: issuer_public.parameters.clone().into(),
            vk: issuer_public.vk.iter().map(|vk| vk.into()).collect(),
        }
    }
}

/// types::ParamSetCommitmentCompressed: From<delanocreds::set_commits::ParamSetCommitmentCompressed>
impl From<ParamSetCommitmentCompressed> for types::ParamSetCommitmentCompressed {
    fn from(param_set_commitment: ParamSetCommitmentCompressed) -> Self {
        types::ParamSetCommitmentCompressed {
            pp_commit_g1: param_set_commitment.pp_commit_g1,
            pp_commit_g2: param_set_commitment.pp_commit_g2,
        }
    }
}

/// types::VkCompressed: From<&delano_keys::vk::VKCompressed>
impl From<&VKCompressed> for types::VkCompressed {
    fn from(vk: &VKCompressed) -> Self {
        match vk {
            VKCompressed::G1(g1) => types::VkCompressed::G1(g1.to_vec()),
            VKCompressed::G2(g2) => types::VkCompressed::G2(g2.to_vec()),
        }
    }
}
