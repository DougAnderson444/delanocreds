//! This module handles the temporary state that is created and mutated by the User Interface.
//! From this module's [StructObject], we can either Create a Credential, Offer a Credential, Accept a Credential, Prove a Credential, or Verify a Credential.

use self::attributes::Hint;

use super::*;
use crate::attributes::AttributeKOV;
use delanocreds::{CBORCodec, Credential, Nonce};
use std::ops::DerefMut;

/// The Credential Struct
#[derive(Debug, Clone)]
pub struct CredentialStruct {
    /// The credential bytes received when loaded, if any
    pub credential: Option<Vec<u8>>,
    /// The Credential's Attributes, as entered at each level
    pub entries: Vec<Vec<AttributeKOV>>,
    /// The Credential's Max Entries
    pub max_entries: usize,
}

impl Default for CredentialStruct {
    fn default() -> Self {
        Self {
            entries: vec![vec![AttributeKOV::default()]],
            max_entries: 0,
            credential: None,
        }
    }
}

impl CredentialStruct {
    /// Reads the LAST_STATE and returns Self
    pub(crate) fn from_latest() -> Self {
        let last = { LAST_STATE.lock().unwrap().clone().unwrap_or_default() };
        last.state.credential
    }

    /// Extends the last Entry Vector of attributes by 1.
    pub(crate) fn push_attribute(mut self) -> Self {
        let last = self.entries.len() - 1;
        self.entries[last].push(AttributeKOV::default());
        self
    }

    /// Entends the Vector of entries by 1.
    pub(crate) fn push_entry(mut self) -> Self {
        self.entries.push(vec![AttributeKOV::default()]);
        self
    }
    /// Use the given context to extract the variant (key, op, or value) and the index
    /// of the attribute to update.
    pub(crate) fn edit_attribute(mut self, kvctx: &context_types::Kvctx) -> Self {
        // ensure self.attributes has 1 empty vec if it's empty
        if self.entries.is_empty() {
            self.entries.push(vec![AttributeKOV::default()]);
        }
        let edited_attributes = match kvctx.ctx {
            context_types::Entry {
                idx,
                val: context_types::Kovindex::Key(i),
            } => {
                self.entries[idx as usize][i as usize].key =
                    attributes::AttributeKey(kvctx.value.clone());
                self.entries
            }
            context_types::Entry {
                idx,
                val: context_types::Kovindex::Op(i),
            } => {
                self.entries[idx as usize][i as usize].op =
                    attributes::Operator::try_from(kvctx.value.clone()).unwrap_or_default();
                self.entries
            }
            context_types::Entry {
                idx,
                val: context_types::Kovindex::Value(i),
            } => {
                self.entries[idx as usize][i as usize].value =
                    attributes::AttributeValue(kvctx.value.clone());
                self.entries
            }
            context_types::Entry {
                idx,
                val: context_types::Kovindex::Selected(i),
            } => {
                self.entries[idx as usize][i as usize].selected = !kvctx.value.is_empty();
                self.entries
            }
        };
        Self {
            entries: edited_attributes.to_vec(),
            max_entries: self.max_entries,
            ..self
        }
    }

    /// Create a new CredentialStruct with the given max entries and the latest state
    pub(crate) fn with_max_entries(max: &u8) -> Self {
        let cred = Self::from_latest();
        Self {
            max_entries: *max as usize,
            entries: cred.entries.clone(),
            ..cred
        }
    }

    /// Create (issue) credential using this struct's attributes
    pub(crate) fn issue(&self) -> Result<Vec<u8>, String> {
        let attr_vec = self.entries[self.entries.len() - 1]
            .iter()
            .map(|a| a.into_bytes())
            .collect::<Vec<_>>();

        wallet::actions::issue(&attr_vec, self.max_entries as u8, None)
    }

    /// Offer this credential with no config
    pub(crate) fn offer(&self, cred: Vec<u8>) -> Result<Vec<u8>, String> {
        wallet::actions::offer(
            &cred,
            &wallet::types::OfferConfig {
                redact: None,
                additional_entry: None,
                max_entries: Some(self.max_entries as u8),
            },
        )
    }

    /// Extend the loaded credential with the given addtional attribute Entry.
    /// When we use this UI to load a credential that is given to use, the UI
    /// allows a user to "Extend" the credential with an additional Entry of 1 or more attributes.
    ///
    /// When we extend, we are taking the length -1 Entries (likely just a single enrty, but could
    /// be more), accepting the offered credential with these entries, and then adding the additional
    /// entry using the lest of the entries Vector for the extension.
    ///
    /// This yields an extended proof that can be used to prove attributes in the additional entry.
    pub(crate) fn extend(&self, cred: Vec<u8>) -> Result<Vec<u8>, String> {
        // accept given credential
        // it'll fail to prove if the Entry attributes don't match the credential
        let accepted = wallet::actions::accept(&cred)?;

        // extend the accepted credential with the last entry in self.entries as wallet::types::Entry
        let last_entry = self.entries[self.entries.len() - 1]
            .iter()
            .map(|kov| {
                let bytes = delanocreds::Attribute::new(kov.to_string()).to_bytes();
                bytes
            })
            .collect::<Vec<_>>();
        wallet::actions::extend(&accepted, &last_entry)
    }

    /// Generate a proof and selected Entrys using the given credential and nonce
    fn prove(&self, credential: Vec<u8>, nonce: Vec<u8>) -> Result<wallet::types::Proven, String> {
        let mut selected = Vec::new();

        let entries = self
            .entries
            .iter()
            .map(|entry| {
                entry
                    .iter()
                    .map(|kov| {
                        let bytes = delanocreds::Attribute::new(kov.to_string()).to_bytes();
                        if kov.selected {
                            selected.push(bytes.clone());
                        }
                        bytes
                    })
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();

        let provables: wallet::types::Provables = wallet::types::Provables {
            credential,
            entries,
            selected,
            nonce,
        };

        wallet::actions::prove(&provables)
    }

    /// generate Proof Package
    pub(crate) fn proof_package(&self) -> Option<Value> {
        // To go from the current credential to a proof, we need to:
        // 1) Extend the current credential with the additional entry
        // 2) generate the proof with the extended credential

        // if self.credential is None, we can't extend it, return None
        let Some(cred) = &self.credential else {
            return Some(Value::from("No credential loaded"));
        };

        let Ok(credential) = Credential::from_bytes(&cred) else {
            return Some(Value::from("Invalid credential bytes"));
        };

        // we will extend the cred using self.entries n + 1, so if there is only 1 self.entries, return None
        if self.entries.len() == 1 {
            return None;
        }

        let extended = match self.extend(cred.clone()) {
            Ok(extended) => extended,
            Err(e) => {
                eprintln!("Error extending credential: {:?}", e);
                return Some(Value::from("Error extending credential"));
            }
        };

        // generate a proof for the extended cred using selected attributeKOVs
        let nonce = Nonce::default();
        let nonce_bytes: Vec<u8> = nonce.into();
        let wallet::types::Proven { proof, selected } = match self.prove(extended, nonce_bytes) {
            Ok(proven) => proven,
            Err(e) => {
                eprintln!("Error generating proof: {:?}", e);
                return Some(Value::from("Error generating proof"));
            }
        };

        // Also generate the Vec<Vec<AttributeKOV>> for the preimages. Leave any unselected
        // attributes as default.
        let preimages = self
            .entries
            .iter()
            .map(|entry| {
                entry
                    .iter()
                    .map(|kov| {
                        if kov.selected {
                            kov.clone()
                        } else {
                            AttributeKOV::default()
                        }
                    })
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();

        let proof_package = crate::api::Loaded::Proof {
            proof,
            selected,
            preimages,
            issuer_public: credential.issuer_public.to_bytes().unwrap_or_default(),
        };

        Some(Value::from(proof_package.to_urlsafe()))
    }
}

impl StructObject for CredentialStruct {
    fn get_field(&self, name: &str) -> Option<Value> {
        match name {
            // assigns a random id attribute to the button element, upon which we can apply
            "id" => Some(Value::from(utils::rand_id())),
            "entries" => Some(Value::from(self.entries.clone())),
            "max_entries" => Some(Value::from(self.max_entries)),
            "context" => {
                // We do this so we get the exact name of the context, any changes
                // will trigger compile error.
                let context_name = context_types::Context::Editattribute(context_types::Kvctx {
                    ctx: context_types::Entry {
                        idx: Default::default(),
                        val: context_types::Kovindex::Key(Default::default()),
                    },
                    value: Default::default(),
                });
                Some(Value::from(util::variant_string(context_name)))
            }
            _ => None,
        }
    }
    /// So that debug will show the values
    fn static_fields(&self) -> Option<&'static [&'static str]> {
        Some(&[
            "id",
            "entries",
            "max_entries",
            "context",
            "credential",
            "offer",
        ])
    }
}

/// Wrap the [context_types::Attribute] in a struct that implements StructObject
#[derive(Debug, Clone)]
pub struct AttributeStruct(context_types::Kov);

impl Default for AttributeStruct {
    fn default() -> Self {
        Self(context_types::Kov {
            key: "name".to_string(),
            op: "=".to_string(),
            value: "value".to_string(),
        })
    }
}

impl StructObject for AttributeStruct {
    /// Fields are key, op, value.
    fn get_field(&self, name: &str) -> Option<Value> {
        match name {
            "id" => Some(Value::from(utils::rand_id())),
            "key" => Some(Value::from(self.key.clone())),
            "op" => Some(Value::from(self.op.clone())),
            "value" => Some(Value::from(self.value.clone())),
            _ => None,
        }
    }
    /// So that debug will show the values
    fn static_fields(&self) -> Option<&'static [&'static str]> {
        Some(&["id", "key", "op", "value"])
    }
}

impl From<CredentialStruct> for wurbo::prelude::Value {
    fn from(context: CredentialStruct) -> Self {
        Self::from_struct_object(context)
    }
}

/// From WIT context Loadables type, which consist of a cred field and a hints field, which are list<list<Attribute>>
impl From<api::Loaded> for CredentialStruct {
    fn from(ctx: api::Loaded) -> Self {
        match ctx {
            api::Loaded::Offer { cred, hints } => {
                match Credential::from_bytes(&cred) {
                    Ok(credential) => {
                        // extract update key from cred
                        let update_key = credential.update_key;
                        // if update key is None, max entries is 0
                        // if update key is Some, max entries is the length of the update key
                        let max_entries = update_key.map(|k| k.len()).unwrap_or_default();

                        Self {
                            credential: Some(cred),
                            entries: hints,
                            // max entries is in the Cred, it's the length of the update_key, if any.
                            max_entries: max_entries as usize,
                        }
                    }
                    _ => Self::default(),
                }
            }
            // If we got a Proof, then we just want to verify the preimages match the selected,
            // show them, and verify the proof.
            // api::Context::Proof {
            //     proof,
            //     selected,
            //     preimages,
            // } => {
            //
            // }
            _ => Self::default(),
        }
    }
}

impl From<context_types::Kov> for AttributeStruct {
    fn from(context: context_types::Kov) -> Self {
        Self(context)
    }
}

impl From<AttributeStruct> for wurbo::prelude::Value {
    fn from(context: AttributeStruct) -> Self {
        Self::from_struct_object(context)
    }
}

impl From<AttributeStruct> for context_types::Kov {
    fn from(context: AttributeStruct) -> Self {
        context.0
    }
}

impl Deref for AttributeStruct {
    type Target = context_types::Kov;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

// We need derefmut to mutate the KOV index
impl DerefMut for AttributeStruct {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

#[cfg(test)]
mod delano_cred_ui_tests {

    use super::*;

    #[test]
    fn test_push_attribute() {
        let mut cred = CredentialStruct::default();
        cred = cred.push_attribute();

        assert_eq!(cred.entries[0].len(), 2);

        cred = cred.push_attribute();
        assert_eq!(cred.entries[0].len(), 3);
    }
}
