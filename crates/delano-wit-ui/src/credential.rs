//! This module handles the temporary state that is created and mutated by the User Interface.
//! From this module's [StructObject], we can either Create a Credential, Offer a Credential, Accept a Credential, Prove a Credential, or Verify a Credential.

use self::attributes::Hint;

use super::*;
use crate::attributes::AttributeKOV;
use base64ct::{Base64UrlUnpadded, Encoding};
use delanocreds::{CBORCodec, Credential};
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
        let state = { LAST_STATE.lock().unwrap().clone().unwrap_or_default() };
        state.credential
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
            // set if selected
            context_types::Entry {
                idx,
                val: context_types::Kovindex::Selected(i),
            } => {
                // show idx, i, and kvctx.value
                println!("idx: {:?}, i: {:?}, kvctx.value: {:?}", idx, i, kvctx.value);
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
    fn issue(&self) -> Result<Vec<u8>, String> {
        let attr_vec = self.entries[self.entries.len() - 1]
            .iter()
            .map(|a| a.into_bytes())
            .collect::<Vec<_>>();

        wallet::actions::issue(&attr_vec, self.max_entries as u8, None)
    }

    /// Offer this credential with no config
    fn offer(&self, cred: Vec<u8>) -> Result<Vec<u8>, String> {
        wallet::actions::offer(
            &cred,
            &wallet::types::OfferConfig {
                redact: None,
                additional_entry: None,
                max_entries: Some(self.max_entries as u8),
            },
        )
    }

    /// Generate a proof using the given
    fn prove(&self, credential: Vec<u8>, nonce: Vec<u8>) -> Result<Vec<u8>, String> {
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
            "credential" => match self.issue() {
                Ok(cred) => Some(Value::from(cred)),
                Err(e) => {
                    eprintln!("Error issuing credential: {:?}", e);
                    None
                }
            },
            // offer is a link to the credential, including hints
            "offer" => {
                let cred = self.issue().unwrap_or_default();
                let offer = self.offer(cred).unwrap_or_default();

                // convert the attributes to hint
                let hints: Vec<Vec<AttributeKOV>> = self
                    .entries
                    .iter()
                    .map(|a| {
                        a.iter()
                            .map(|a| Hint::from(a.clone()).into())
                            .collect::<Vec<_>>()
                    })
                    .collect::<Vec<_>>();

                let offer = crate::offer::Context::Offer { cred: offer, hints };

                let serialized = serde_json::to_string(&offer).unwrap_or_default();

                let b64 = Base64UrlUnpadded::encode_string(serialized.as_bytes());

                Some(Value::from(b64))
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
pub struct AttributeStruct(context_types::Attribute);

impl Default for AttributeStruct {
    fn default() -> Self {
        Self(context_types::Attribute {
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

impl From<Option<context_types::Loadables>> for CredentialStruct {
    fn from(maybe_loadables: Option<context_types::Loadables>) -> Self {
        match maybe_loadables {
            Some(loadables) => Self::from(loadables),
            None => Self::default(),
        }
    }
}

/// From WIT context Loadables type, which consist of a cred field and a hints field, which are list<list<Attribute>>
impl From<context_types::Loadables> for CredentialStruct {
    fn from(loadables: context_types::Loadables) -> Self {
        // get credential from bytes so we can get the length of max entries
        match (
            Credential::from_bytes(&loadables.cred),
            loadables.hints.as_ref(),
        ) {
            (Ok(cred), Some(entry_hints)) => {
                // extract update key from cred
                let update_key = cred.update_key;
                // if update key is None, max entries is 0
                // if update key is Some, max entries is the length of the update key
                let max_entries = update_key.map(|k| k.len()).unwrap_or_default();

                Self {
                    credential: Some(loadables.cred),
                    entries: entry_hints
                        .iter()
                        .map(|a| {
                            a.iter()
                                .map(|a| AttributeKOV::from(a.clone()))
                                .collect::<Vec<_>>()
                        })
                        .collect::<Vec<_>>(),
                    // max entries is in the Cred, it's the length of the update_key, if any.
                    max_entries: max_entries as usize,
                }
            }
            _ => {
                eprintln!("Error deserializing credential",);
                Self::default()
            }
        }
    }
}

impl From<&context_types::Loadables> for CredentialStruct {
    fn from(loadables: &context_types::Loadables) -> Self {
        Self::from(loadables.clone())
    }
}

impl From<context_types::Attribute> for AttributeStruct {
    fn from(context: context_types::Attribute) -> Self {
        Self(context)
    }
}

impl From<AttributeStruct> for wurbo::prelude::Value {
    fn from(context: AttributeStruct) -> Self {
        Self::from_struct_object(context)
    }
}

impl From<AttributeStruct> for context_types::Attribute {
    fn from(context: AttributeStruct) -> Self {
        context.0
    }
}

impl Deref for AttributeStruct {
    type Target = context_types::Attribute;

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
