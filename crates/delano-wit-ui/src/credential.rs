//! This module handles the temporary state that is created and mutated by the User Interface.
//! From this module's [StructObject], we can either Create a Credential, Offer a Credential, Accept a Credential, Prove a Credential, or Verify a Credential.

use super::*;
use crate::attributes::AttributeKOV;
use delano_events::Provables;
use delanocreds::{CBORCodec, Credential, Nonce};

/// The Credential Struct
#[derive(Debug, Clone)]
pub struct CredentialStruct {
    /// The Credential's Attributes, as entered at each level
    pub entries: Vec<Vec<AttributeKOV>>,
    /// The Credential's Max Entries
    pub max_entries: usize,
}

impl Default for CredentialStruct {
    fn default() -> Self {
        Self {
            entries: vec![vec![AttributeKOV::default()]],
            max_entries: 2,
        }
    }
}

impl CredentialStruct {
    /// Reads the LAST_STATE and returns Self
    pub(crate) fn from_latest() -> Self {
        let last = { LAST_STATE.lock().unwrap().clone().unwrap_or_default() };
        last.state.builder
    }

    /// Extends the last Entry Vector of attributes by 1.
    pub(crate) fn push_attribute(mut self) -> Self {
        let last = self.entries.len() - 1;
        self.entries[last].push(AttributeKOV::default());
        self
    }

    /// Entends the Vector of entries by 1.
    pub(crate) fn push_entry(mut self) -> Self {
        // TODO: assert existing entries are valid by creating a proof and verifying it
        self.entries.push(vec![AttributeKOV::default()]);
        self
    }
    /// Use the given context to extract the variant (key, op, or value) and the index
    /// of the attribute to update.
    pub(crate) fn edit_attribute(&mut self, kvctx: &context_types::Kvctx) {
        // ensure self.attributes has 1 empty vec if it's empty
        if self.entries.is_empty() {
            self.entries.push(vec![AttributeKOV::default()]);
        }
        match kvctx.ctx {
            context_types::Entry {
                idx,
                val: context_types::Kovindex::Key(i),
            } => {
                self.entries[idx as usize][i as usize].key =
                    attributes::AttributeKey(kvctx.value.clone());
            }
            context_types::Entry {
                idx,
                val: context_types::Kovindex::Op(i),
            } => {
                self.entries[idx as usize][i as usize].op =
                    attributes::Operator::try_from(kvctx.value.clone()).unwrap_or_default();
            }
            context_types::Entry {
                idx,
                val: context_types::Kovindex::Value(i),
            } => {
                self.entries[idx as usize][i as usize].value =
                    attributes::AttributeValue(kvctx.value.clone());
            }
            context_types::Entry {
                idx,
                val: context_types::Kovindex::Selected(i),
            } => {
                self.entries[idx as usize][i as usize].selected = !kvctx.value.is_empty();
            }
        };
    }

    /// Create a new CredentialStruct with the given max entries and the latest state
    pub(crate) fn with_max_entries(mut self, max: &u8) -> Self {
        self.max_entries = *max as usize;
        self
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

    /// Extend the accepted credential with the given addtional attribute Entry.
    /// When we use this UI to load a credential that is given to use, the UI
    /// allows a user to "Extend" the credential with an additional Entry of 1 or more attributes.
    ///
    /// When we extend, we are taking the length -1 Entries (likely just a single enrty, but could
    /// be more), accepting the offered credential with these entries, and then adding the additional
    /// entry using the lest of the entries Vector for the extension.
    ///
    /// This yields an extended proof that can be used to prove attributes in the additional entry.
    pub(crate) fn extend(&self, accepted: Vec<u8>) -> Result<Vec<u8>, String> {
        // we will extend the cred using self.entries n + 1, so if there is only 1 self.entries, return what was given to us
        if self.entries.len() < 2 {
            return Ok(accepted);
        }

        // extend the accepted credential with the last entry in self.entries as wallet::types::Entry
        let last_entry = self.entries[self.entries.len() - 1]
            .iter()
            .map(|kov| delanocreds::Attribute::from(kov).to_bytes())
            .collect::<Vec<_>>();
        wallet::actions::extend(&accepted, &last_entry)
    }

    /// generate Proof Package
    pub(crate) fn proof_package(&self, cred: &[u8]) -> Result<crate::api::Loaded, String> {
        // To go from the current credential to a proof, we need to:
        // 1) Extend the current credential with the additional entry
        // 2) generate the proof with the extended credential

        // generate a proof for the extended cred using selected attributeKOVs
        let nonce = Nonce::default();
        let nonce_bytes: Vec<u8> = nonce.into();

        let mut selected_attrs = Vec::new();

        // Convert to bytes in preparation for the proof.
        // Also generate the Vec<Vec<AttributeKOV>> for the preimages. Leaves any unselected
        // attributes as default.
        let (entries, preimages): (Vec<Vec<Vec<u8>>>, Vec<Vec<AttributeKOV>>) = self
            .entries
            .iter()
            .map(|entry| {
                entry
                    .iter()
                    .map(|kov| {
                        let bytes = delanocreds::Attribute::new(kov.to_string()).to_bytes();
                        let mut preimage = AttributeKOV::default();
                        if kov.selected {
                            selected_attrs.push(bytes.clone());
                            preimage = kov.clone();
                        }
                        (bytes, preimage)
                    })
                    .unzip()
            })
            .unzip();

        let provables = wallet::types::Provables {
            credential: cred.to_vec(),
            entries,
            selected: selected_attrs,
            nonce: nonce_bytes,
        };

        let wallet::types::Proven {
            proof,
            selected: selected_entries,
        } = wallet::actions::prove(&provables)?;

        let cred_struct = Credential::from_bytes(cred).map_err(|e| e.to_string())?;

        Ok(api::Loaded::Proof(Provables {
            proof,
            issuer_public: cred_struct.issuer_public.to_bytes().unwrap_or_default(),
            selected: selected_entries,
            selected_preimages: preimages,
        }))
    }
}

impl StructObject for CredentialStruct {
    fn get_field(&self, name: &str) -> Option<Value> {
        match name {
            // assigns a random id attribute to the button element, upon which we can apply
            "id" => Some(Value::from(rand_id())),
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

impl From<CredentialStruct> for wurbo::prelude::Value {
    fn from(context: CredentialStruct) -> Self {
        Self::from_struct_object(context)
    }
}

/// From WIT context Loadables type, which consist of a cred field and a hints field, which are list<list<Attribute>>
impl From<&api::Loaded> for CredentialStruct {
    fn from(ctx: &api::Loaded) -> Self {
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
                            // iterate mutbly and set each selected to true
                            entries: hints
                                .iter()
                                .map(|a| a.iter().map(|a| a.clone().selected()).collect())
                                .collect(),
                            // max entries is in the Cred, it's the length of the update_key, if any.
                            max_entries: max_entries as usize,
                        }
                    }
                    _ => Self::default(),
                }
            }
            _ => Self::default(),
        }
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
