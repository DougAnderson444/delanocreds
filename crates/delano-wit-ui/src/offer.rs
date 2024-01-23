//! Module to hold Offer code
use super::*;

use attributes::AttributeKOV;
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
        hints: Vec<Vec<attributes::Hint>>,
    },
}

/// OfferStruct is the minijinja wrapper around the Offer context
#[derive(Debug, Clone, Default)]
pub(crate) struct OfferStruct(Option<context_types::Offer>);

impl OfferStruct {
    /// Gets the hints as a Vector of [attributes::Attribute]
    fn entries_from_hints(&self) -> Vec<Vec<AttributeKOV>> {
        self.as_ref().map_or(vec![], |v| {
            v.hints
                .as_ref()
                .unwrap_or(&vec![vec![]])
                .iter()
                .map(|a| {
                    a.iter()
                        .map(|a| AttributeKOV::from(a.clone()))
                        .collect::<Vec<_>>()
                })
                .collect::<Vec<_>>()
        })
    }
}

impl StructObject for OfferStruct {
    fn get_field(&self, name: &str) -> Option<Value> {
        match name {
            // if the ID is static, set it here. Otherwise, you can use {{app.id}}
            "id" => Some(Value::from(utils::rand_id())),
            "hints" => Some(Value::from(self.entries_from_hints())),
            // context of any changes (like adding a new row)
            "context" => {
                // We do this so we get the exact name of the context, any changes
                // will trigger compile error.
                let context_name = context_types::Context::Offer(context_types::Offer {
                    cred: Default::default(),
                    hints: Default::default(),
                });
                Some(Value::from(util::variant_string(context_name)))
            }
            _ => None,
        }
    }
    /// So that debug will show the values
    fn static_fields(&self) -> Option<&'static [&'static str]> {
        Some(&["id", "hints", "context"])
    }
}

impl From<Option<context_types::Offer>> for OfferStruct {
    fn from(context: Option<context_types::Offer>) -> Self {
        Self(context)
    }
}

impl From<context_types::Offer> for OfferStruct {
    fn from(context: context_types::Offer) -> Self {
        Self(Some(context))
    }
}

impl Deref for OfferStruct {
    type Target = Option<context_types::Offer>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
