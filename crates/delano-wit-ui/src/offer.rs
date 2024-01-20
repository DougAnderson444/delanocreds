//! Module to hold Offer code
use super::*;

use attributes::AttributeKOV;

/// OfferStruct is the minijinja wrapper around the Offer context
#[derive(Debug, Clone, Default)]
pub(crate) struct OfferStruct(Option<context_types::Offer>);

impl OfferStruct {
    /// Gets the hints as a Vector of [attributes::Attribute]
    fn attributes_from_hints(&self) -> Vec<AttributeKOV> {
        self.as_ref().map_or(vec![], |v| {
            v.hints
                .as_ref()
                .unwrap_or(&vec![])
                .iter()
                .map(|a| AttributeKOV::from(a.clone()))
                .collect::<Vec<_>>()
        })
    }
}

impl StructObject for OfferStruct {
    fn get_field(&self, name: &str) -> Option<Value> {
        match name {
            // if the ID is static, set it here. Otherwise, you can use {{app.id}}
            "id" => Some(Value::from(utils::rand_id())),
            "hints" => Some(Value::from(self.attributes_from_hints())),
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
