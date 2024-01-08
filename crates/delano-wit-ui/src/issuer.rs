use std::{ops::DerefMut, sync::OnceLock};

use super::*;

/// Element id for the attributes.html template, which can only be set once.
static ISSUER_ID: OnceLock<String> = OnceLock::new();

/// Page is the wrapper for Input and Output
#[derive(Debug, Clone, Default)]
pub(crate) struct IssuerStruct(Option<context_types::Issuer>);

impl IssuerStruct {
    /// Reads the LAST_STATE and returns Self
    pub(crate) fn from_latest() -> Self {
        let state = { LAST_STATE.lock().unwrap().clone().unwrap_or_default() };
        let issuer = state.issuer.clone();
        Self(Some(issuer.into()))
    }

    /// Extends the Vector of attributes by 1.
    pub(crate) fn push_attribute(&mut self) -> Self {
        let mut attributes = self.get_attributes();
        attributes.push(AttributeStruct::default());
        Self(Some(context_types::Issuer {
            attributes: attributes.into_iter().map(|a| a.into()).collect(),
            max_entries: self.as_ref().map_or(0, |v| v.max_entries),
        }))
    }

    /// Use the given context to extract the variant (key, op, or value) and the index
    /// of the attribute to update.
    pub(crate) fn edit_attribute(&self, kvctx: &context_types::Kvctx) -> Self {
        let mut attributes = self.get_attributes();
        let edited_attributes = match kvctx.ctx {
            context_types::Kovindex::Key(i) => {
                attributes[i as usize].key = kvctx.value.clone();
                attributes
            }
            context_types::Kovindex::Op(i) => {
                attributes[i as usize].op = kvctx.value.clone();
                attributes
            }
            context_types::Kovindex::Value(i) => {
                attributes[i as usize].value = kvctx.value.clone();
                attributes
            }
        };
        Self(Some(context_types::Issuer {
            attributes: edited_attributes.into_iter().map(|a| a.into()).collect(),
            max_entries: self.as_ref().map_or(0, |v| v.max_entries),
        }))
    }

    /// Create a new IssuerStruct with the given max entries and the latest state
    pub(crate) fn with_max_entries(max: &u8) -> Self {
        let issuer = Self::from_latest();
        Self(Some(context_types::Issuer {
            max_entries: *max,
            attributes: issuer.as_ref().unwrap().attributes.clone(),
        }))
    }

    /// Utility func to get attributes
    fn get_attributes(&self) -> Vec<AttributeStruct> {
        self.as_ref().map_or(vec![AttributeStruct::default()], |v| {
            v.attributes
                .iter()
                .map(|a| AttributeStruct::from(a.clone()))
                .collect::<Vec<_>>()
        })
    }
}

impl StructObject for IssuerStruct {
    fn get_field(&self, name: &str) -> Option<Value> {
        match name {
            "id" => Some(Value::from(
                ISSUER_ID.get_or_init(|| utils::rand_id()).to_owned(),
            )),
            "attributes" => Some(Value::from(self.get_attributes())),
            "max_entries" => Some(Value::from(self.as_ref().map_or(0, |v| v.max_entries))),
            // assigns a random id attribute to the button element, upon which we can apply
            // minijinja filters
            // set EventTarget makes .id and .target for us.
            // We pick ATTRIBUTES_HTML because we need to refresh the input screen with a new entry
            "add_attribute_button" => Some(Value::from_struct_object(EventListener::with_target(
                ATTRIBUTES_HTML.to_owned(),
            ))),
            // we pick output.html because the input screen is not altered
            "input_key" => Some(Value::from_struct_object(EventListener::with_target(
                "output.html".to_owned(),
            ))),
            // we pick output.html because the input screen is not altered
            "input_maxentries" => Some(Value::from_struct_object(EventListener::with_target(
                "output.html".to_owned(),
            ))),
            "credential" => {
                // convert self.attributes into a Vec<Vec<u8>> and use wallet::delano::issue to calculate the cred
                let attr_vec = self.as_ref().map_or(vec![], |v| {
                    v.attributes
                        .iter()
                        .map(|a| a.value.as_bytes().to_vec())
                        .collect::<Vec<_>>()
                });
                let max_entries = self.as_ref().map_or(0, |v| v.max_entries);

                match wallet::actions::issue(&attr_vec, max_entries, None) {
                    Ok(cred) => {
                        // convert it to hex first
                        let literal = format!("{:X?}", cred);
                        let literal = literal.replace("[", "").replace("]", "").replace(", ", "");
                        Some(Value::from(cred))
                    }
                    Err(_e) => {
                        // log::error!("Error issuing credential: {:?}", e);
                        None
                    }
                }
            }
            _ => None,
        }
    }
    /// So that debug will show the values
    fn static_fields(&self) -> Option<&'static [&'static str]> {
        Some(&["id", "attributes"])
    }
}

impl From<Option<context_types::Issuer>> for IssuerStruct {
    fn from(context: Option<context_types::Issuer>) -> Self {
        Self(context)
    }
}

impl From<&context_types::Issuer> for IssuerStruct {
    fn from(context: &context_types::Issuer) -> Self {
        Self(Some(context.clone()))
    }
}

impl From<IssuerStruct> for context_types::Issuer {
    fn from(context: IssuerStruct) -> Self {
        context_types::Issuer {
            attributes: context
                .get_attributes()
                .into_iter()
                .map(|a| a.into())
                .collect(),
            max_entries: context.as_ref().map_or(0, |v| v.max_entries),
        }
    }
}

impl Deref for IssuerStruct {
    type Target = Option<context_types::Issuer>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// Use this to create id and target fields for our event targets.
#[derive(Debug, Clone)]
struct EventListener {
    id: String,
    target: String,
}

impl Default for EventListener {
    fn default() -> Self {
        Self::with_target("index.html".to_string())
    }
}

impl EventListener {
    /// Create a new IssuerEventTarget with a random id and target
    pub(crate) fn with_target(target: String) -> Self {
        Self {
            id: utils::rand_id(),
            target,
        }
    }
}

impl StructObject for EventListener {
    fn get_field(&self, name: &str) -> Option<Value> {
        match name {
            "id" => Some(Value::from(self.id.to_owned())),
            "target" => Some(Value::from_safe_string(self.target.to_owned())),
            _ => None,
        }
    }

    /// So that debug will show the values
    fn static_fields(&self) -> Option<&'static [&'static str]> {
        Some(&["id", "target"])
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

impl DerefMut for AttributeStruct {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

#[cfg(test)]
mod delano_issuer_ui_tests {

    use super::*;

    #[test]
    fn test_push_attribute() {
        let mut issuer = IssuerStruct::default();
        issuer = issuer.push_attribute();

        assert_eq!(issuer.as_ref().unwrap().attributes.len(), 2);

        issuer = issuer.push_attribute();
        assert_eq!(issuer.as_ref().unwrap().attributes.len(), 3);
    }
}
