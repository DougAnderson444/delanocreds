use std::ops::DerefMut;

use super::*;

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
        let mut attributes = self.as_ref().map_or(vec![AttributeStruct::default()], |v| {
            v.attributes
                .iter()
                .map(|a| AttributeStruct::from(a.clone()))
                .collect::<Vec<_>>()
        });
        attributes.push(AttributeStruct::default());
        Self(Some(context_types::Issuer {
            attributes: attributes.into_iter().map(|a| a.into()).collect(),
        }))
    }

    /// Use the given context to extract the variant (key, op, or value) and the index
    /// of the attribute to update.
    pub(crate) fn edit_attribute(&self, kvctx: &context_types::Kvctx) -> Self {
        let mut attributes = self.as_ref().map_or(vec![AttributeStruct::default()], |v| {
            v.attributes
                .iter()
                .map(|a| AttributeStruct::from(a.clone()))
                .collect::<Vec<_>>()
        });
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
        }))
    }
}

impl StructObject for IssuerStruct {
    fn get_field(&self, name: &str) -> Option<Value> {
        match name {
            "id" => Some(Value::from(utils::rand_id())),
            "attributes" => Some(Value::from(self.as_ref().map_or(
                vec![AttributeStruct::default()],
                |v| {
                    v.attributes
                        .iter()
                        .map(|a| AttributeStruct::from(a.clone()))
                        .collect::<Vec<_>>()
                },
            ))),
            // assigns a random id attribute to the button element, upon which we can apply
            // minijinja filters
            // ise IssuerEventTarget::default() to make a new button .id and .target for us.
            "add_attribute_button" => Some(Value::from_struct_object(EventListener::with_target(
                "index.html".to_owned(),
            ))),
            "input_key" => Some(Value::from_struct_object(EventListener::with_target(
                "output.html".to_owned(),
            ))),

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
                .as_ref()
                .map_or(vec![AttributeStruct::default()], |v| {
                    v.attributes
                        .iter()
                        .map(|a| AttributeStruct::from(a.clone()))
                        .collect::<Vec<_>>()
                })
                .into_iter()
                .map(|a| a.into())
                .collect(),
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
