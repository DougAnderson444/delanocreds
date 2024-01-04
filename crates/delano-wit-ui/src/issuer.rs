use super::*;

/// Page is the wrapper for Input and Output
#[derive(Debug, Clone)]
pub(crate) struct IssuerStruct(Option<context_types::Issuer>);

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

impl Deref for IssuerStruct {
    type Target = Option<context_types::Issuer>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// Wrap the [context_types::Attribute] in a struct that implements StructObject
#[derive(Debug, Clone)]
pub(crate) struct AttributeStruct(context_types::Attribute);

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

impl Deref for AttributeStruct {
    type Target = context_types::Attribute;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
