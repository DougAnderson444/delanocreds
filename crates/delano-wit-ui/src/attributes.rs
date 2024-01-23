use super::*;

use serde::{Deserialize, Serialize};
use std::ops::Deref;

use crate::credential::CredentialStruct;

/// Constant representing the Equal operator
pub const EQUAL: &str = "=";
/// Constant representing the Less Than operator
pub const LESS_THAN: &str = "<";
/// Constant representing the Greater Than operator
pub const GREATER_THAN: &str = ">";

/// Enum of Possible Operators
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum Operator {
    /// Equals Operator
    #[default]
    #[serde(rename = "=")]
    Equal,
    /// Less Than Operator
    #[serde(rename = "<")]
    LessThan,
    /// Greater Than Operator
    #[serde(rename = ">")]
    GreaterThan,
}

impl Operator {
    pub const EQUAL: &'static str = EQUAL;
    pub const LESS_THAN: &'static str = LESS_THAN;
    pub const GREATER_THAN: &'static str = GREATER_THAN;

    /// Return the value of the enum variant
    pub fn value(&self) -> &'static str {
        match self {
            Operator::Equal => Self::EQUAL,
            Operator::LessThan => Self::LESS_THAN,
            Operator::GreaterThan => Self::GREATER_THAN,
        }
    }
}

impl StructObject for Operator {
    fn get_field(&self, name: &str) -> Option<Value> {
        match name {
            "value" => Some(Value::from(self.value())),
            _ => None,
        }
    }
    /// So that debug will show the values
    fn static_fields(&self) -> Option<&'static [&'static str]> {
        Some(&["value"])
    }
}

impl ToString for Operator {
    fn to_string(&self) -> String {
        self.value().to_string()
    }
}

impl TryFrom<String> for Operator {
    type Error = String;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        match value.as_str() {
            Operator::EQUAL => Ok(Operator::Equal),
            Operator::LESS_THAN => Ok(Operator::LessThan),
            Operator::GREATER_THAN => Ok(Operator::GreaterThan),
            _ => Err(format!("Invalid Operator: {}", value)),
        }
    }
}

impl From<Operator> for wurbo::prelude::Value {
    fn from(operator: Operator) -> Self {
        Self::from_struct_object(operator)
    }
}

/// Newtype Key to create an AttributeKOV struct
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct AttributeKey(pub String);

impl Deref for AttributeKey {
    type Target = String;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// Newtype Value to create an AttributeKOV struct
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AttributeValue(pub String);

impl Deref for AttributeValue {
    type Target = String;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// Atrribute Key Operator Value (KOV)
#[derive(Default, Clone, Debug)]
pub struct AttributeKOV {
    /// Key
    pub key: AttributeKey,
    /// Operator
    pub op: Operator,
    /// Value
    pub value: AttributeValue,
}

impl AttributeKOV {
    /// Create a new AttributeKOV from AttributeKey, Operator, and AttributeValue
    pub fn new(key: AttributeKey, op: Operator, value: AttributeValue) -> Self {
        Self { key, op, value }
    }

    /// Represent this KOV as byte vector
    pub fn into_bytes(&self) -> Vec<u8> {
        format!("{} {} {}", *self.key, self.op.to_string(), *self.value).into_bytes()
    }
}

impl StructObject for AttributeKOV {
    fn get_field(&self, name: &str) -> Option<Value> {
        match name {
            "key" => Some(Value::from(self.key.deref().clone())),
            "op" => Some(Value::from(self.op.get_field("value").unwrap())),
            "value" => Some(Value::from(self.value.deref().clone())),
            _ => None,
        }
    }
    /// So that debug will show the values
    fn static_fields(&self) -> Option<&'static [&'static str]> {
        Some(&["key", "op", "value"])
    }
}

impl ToString for AttributeKOV {
    fn to_string(&self) -> String {
        format!("{} {} {}", *self.key, self.op.to_string(), *self.value)
    }
}

impl From<CredentialStruct> for Vec<Vec<AttributeKOV>> {
    fn from(cred: CredentialStruct) -> Self {
        cred.entries
            .iter()
            .map(|a| {
                a.iter()
                    .map(|a| AttributeKOV::from(a.clone()))
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>()
    }
}

impl From<context_types::Attribute> for AttributeKOV {
    fn from(attribute: context_types::Attribute) -> Self {
        Self {
            key: AttributeKey(attribute.key),
            op: Operator::try_from(attribute.op).unwrap_or_default(),
            value: AttributeValue(attribute.value),
        }
    }
}

impl From<context_types::Hint> for AttributeKOV {
    fn from(hint: context_types::Hint) -> Self {
        Self {
            key: AttributeKey(hint.key),
            op: Operator::try_from(hint.op).unwrap_or_default(),
            value: AttributeValue("".to_string()),
        }
    }
}

impl From<AttributeKOV> for wurbo::prelude::Value {
    fn from(attribute: AttributeKOV) -> Self {
        Self::from_struct_object(attribute)
    }
}

/// Hints are only the key and operator values
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct Hint {
    /// Key
    pub key: AttributeKey,
    /// Operator
    pub op: Operator,
}

impl Hint {
    /// Create a new AttributeHint from AttributeKey and Operator
    pub fn new(key: AttributeKey, op: Operator) -> Self {
        Self { key, op }
    }
}

impl StructObject for Hint {
    fn get_field(&self, name: &str) -> Option<Value> {
        match name {
            "key" => Some(Value::from(self.key.deref().clone())),
            "op" => Some(Value::from(self.op.clone())),
            _ => None,
        }
    }
    /// So that debug will show the values
    fn static_fields(&self) -> Option<&'static [&'static str]> {
        Some(&["key", "op"])
    }
}

impl ToString for Hint {
    fn to_string(&self) -> String {
        format!("{} {}", *self.key, self.op.to_string())
    }
}

impl From<CredentialStruct> for Vec<Vec<Hint>> {
    fn from(cred: CredentialStruct) -> Self {
        cred.entries
            .iter()
            .map(|a| a.iter().map(|a| Hint::from(a.clone())).collect::<Vec<_>>())
            .collect::<Vec<_>>()
    }
}

impl From<AttributeKOV> for Hint {
    fn from(attribute: AttributeKOV) -> Self {
        Self {
            key: attribute.key,
            op: attribute.op,
        }
    }
}

impl From<context_types::Attribute> for Hint {
    fn from(attribute: context_types::Attribute) -> Self {
        Self {
            key: AttributeKey(attribute.key),
            op: Operator::try_from(attribute.op).unwrap_or_default(),
        }
    }
}

impl From<Hint> for context_types::Hint {
    fn from(hint: Hint) -> Self {
        Self {
            key: hint.key.deref().clone(),
            op: hint.op.to_string(),
        }
    }
}

impl From<context_types::Hint> for Hint {
    fn from(hint: context_types::Hint) -> Self {
        Self {
            key: AttributeKey(hint.key),
            op: Operator::try_from(hint.op).unwrap_or_default(),
        }
    }
}

impl From<Hint> for wurbo::prelude::Value {
    fn from(hint: Hint) -> Self {
        Self::from_struct_object(hint)
    }
}
