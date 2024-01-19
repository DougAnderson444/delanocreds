use super::*;

use serde::{Deserialize, Serialize};
use std::ops::Deref;

use crate::issuer::IssuerStruct;

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
    Equal,
    /// Less Than Operator
    LessThan,
    /// Greater Than Operator
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

/// Atrribute Key Operator Value (KOV)
#[derive(Default, Clone)]
pub struct AttributeKOV {
    /// Key
    pub key: AttributeKey,
    /// Operator
    pub op: Operator,
    /// Value
    pub value: AttributeValue,
}

/// Newtype Key to create an AttributeKOV struct
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct AttributeKey(String);

impl Deref for AttributeKey {
    type Target = String;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// Newtype Value to create an AttributeKOV struct
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AttributeValue(String);

impl Deref for AttributeValue {
    type Target = String;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl AttributeKOV {
    /// Create a new AttributeKOV from AttributeKey, Operator, and AttributeValue
    pub fn new(key: AttributeKey, op: Operator, value: AttributeValue) -> Self {
        Self { key, op, value }
    }
}

impl ToString for AttributeKOV {
    fn to_string(&self) -> String {
        format!("{} {} {}", *self.key, self.op.to_string(), *self.value)
    }
}

impl From<IssuerStruct> for Vec<AttributeKOV> {
    fn from(issuer: IssuerStruct) -> Self {
        issuer.as_ref().map_or(vec![], |v| {
            v.attributes
                .iter()
                .map(|a| AttributeKOV::from(a.clone()))
                .collect::<Vec<_>>()
        })
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

/// Hints are only the key and operator values
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct AttributeHint {
    /// Key
    pub key: AttributeKey,
    /// Operator
    pub op: Operator,
}

impl AttributeHint {
    /// Create a new AttributeHint from AttributeKey and Operator
    pub fn new(key: AttributeKey, op: Operator) -> Self {
        Self { key, op }
    }
}

impl ToString for AttributeHint {
    fn to_string(&self) -> String {
        format!("{} {}", *self.key, self.op.to_string())
    }
}

impl From<IssuerStruct> for Vec<AttributeHint> {
    fn from(issuer: IssuerStruct) -> Self {
        issuer.as_ref().map_or(vec![], |v| {
            v.attributes
                .iter()
                .map(|a| AttributeHint::from(a.clone()))
                .collect::<Vec<_>>()
        })
    }
}

impl From<context_types::Attribute> for AttributeHint {
    fn from(attribute: context_types::Attribute) -> Self {
        Self {
            key: AttributeKey(attribute.key),
            op: Operator::try_from(attribute.op).unwrap_or_default(),
        }
    }
}
