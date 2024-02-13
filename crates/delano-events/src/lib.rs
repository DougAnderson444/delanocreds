#![doc = include_str!("../README.md")]

use delano_keys::publish::PublishingKey;
use serde::{Deserialize, Serialize};

// Test the README.md code snippets
#[cfg(doctest)]
pub struct ReadmeDoctests;

/// The Context of the event.
/// This event is deisgned to pass through `jco` WIT, which expects variants to be {tag: _, val: _} in lower kebab-case.
/// Any messages serialized by serde converts Vec to an Array, however `jco` expects TypedArrays.
/// To avoid this issue, we serialize the Type bytes as base64 string to avoid missing TypedArray issue.
/// The recever simply decodes the base64, and deserializes the Vec back into the inner type.
/// Usign base64Url also makes the Message Events passable through URLs.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[serde(tag = "tag", content = "val")]
#[non_exhaustive]
pub enum Context {
    Message(String),
}

/// The Messages eitted.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[serde(tag = "tag", content = "val")]
#[non_exhaustive]
pub enum Message<T> {
    /// The Proof key values pair, serialized as base64 to avoid missing TypedArray issued in JavaScript
    /// with Uint8Array.
    ///
    ///
    Publishables(Publishables<T>),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Publishables<T> {
    /// Topic key needs to be a string for gossipsub
    key: String,
    /// Provables are the values and the proof that they belong with this key.
    value: Provables<T>,
}

impl<T> Publishables<T>
where
    T: serde::Serialize,
{
    /// Creates a new Publishables from any serializable type.
    /// This method ensures our types match in the Publishing Key and Provables Value.
    pub fn new(key: PublishingKey<T>, value: Provables<T>) -> Self {
        Self {
            key: key.cid().to_string(),
            value,
        }
    }

    /// Getter for the key
    pub fn key(&self) -> &str {
        &self.key
    }

    /// Getter for the value
    pub fn value(&self) -> &Provables<T> {
        &self.value
    }
}

/// The bytes are serialized as base64 to avoid missing TypedArray issues when passing through JavaScript in `jco`
/// They will be decoded on the receiving end back to bytes when deserialized.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Provables<T> {
    pub proof: Vec<u8>,
    pub issuer_public: Vec<u8>,
    /// The selected delanocreds::Attributes used in the proof
    pub selected: Vec<Vec<Vec<u8>>>,
    /// Preimages can be any type, such as text or images, as long as they can be serialized to bytes.
    /// These bytes are encoded as base64 to avoid missing TypedArray issues in JavaScript.
    ///
    /// When these bytes are decoded and deserialized, they will try to be converted to the original type, which
    /// is essentially embedded into the UI. That's ok, because if the preimage is an image but
    /// my UI can't handle it, it doesn't matter about the conversion because my UI can't
    /// interface to it anyway ¯\_(ツ)_/¯
    pub selected_preimages: Vec<Vec<T>>,
}