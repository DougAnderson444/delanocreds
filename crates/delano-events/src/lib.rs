#![doc = include_str!("../README.md")]

pub mod utils;

use delano_keys::publish::PublishingKey;
use delanocreds::keypair::{CredProofCompressed, IssuerPublicCompressed};
use serde::{Deserialize, Serialize};
use utils::PayloadEncoding;

// Test the README.md code snippets
#[cfg(doctest)]
pub struct ReadmeDoctests;

/// The Context of the event, `jco` compatible (<https://github.com/bytecodealliance/jco>)
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

/// The serialized publish message, which is a key string and value bytes serialized
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublishMessage {
    pub key: String,
    pub value: Vec<u8>,
}

impl PayloadEncoding for PublishMessage {}

impl<T> From<&Publishables<T>> for PublishMessage
where
    T: serde::Serialize,
{
    fn from(publishables: &Publishables<T>) -> Self {
        Self {
            key: publishables.key(),
            // CBOR ecode the value
            value: utils::try_cbor(&publishables.value()).unwrap_or_default(),
        }
    }
}

impl<T> TryFrom<&PublishMessage> for Publishables<T>
where
    T: for<'de> serde::Deserialize<'de>,
{
    type Error = String;

    fn try_from(publish_message: &PublishMessage) -> Result<Self, Self::Error> {
        Ok(Self {
            key: publish_message.key.clone(),
            value: utils::try_from_cbor(&publish_message.value)?,
        })
    }
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
    /// The generic types in this method ensures our types match in the Publishing Key and Provables Value.
    pub fn new(key: PublishingKey<T>, value: Provables<T>) -> Self {
        Self {
            key: key.cid().to_string(),
            value,
        }
    }

    /// Getter for the key
    pub fn key(&self) -> String {
        self.key.clone()
    }

    /// Getter for the value
    pub fn value(&self) -> &Provables<T> {
        &self.value
    }

    /// Builds a [PublishMessage] from the [Publishables]
    pub fn build(&self) -> PublishMessage {
        self.into()
    }
}

/// The serializable proof package to be published. Contains both the preimages and the corresponding proof for those preimages.
/// The Issuer Pulic material should be compared to another known reference to that Isser to
/// validate they match each other. The selectec preimages are hashed into [delanocreds::Attribute]s to ensure they also match those in the proof.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Provables<T> {
    /// cred proof size is 240 + 48 * max_entries + 48 + 320 bytes.
    pub proof: CredProofCompressed,
    /// Size depends on the Max Cardinality and Max Entries.
    /// Size = (48 + 96) * (MaxCardinality + 1) + 48 + (96 * (MaxEntries + 2))
    /// | Max Cardinality  | Max Entries | Size (bytes)     |
    /// |------------------|-------------|------------------|
    /// | 1                | 1           | 228 + 336 = 564  |
    /// | 2                | 2           | 276 + 384 = 660  |
    /// | 4                | 4           | 720 + 624 = 1344 |
    pub issuer_public: IssuerPublicCompressed,
    /// The selected [delanocreds::Attribute]s used in the proof, in the right order and position
    /// (which is important when veirfying the proof).
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

/// The serializable key to subscribe to. In other words, the PubSub topic.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubscribeTopic {
    pub key: String,
}

/// From<impl ToString> for SubscribeTopic
impl<T> From<T> for SubscribeTopic
where
    T: ToString,
{
    fn from(key: T) -> Self {
        Self {
            key: key.to_string(),
        }
    }
}

impl PayloadEncoding for SubscribeTopic {}
