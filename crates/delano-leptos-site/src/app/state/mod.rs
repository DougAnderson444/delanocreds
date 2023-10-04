//! Module for in-memory state
//! We keep the seed, keys, and pin here so as not to epxose them in the URL.
//!

use std::fmt::Display;

use seed_keeper_core::Zeroizing;

/// The Label and Encrypted key params in the hash value
///
/// `label` - A 6+ character string, usually a username, email, or phrase to identify the key
/// `pin` - A 4+ digit pin to encrypt the key
#[derive(Default, Clone, Debug)]
pub(crate) struct LabelAndPin {
    pub label: Label,
    pub(crate) pin: Zeroizing<String>,
}

#[derive(Default, Clone, Debug, PartialEq)]
pub(crate) struct Label(pub(crate) Zeroizing<String>);

impl Display for Label {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::ops::Deref for Label {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<String> for Label {
    fn from(s: String) -> Self {
        Self(Zeroizing::new(s))
    }
}

impl AsRef<[u8]> for Label {
    fn as_ref(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

impl AsRef<str> for Label {
    fn as_ref(&self) -> &str {
        &self.0
    }
}
