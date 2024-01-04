//! User Interface state management.
//! Since the UI only outputs raw HTML and the front end has minimal JavScript to provide
//! interactivity, the state is managed here in Rust.
//!
//! The User Interface State is essentially a thin wrapper around the WIT types, as we then pass
//! these WIT types to the backend to be processed.
//!
//! This UI simply provides the mechanisms to update the values of those types to what the user
//! wants before they are shipped off back stage to be processed.
use super::*;
// types.{attribute, provables, verifiables, offer-config, nonce};
use bindings::delano::wallet::types::{
    Attribute, Entry, Nonce, OfferConfig, Provables, Redactables, Verifiables,
};

/// There are a number of States that the UI can be in:
/// - `Issuing` { attributes: Vec<Attributes>, maxentries: u8, nonce: Option<Vec<u8>> } - The user is issuing a credential.
/// - `Offering` { offer_config: OfferConfig } - The user is offering a credential.
/// - `Accepting` - The user is accepting a credential.
/// - `Proving` - The user is proving a credential.
/// - `Verifying` - The user is verifying a credential.
#[derive(Debug)]
pub enum State {
    Issuing {
        attributes: Vec<Attribute>,
        maxentries: Option<u8>,
        nonce: Option<Vec<u8>>,
    },
    // Offering {
    //     offer_config: OfferConfig,
    // },
    // Accepting,
    // Proving,
    // Verifying,
}
