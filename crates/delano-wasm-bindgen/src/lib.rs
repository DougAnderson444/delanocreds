//! Once a Seed Manager has been loaded using [`load_seed`], it can be used
//! to perform operations on the Issuer such as loading an account and generating
//! an Issuer for an account length.
//!
//! If no seed has been loaded, the [`SEED_MANAGER`] will be empty and the API
//! functions will return errors.
mod utils;

use delano_crypto::{basic::BasicSecretsManager, Seed};
use delanocreds::{Issuer, IssuerPublic, MaxCardinality};
use std::sync::Mutex;
use wasm_bindgen::prelude::*;

// We cannot have &self in the Component struct,
// so we use static variables to store the state between functions
// See https://crates.io/crates/lazy_static
lazy_static::lazy_static! {
    /// Variable to hold the [`delano_crypto::basic::BasicSecretsManager`]
    static ref SEED_MANAGER: Mutex<Option<BasicSecretsManager>> = Mutex::new(None);
    /// [`ISSUER`] holds the currently active [`Issuer`] for the currently active [`BasicSecretsManager`] Account
    ///
    /// Technically you could have many Issuers for one Account, all with different account sizes,
    /// but for simplicity we only allow one Issuer per Account.
    ///
    /// If users want a different sized account, they can create a new Account and load a new Issuer.
    ///
    /// The Root Verification key for the Issuer's account is always the same no matter the length,
    /// since they are derived using hierarchical deterministic keys.
    static ref ISSUER: Mutex<Option<Issuer>> = Mutex::new(None);
}

/// Wrap the IssuerPublic so we can return it to JS
#[wasm_bindgen]
pub struct IssuerPublicWrapper(IssuerPublic);

/// Load the given 32 bytes into the Seed Manager.
#[wasm_bindgen]
pub fn load_seed(bytes: &[u8]) -> Result<bool, JsValue> {
    let sized: [u8; 32] = bytes.try_into().expect("seed should be 32 bytes long"); // has to be 32 bytes
    let seed = Seed::new(sized);
    let manager =
        BasicSecretsManager::from_seed(seed).map_err(|e| JsValue::from_str(&format!("{:?}", e)))?;
    SEED_MANAGER.lock().unwrap().replace(manager);
    Ok(true)
}

/// Uses the [`SEED_MANAGER`] to create an [Issuer] for the given account index
/// and account size (attributes length, aka [`MaxCardinality`]).
///
/// Returns the public verfification key of the Issuer.
#[wasm_bindgen]
pub fn set_account(account_index: u32, account_size: u32) -> Result<IssuerPublicWrapper, JsValue> {
    let manager = SEED_MANAGER
        .lock()
        .expect("should be able to obtain read lock on SEED_MANAGER");
    let manager = manager.as_ref().ok_or(JsValue::from_str(
        "Seed Manager not loaded. Call load_seed() first.",
    ))?;
    let account = manager.account(account_index);
    let sk = account.derive(account_size);
    let issuer = Issuer::new_with_secret(sk, MaxCardinality::new(account_size as usize));
    Ok(IssuerPublicWrapper(issuer.public))
}
