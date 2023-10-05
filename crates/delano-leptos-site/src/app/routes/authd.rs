//! The authenticated account page.
//! If the hash doesn't exist, or hasn't been unlocked yet, redirect back to Home page.
//! Otherwise, display the account page.

use delanocreds::{Issuer, MaxCardinality};
use leptos::*;
// use leptos_router::use_navigate;

use seed_keeper_core::{derive_key, seed::Seed, ExposeSecret};

use crate::app::LabelAndPin;

/// Use Label and Pin to Create an encrypted key, and save it to the #hash part of the URL
#[component]
pub(crate) fn Authd() -> impl IntoView {
    // use the seed to derive a keypair for BLS12-38 use, using delano-keys, manager, from_seed
    // let manager = delano_keys::kdf::Manager::from_seed(seed);
    // let account = manager.account(1);
    //
    // let expanded = account.expand_to(MaxEntries::default().into());
    //
    // // now use these secret keys in Issuer
    // let issuer = Issuer::new_with_secret(expanded, MaxCardinality::default());

    view! { "Let's Create some Credentials!" }
}
