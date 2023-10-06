//! The authenticated account page.
//! If the hash doesn't exist, or hasn't been unlocked yet, redirect back to Home page.
//! Otherwise, display the account page.

use crate::app::constants::*;
use crate::app::state::ManagerState;
use base64::{engine::general_purpose, Engine as _};
use delano_keys::kdf::GroupEncoding;
use delanocreds::{Issuer, MaxCardinality, MaxEntries};
use leptos::{leptos_dom::helpers::location_hash, *};
use leptos_router::unescape;

/// Use Label and Pin to Create an encrypted key, and save it to the #hash part of the URL
#[component]
pub(crate) fn Account() -> impl IntoView {
    // use the seed to derive a keypair for BLS12-38 use, using delano-keys, manager, from_seed
    // read account from Global State. If use_context::<ReadSignal<ManagerState>>() returns some
    // manager, use it and continue to view this page. If not, use_navigate to redirect to Home page
    log::debug!("Account page");

    let maybe_manager = expect_context::<ReadSignal<ManagerState>>();
    let navigate = leptos_router::use_navigate();
    let hash = location_hash()
        .as_ref()
        .map(|hash| unescape(hash))
        .unwrap_or("".to_string());

    log::debug!("Account page hash: {:?}", hash);

    // if none, redirect
    if maybe_manager.get().is_none() {
        let dest = format!("{HOME}#{hash}");
        log::debug!("No manager, redirecting to Home page {dest}");
        navigate(&dest, Default::default());
        view! { "Navigating home..."}.into_view()
    } else {
        // if some, continue
        let m = maybe_manager.get().unwrap();

        let account = m.account(1);

        let expanded = account.expand_to(MaxEntries::default().into());

        // now use these secret keys in Issuer
        let _issuer = Issuer::new_with_secret(expanded, MaxCardinality::default());

        let pk_g1 = account.pk_g1.to_bytes();

        let vk_g1_b64 = general_purpose::URL_SAFE_NO_PAD.encode(pk_g1);

        view! {
            <div class="font-mono">
                "Let's Create some Credentials! Using account public keys (G1 and G2):"
                <pre class="font-mono">{vk_g1_b64.to_string()}</pre>
            </div>
        }
        .into_view()
    }
}
