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
    // use the seed to derive a keypair for BLS12-381 use, using delano-keys, manager, from_seed
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
        view! { "Navigating home..." }.into_view()
    } else {
        // if some, continue
        let m = maybe_manager.get().unwrap();

        let account = m.account(1);

        let expanded = account.expand_to(MaxEntries::default().into());

        // now use these secret keys in Issuer
        let issuer = Issuer::new_with_secret(expanded, MaxCardinality::default());

        let vk_g1_b64 = general_purpose::URL_SAFE_NO_PAD.encode(account.pk_g1.to_bytes());
        let vk_g2_b64 = general_purpose::URL_SAFE_NO_PAD.encode(account.pk_g2.to_bytes());

        view! {
            <div class="mx-auto max-w-md">
                <div class="">
                    "Let's Create some Credentials! Using account public info (G1, G2, Public Parameters):"
                    <div class="mt-4 font-mono break-all">{vk_g1_b64.to_string()}.{vk_g2_b64}</div>
                </div>
                <div class="mt-4 font-semibold">"Your Public Parameters:"</div>
                <div class="mt-4 font-mono break-all text-sm">{issuer.public.to_string()}</div>
            </div>
        }
        .into_view()
    }
}
