//! The authenticated account page.
//! If the hash doesn't exist, or hasn't been unlocked yet, redirect back to Home page.
//! Otherwise, display the account page.

use crate::app::components::copy_to_clipboard;
use crate::app::components::qrcode::QrCode;
use crate::app::constants::*;
use crate::app::state::ManagerState;
use delanocreds::{Issuer, MaxCardinality, MaxEntries};
use leptos::{leptos_dom::helpers::location_hash, *};
use leptos_router::unescape;

/// Use Label and Pin to Create an encrypted key, and save it to the #hash part of the URL
#[component]
pub(crate) fn Account() -> impl IntoView {
    // use the seed to derive a keypair for BLS12-381 use, using delano-keys, manager, from_seed
    // read account from Global State. If use_context::<ReadSignal<ManagerState>>() returns some
    // manager, use it and continue to view this page. If not, use_navigate to redirect to Home page
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

        let expanded = account.expand_to(MaxEntries::new(8).into());

        // now use these secret keys in Issuer
        let issuer = Issuer::new_with_secret(expanded, MaxCardinality::new(4));

        // <!-- // value={issuer.public.to_string().into()} issuer.public.to_string().clone().into()-->
        let qrvalue = issuer.public.to_compact().to_string();
        let value_copy = qrvalue.to_owned();
        view! {
            <div class="mx-auto max-w-md">
                <div class="">
                    "Let's Create some Credentials! Using account public info (G1, G2, Public Parameters):"
                </div>
                <div class="mt-4 font-semibold">"Publish Your Public Parameters:"</div>
                // Summary QR Code
                <details class="mt-4">
                    <summary class="font-semibold">"Social Media QR Code"</summary>
                    // to copy to clipboard on click: onclick=|_| { copy_to_clipboard(&qrvalue); }
                    <div
                        class="mt-4 font-mono break-all text-sm"
                        on:click=move |_| { copy_to_clipboard(value_copy.to_string()) }
                    >
                        <QrCode qrvalue=qrvalue.to_owned().into()/>
                    </div>
                </details>
                // Summary and details element
                <details class="mt-4">
                    <summary class="font-semibold">"Public Parameters"</summary>
                    <div class="mt-4 font-mono break-all text-sm">{qrvalue}</div>
                </details>
            </div>
        }
        .into_view()
    }
}
