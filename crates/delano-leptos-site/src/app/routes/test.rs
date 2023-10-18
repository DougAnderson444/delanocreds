//! For testing components without havign to authenticate
use crate::app::components::*;
use leptos::*;

/// List the components to test here
#[component]
pub fn Test() -> impl IntoView {
    // create a new Issuer signal and add it to context
    let max_cardinality = delanocreds::MaxCardinality::new(12);

    let (issuer, _write) = create_signal(delanocreds::Issuer::new(
        max_cardinality.clone(),
        delanocreds::MaxEntries::new(6),
    ));
    provide_context(issuer);

    view! {
        <div class="mx-auto">
            // <div class="mt-4 font-semibold">"Test Components:"</div>
            // <div class="mt-4">
            // <div class="mt-4 font-semibold">"QrCode:"</div>
            // <qrcode::QrCode qrvalue="test".to_string().into()></qrcode::QrCode>
            // </div>
            // <div class="mt-4">
            // <div class="mt-4 font-semibold">"Copy to Clipboard:"</div>
            // <div class="mt-4 font-mono break-all text-sm">
            // <input type="text" value="test" id="copy-to-clipboard" class="w-full"/>
            // </div>
            // </div>
            <div class="m-4 border-4 border-dashed p-4">
                <offer::OfferForm max_cardinality></offer::OfferForm>
            </div>
        </div>
    }
}
