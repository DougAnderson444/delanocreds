// use delanocreds::{Issuer, MaxCardinality};
// use leptos::*;
// // use leptos_router::use_navigate;
//
// use seed_keeper_core::{derive_key, seed::Seed, ExposeSecret};
//
// use crate::app::LabelAndPin;
//
// /// Use Label and Pin to Create an encrypted key, and save it to the #hash part of the URL
// #[component]
// pub(crate) fn CreateKey(label_and_pin: LabelAndPin) -> impl IntoView {
//     use base64::{engine::general_purpose, Engine as _};
//     use delanocreds::MaxEntries;
//
//     // get random 32 bytes using getrandom
//     let mut seed = Seed::new([0u8; 32].into());
//     if let Err(e) = getrandom::getrandom(&mut seed) {
//         log::error!("getrandom failed: {:?}", e);
//     }
//
//     log::debug!("Generating key...");
//
//     let key = match derive_key(&label_and_pin.pin, &label_and_pin.label) {
//         Ok(key) => key,
//         Err(e) => {
//             log::error!("Failed to generate key: {:?}", e);
//             return view! { "Failed to generate key" };
//         }
//     };
//
//     // log::debug!("Generated key: {:?}", key);
//     let encrypted = seed_keeper_core::wrap::encrypt(
//         (&key.expose_secret()[..])
//             .try_into()
//             .expect("seed to be 32 bytes"),
//         &seed.as_ref(),
//     );
//
//     log::debug!("Encrypted key: {:?}", encrypted);
//
//     // and we store encrypted key in the URL fragment for easy bookmarking
//     let hash = format!(
//         "#label={}&encrypted_key={}",
//         label_and_pin.label,
//         general_purpose::URL_SAFE_NO_PAD.encode(encrypted)
//     );
//
//     let navigate = leptos_router::use_navigate();
//     request_animation_frame(move || {
//         _ = navigate(
//             &format!("{}/authd/{hash}", env!("BASE_PATH")),
//             Default::default(),
//         );
//     });
// }
//
// /// Use Label and Pin to Create an encrypted key, and save it to the #hash part of the URL
// #[component]
// pub(crate) fn DecryptKey(label_and_pin: LabelAndPin) -> impl IntoView {
//     // get random 32 bytes
//     view! { "Let's decrypt your key for you." }
// }
