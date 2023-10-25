use crate::app::components::encrypted_key::{EncryptedKey, ShowEncryptedKey};
use crate::app::components::list::List;
use crate::app::state::ManagerState;
use crate::app::LabelAndPin;
use gloo_storage::Storage;
use leptos::ev::SubmitEvent;
use leptos::*;
use leptos_router::*;
use seed_keeper_core::seed::Seed;
use seed_keeper_core::{derive_key, ExposeSecret, Zeroizing};

// /// The Label and Encrypted key params in the hash value
// #[derive(Params)]
// struct SavedParams {
//     pub label: String,
//  pub encrypted_key: String,
// }

#[derive(Params, Debug, Clone, PartialEq, Eq, Default)]
struct HomeRedirects {
    offer: String,
}

#[component]
pub(crate) fn Home() -> impl IntoView {
    let (label_and_pin, set_label_n_pin) = create_signal(LabelAndPin::default());

    let (encrypted_key, set_encrypted_key) = create_signal(EncryptedKey::default());

    // share the ability to set and read pin info to all children
    provide_context(set_label_n_pin);
    provide_context(encrypted_key);
    provide_context(set_encrypted_key);

    // To make this reactive based on LabelAndPin changes, we make it a closure
    let active_view = move || {
        match encrypted_key.get().0 {
            encrypted_key if !encrypted_key.is_empty() => {
                match label_and_pin.get() {
                    LabelAndPin { label, .. } if label.is_empty() => {
                        // No label, so show create screen
                        log::info!("encrypted_key: {:?} but no label yet", encrypted_key);
                        view! { <Splash/> }.into_view()
                    }
                    lap => {
                        // There is a label, so use it to create the key
                        log::info!("Label {:?} and Hash: {:?}", lap.label, encrypted_key);
                        // view! { <CreateKey label_and_pin=lap/> }
                        authn(label_and_pin())
                    }
                }
            }
            _ => {
                match label_and_pin.get() {
                    LabelAndPin { label, .. } if label.is_empty() => {
                        // No label, so show create screen
                        log::info!("No Hash, no label bro");
                        view! { <Splash/> }.into_view()
                    }
                    lap => {
                        // There is a label, so use it to create the key
                        log::info!("No hash, new Label {:?}", lap.label);
                        authn(label_and_pin())
                    }
                }
            }
        }
    };

    view! {
        <ShowEncryptedKey set_encrypted_key/>
        {active_view}
    }
}

/// Wraps each child in an `<li>` and embeds them in a `<ul>`.
#[component]
pub fn Splash() -> impl IntoView {
    view! {
        <div class="my-0 mx-auto max-w-3xl text-center">
            <List>
                <p>
                    "To gain street Creds, first you'll need a "
                    <code class="text-sm font-bold text-gray-900 bg-green-200 p-2 ml-1 rounded">
                        "Cryptographic Key"
                    </code>
                </p>
                <p>
                    "Make it using a memorable "
                    <code class="text-sm font-bold text-gray-900 bg-green-200 p-2 ml-1 rounded">
                        "Label"
                    </code>
                </p>
                <p>
                    "Lock it with a "
                    <code class="text-sm font-bold text-gray-900 bg-green-200 p-2 ml-1 rounded">
                        "Passphrase"
                    </code>
                </p>
            </List>
            // <h3 class="italic">
            // "This stays "
            // <span class="text-sm font-semibold text-gray-900 outline outline-sky-500 p-1 m-1 rounded">
            // "in your browser"
            // </span> " so only you have access to it."
            // </h3>
            <div class="flex flex-col items-center justify-center p-2">
                <PinPad/>
            </div>
        </div>
    }
}

#[component]
pub fn PinPad() -> impl IntoView {
    // Indicate whether we are bus generating the key (or not)
    let generating = create_rw_signal(false);

    let (pin, set_pin) = create_signal("".to_string());
    let (label, set_label) = create_signal("".to_string());

    let pin_too_short = { move || pin.get().len() < 4 };
    let label_too_short = { move || label.get().len() < 8 };
    let button_label = move || match (pin_too_short(), label_too_short(), generating.get()) {
        (true, true, false) => "Label and Pin too short",
        (true, false, false) => "Pin too short",
        (false, true, false) => "Label too short",
        (false, false, false) => "Enter",
        (_, _, true) => "Generating key...",
    };

    let setter =
        use_context::<WriteSignal<LabelAndPin>>().expect("to have found the setter provided");

    let on_submit = move |ev: SubmitEvent| {
        // set generating to true
        generating.set(true);

        ev.prevent_default();

        log::debug!("generating: {:?}", generating.get());

        setter.update(|value| {
            *value = LabelAndPin {
                label: label.get().to_owned(),
                pin: pin.get().into(),
            }
        });
    };

    let encrypted_key = expect_context::<ReadSignal<EncryptedKey>>();

    view! {
        <div class="flex flex-row items-center justify-center space-x-2">
            <form on:submit=on_submit>
                <div class="text-xl font-semibold tracking-tight items-center justify-center">
                    // if encrypted_key.is_empty(), show "Create" , otherwise show "Unlock"
                    {if encrypted_key.get().0.is_empty() { "Create" } else { "Unlock" }}

                </div>
                <input
                    type="text"
                    name="label"
                    autocomplete="username"
                    placeholder="My main wallet"
                    class="p-2 my-2 border rounded-lg w-full bg-gray-50"
                    on:input=move |ev| {
                        set_label(event_target_value(&ev));
                    }
                />
                <input
                    type="password"
                    name="pin"
                    autocomplete="current-password"
                    placeholder="********"
                    class="p-2 my-2 border rounded-lg w-full bg-gray-50"
                    on:input=move |ev| {
                        set_pin(event_target_value(&ev));
                    }
                />
                <div class="flex flex-row justify-between w-full space-x-2">
                    <input
                        type="submit"
                        value=move || { button_label() }
                        disabled=move || pin_too_short() || label_too_short() || generating()
                        class="w-full px-4 py-4 my-1 rounded shadow-lg disabled:bg-red-400 bg-green-500 disabled:text-slate-100 text-white cursor-pointer"
                        class=("bg-red-400", move || generating())
                    />
                </div>
            </form>
        </div>
    }
}

/// Pin pad button component
#[component]
pub fn PinButton(label: String) -> impl IntoView {
    view! {
        <button
            type="number"
            class="px-4 py-2 my-1 rounded border w-full mb-2 bg-slate-100 border-slate-300"
        >
            {label}
        </button>
    }
}

fn authn(label_and_pin: LabelAndPin) -> View {
    use crate::app::constants::{ACCOUNT, OFFER};
    use base64::{engine::general_purpose, Engine as _};

    let encrypted_key = expect_context::<ReadSignal<EncryptedKey>>();

    let key = derive_key(&label_and_pin.pin, &label_and_pin.label).expect("Key to derive fine");

    let (seed, hash) = match encrypted_key.get() {
        EncryptedKey(e_key) if !e_key.is_empty() => {
            // and we store encrypted key in the URL fragment for easy bookmarking
            let hash = format!(
                "#label={}&encrypted_key={}",
                label_and_pin.label,
                general_purpose::URL_SAFE_NO_PAD.encode(e_key.clone())
            );
            let seed = Zeroizing::new(seed_keeper_core::wrap::decrypt(
                (&key.expose_secret()[..])
                    .try_into()
                    .expect("seed to be 32 bytes"),
                e_key.as_ref(),
            ));
            (seed, hash)
        }
        _ => {
            // get random 32 bytes using getrandom
            let mut seed = Seed::new([0u8; 32].into());
            if let Err(e) = getrandom::getrandom(&mut seed) {
                log::error!("getrandom failed: {:?}", e);
            }

            log::debug!("Generating key...");
            let encrypted = seed_keeper_core::wrap::encrypt(
                (&key.expose_secret()[..])
                    .try_into()
                    .expect("seed to be 32 bytes"),
                seed.as_ref(),
            );

            log::debug!("Encrypted key: {:?}", encrypted);

            let encrypted_key_b64 = general_purpose::URL_SAFE_NO_PAD.encode(encrypted);

            // and we store encrypted key in the URL fragment for easy bookmarking
            let hash = format!(
                "#label={}&encrypted_key={}",
                label_and_pin.label, encrypted_key_b64
            );

            // also store it in the browser's LOCAL_STORAGE using gloo-storage
            let storage = gloo_storage::LocalStorage::raw();
            match storage.set("encrypted_key", &encrypted_key_b64) {
                Ok(_) => log::debug!("Saved encrypted_key to local storage"),
                Err(e) => log::error!("Failed to save encrypted_key to local storage: {:?}", e),
            };
            (Zeroizing::new(seed.to_vec()), hash)
        }
    };

    let manager = delano_keys::kdf::Manager::from_seed(seed);

    // set Manager in state::GlobalState.manager
    let state = expect_context::<WriteSignal<ManagerState>>();

    state.set(Some(manager));

    // Lastly, navigate to the account page
    // Before we do, look at the query params to see if there is an offer we are claiming, ie `?offer=pWVzaWdtYa`
    let query = use_query::<HomeRedirects>();
    let offer_value = query.with(|q| q.clone().map(|q| q.offer).unwrap_or_default());

    log::debug!("offer: {:?}", offer_value);

    let navigate = leptos_router::use_navigate();

    // if offer, append it to the destination
    let dest = if offer_value.is_empty() {
        log::debug!("No offer");
        format!("{}{}", ACCOUNT, hash)
    } else {
        log::debug!("Offer found");
        format!(
            "{ACCOUNT}/{OFFER}/{offer_value}{hash}",
            offer_value = offer_value,
            hash = hash
        )
    };
    log::debug!("Navigating to: {:?}", dest);
    navigate(&dest, Default::default());

    view! { <pre>"Navigating to Account page..."</pre> }.into_view()
}
