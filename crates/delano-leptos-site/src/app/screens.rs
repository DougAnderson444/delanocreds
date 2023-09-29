use crate::app::list::List;
use leptos::*;
// use leptos_router::use_navigate;

use seed_keeper_core::{derive_key, ExposeSecret, Input};

/// The Label and Encrypted key params in the hash value
///
/// `label` - A 6+ character string, usually a username, email, or phrase to identify the key
/// `pin` - A 4+ digit pin to encrypt the key
#[derive(Default, Clone)]
pub(crate) struct LabelAndPin {
    pub label: String,
    pub(crate) pin: String,
}

/// Wraps each child in an `<li>` and embeds them in a `<ul>`.
#[component]
pub fn Splash(cx: Scope) -> impl IntoView {
    let (count, set_count) = create_signal(cx, 0);

    view! {
        cx,
        <div class="my-0 mx-auto max-w-3xl text-center">
            <h2 class="p-6 text-4xl font-bold">"Delanocreds."</h2>
            <List>
                <p>
                    "Create & Publish your"
                    <code class="text-sm font-bold text-gray-900 bg-green-200 p-2 ml-1 rounded">"Verification Key"</code>
                </p>
                <p>
                    "Issue some"
                    <code class="text-sm font-bold text-gray-900 bg-green-200 p-2 ml-1 rounded">"Credentials"</code>
                </p>
                <p>"Send them to your"
                    <code class="text-sm font-bold text-gray-900 bg-green-200 p-2 ml-1 rounded">"Contacts"</code>
                </p>
            </List>
            <div class="flex flex-col items-center justify-center p-2">
                <PinPad />
            </div>
        </div>
    }
}

#[component]
pub fn PinPad(cx: Scope) -> impl IntoView {
    let (pin, set_pin) = create_signal(cx, "".to_string());
    let (label, set_label) = create_signal(cx, "".to_string());

    let pin_too_short = { move || pin.get().len() < 4 };
    let label_too_short = { move || label.get().len() < 8 };
    let button_label = move || match (pin_too_short(), label_too_short()) {
        (true, true) => "Label and Pin too short",
        (true, false) => "Pin too short",
        (false, true) => "Label too short",
        (false, false) => "Enter",
    };

    let setter =
        use_context::<WriteSignal<LabelAndPin>>(cx).expect("to have found the setter provided");

    view! { cx,

        <div class="flex flex-col items-center justify-center">
            <div class="text-2xl font-sans tracking-tight items-center justify-center">"Label"</div>
            <input
                placeholder="My main wallet"
                class="p-2 my-2 border rounded-lg w-full bg-gray-50"
                type="text"
                on:input=move |ev| {
                    // event_target_value is a Leptos helper function
                    // it functions the same way as event.target.value
                    // in JavaScript, but smooths out some of the typecasting
                    // necessary to make this work in Rust
                    set_label(event_target_value(&ev));
                }

                // the `prop:` syntax lets you update a DOM property,
                // rather than an attribute.
                prop:value=label
            />
        </div>

        // <!-- only show the last Number, all other leading numbers convert to * -->
        <p>"Pin " {move || pin().chars().map(
            |c| if c == pin().chars().last().unwrap() {
                c
            } else {
                '*'
            }
        ).collect::<String>()
        }</p>
        // note the on:click instead of on_click
        // this is the same syntax as an HTML element event listener
        <div class="flex flex-col items-center justify-center">
            <div class="flex flex-row justify-between w-full space-x-2">
                <PinButton label="1".to_string() on:click=move |_| set_pin.update(|value| *value = value.to_owned() + "1")/>
                <PinButton label="2".to_string() on:click=move |_| set_pin.update(|value| *value = value.to_owned() + "2")/>
                <PinButton label="3".to_string() on:click=move |_| set_pin.update(|value| *value = value.to_owned() + "3")/>
            </div>
            <div class="flex flex-row justify-between w-full space-x-2">
                <PinButton label="4".to_string() on:click=move |_| set_pin.update(|value| *value = value.to_owned() + "4")/>
                <PinButton label="5".to_string() on:click=move |_| set_pin.update(|value| *value = value.to_owned() + "5")/>
                <PinButton label="6".to_string() on:click=move |_| set_pin.update(|value| *value = value.to_owned() + "6")/>
            </div>
            <div class="flex flex-row justify-between w-full space-x-2">
                <PinButton label="7".to_string() on:click=move |_| set_pin.update(|value| *value = value.to_owned() + "7")/>
                <PinButton label="8".to_string() on:click=move |_| set_pin.update(|value| *value = value.to_owned() + "8")/>
                <PinButton label="9".to_string() on:click=move |_| set_pin.update(|value| *value = value.to_owned() + "9")/>
            </div>
            <div class="flex flex-row justify-between w-full space-x-2">
                <div class="w-20" />
                <PinButton label="0".to_string() on:click=move |_| set_pin.update(|value| *value = value.to_owned() + "0")/>
                <div class="w-20" />
            </div>
            <div class="flex flex-row justify-between w-full space-x-2">
                <button
                    class="bg-blue-500 w-full text-white px-4 py-2 my-1 rounded shadow"
                    disabled={move || pin_too_short() || label_too_short()}
                    on:click=move |_| setter.update(|value| {
                        *value = LabelAndPin {
                        label: label.get().to_owned(),
                        pin: pin.get().to_owned(),
                    }})
                    >{move || { button_label() }}
                </button>
            </div>
        </div>
    }
}

/// Pin pad button component
#[component]
pub fn PinButton(cx: Scope, label: String) -> impl IntoView {
    view! {
        cx,
        <button type="number" class="px-4 py-2 my-1 rounded border w-full mb-2 bg-slate-100 border-slate-300" >
            {label}
        </button>
    }
}

/// Use Label and Pin to Create an encrypted key, and save it to the #hash part of the URL
#[component]
pub(crate) fn CreateKey(cx: Scope, label_and_pin: LabelAndPin) -> impl IntoView {
    use base64::{engine::general_purpose, Engine as _};

    // get random 32 bytes using getrandom
    let mut seed = [0u8; 32];
    if let Err(e) = getrandom::getrandom(&mut seed) {
        log::error!("getrandom failed: {:?}", e);
    }

    log::debug!("Generating key...");

    let key = match derive_key(&label_and_pin.pin, &label_and_pin.label) {
        Ok(key) => key,
        Err(e) => {
            log::error!("Failed to generate key: {:?}", e);
            return view! {cx,
                "Failed to generate key"
            };
        }
    };

    // log::debug!("Generated key: {:?}", key);
    let encrypted = seed_keeper_core::wrap::encrypt(
        (&key.expose_secret()[..])
            .try_into()
            .expect("seed to be 32 bytes"),
        &seed,
    );

    log::debug!("Encrypted key: {:?}", encrypted);

    // and we store encrypted key in the URL fragment for easy bookmarking
    let hash = format!(
        "#label={}&encrypted_key={}",
        label_and_pin.label,
        general_purpose::URL_SAFE_NO_PAD.encode(encrypted)
    );

    let navigate = leptos_router::use_navigate(cx);
    request_animation_frame(move || {
        _ = navigate(&format!("{}{hash}", env!("BASE_PATH")), Default::default());
    });

    view! {cx,
        "Your key has been created!"
    }
}

/// Use Label and Pin to Create an encrypted key, and save it to the #hash part of the URL
#[component]
pub(crate) fn DecryptKey(cx: Scope, label_and_pin: LabelAndPin) -> impl IntoView {
    // get random 32 bytes
    view! {cx,
        "Let's decrypt your key for you."
    }
}
