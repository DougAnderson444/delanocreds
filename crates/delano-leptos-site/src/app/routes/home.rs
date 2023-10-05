use leptos::ev::SubmitEvent;
use leptos::{leptos_dom::helpers::location_hash, *};
use leptos_router::unescape;
use seed_keeper_core::seed::Seed;
use seed_keeper_core::{derive_key, ExposeSecret};

use crate::app::components::list::List;
// use crate::app::screens::CreateKey;
use crate::app::LabelAndPin;

// /// The Label and Encrypted key params in the hash value
// #[derive(Params)]
// struct SavedParams {
//     pub label: String,
//     pub encrypted_key: String,
// }

#[component]
pub(crate) fn Home() -> impl IntoView {
    let (label_and_pin, set_label_n_pin) = create_signal(LabelAndPin::default());

    // share the ability to set and read pin info to all children
    provide_context(set_label_n_pin);

    let hash = location_hash().as_ref().map(|hash| unescape(hash));

    // To make this reactive based on LabelAndPin changes, we make it a closure
    move || {
        match hash.clone() {
            Some(h) if !h.is_empty() => {
                match (move || label_and_pin.get())() {
                    LabelAndPin { label, .. } if label.is_empty() => {
                        // No label, so show create screen
                        log::info!("Hash: {:?} but no label yet", h);
                        view! { <Splash/> }.into_view()
                    }
                    lap => {
                        // There is a label, so use it to create the key
                        log::info!("Label {:?} and Hash: {:?}", lap.label, h);
                        // view! { <CreateKey label_and_pin=lap/> }
                        authn(label_and_pin())
                    }
                }
            }
            _ => {
                match (move || label_and_pin.get())() {
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
    }
    // move || active_view.get()
}

/// Wraps each child in an `<li>` and embeds them in a `<ul>`.
#[component]
pub fn Splash() -> impl IntoView {
    view! {
        <div class="my-0 mx-auto max-w-3xl text-center">
            <List>
                <p>
                    "Create & Publish your"
                    <code class="text-sm font-bold text-gray-900 bg-green-200 p-2 ml-1 rounded">
                        "Verification Key"
                    </code>
                </p>
                <p>
                    "Issue some"
                    <code class="text-sm font-bold text-gray-900 bg-green-200 p-2 ml-1 rounded">
                        "Credentials"
                    </code>
                </p>
                <p>
                    "Send them to your"
                    <code class="text-sm font-bold text-gray-900 bg-green-200 p-2 ml-1 rounded">
                        "Contacts"
                    </code>
                </p>
            </List>
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

    view! {
        <div class="flex flex-col items-center justify-center">
            <div class="text-2xl font-sans tracking-tight items-center justify-center">"Label"</div>
            <input
                placeholder="My main wallet"
                class="p-2 my-2 border rounded-lg w-full bg-gray-50"
                type="text"
                on:input=move |ev| {
                    set_label(event_target_value(&ev));
                }

                // the `prop:` syntax lets you update a DOM property,
                // rather than an attribute.
                prop:value=label
            />
        </div>

        // <!-- only show the last Number, all other leading numbers convert to * -->
        <p>
            "Pin "
            {move || {
                pin()
                    .chars()
                    .map(|c| if c == pin().chars().last().unwrap() { c } else { '*' })
                    .collect::<String>()
            }}

        </p>
        // note the on:click instead of on_click
        // this is the same syntax as an HTML element event listener
        <div class="flex flex-col items-center justify-center">
            <div class="flex flex-row justify-between w-full space-x-2">
                <PinButton
                    label="1".to_string()
                    on:click=move |_| set_pin.update(|value| *value = value.to_owned() + "1")
                />
                <PinButton
                    label="2".to_string()
                    on:click=move |_| set_pin.update(|value| *value = value.to_owned() + "2")
                />
                <PinButton
                    label="3".to_string()
                    on:click=move |_| set_pin.update(|value| *value = value.to_owned() + "3")
                />
            </div>
            <div class="flex flex-row justify-between w-full space-x-2">
                <PinButton
                    label="4".to_string()
                    on:click=move |_| set_pin.update(|value| *value = value.to_owned() + "4")
                />
                <PinButton
                    label="5".to_string()
                    on:click=move |_| set_pin.update(|value| *value = value.to_owned() + "5")
                />
                <PinButton
                    label="6".to_string()
                    on:click=move |_| set_pin.update(|value| *value = value.to_owned() + "6")
                />
            </div>
            <div class="flex flex-row justify-between w-full space-x-2">
                <PinButton
                    label="7".to_string()
                    on:click=move |_| set_pin.update(|value| *value = value.to_owned() + "7")
                />
                <PinButton
                    label="8".to_string()
                    on:click=move |_| set_pin.update(|value| *value = value.to_owned() + "8")
                />
                <PinButton
                    label="9".to_string()
                    on:click=move |_| set_pin.update(|value| *value = value.to_owned() + "9")
                />
            </div>
            <div class="flex flex-row justify-between w-full space-x-2">
                <div class="w-20"></div>
                <PinButton
                    label="0".to_string()
                    on:click=move |_| set_pin.update(|value| *value = value.to_owned() + "0")
                />
                <div class="w-20"></div>
            </div>
            <form on:submit=on_submit>
                <input
                    type="password"
                    name="pin"
                    value=move || pin.get()
                    autocomplete="current-password"
                />
                <input type="text" name="label" autocomplete="username" value=move || label.get()/>
                <div class="flex flex-row justify-between w-full space-x-2">
                    <input
                        type="submit"
                        value=move || { button_label() }
                        disabled=move || pin_too_short() || label_too_short() || generating()
                        class="w-full px-4 py-4 my-1 rounded shadow-lg disabled:bg-red-400 bg-green-500 disabled:text-slate-100 text-white cursor-pointer"
                        class=("bg-red-400", move || generating() == true)
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
    use crate::app::constants::ACCOUNT;
    use base64::{engine::general_purpose, Engine as _};

    // get random 32 bytes using getrandom
    let mut seed = Seed::new([0u8; 32].into());
    if let Err(e) = getrandom::getrandom(&mut seed) {
        log::error!("getrandom failed: {:?}", e);
    }

    log::debug!("Generating key...");

    let key = derive_key(&label_and_pin.pin, &label_and_pin.label).expect("Key to derive fine");

    // log::debug!("Generated key: {:?}", key);
    let encrypted = seed_keeper_core::wrap::encrypt(
        (&key.expose_secret()[..])
            .try_into()
            .expect("seed to be 32 bytes"),
        &seed.as_ref(),
    );

    log::debug!("Encrypted key: {:?}", encrypted);

    // and we store encrypted key in the URL fragment for easy bookmarking
    let hash = format!(
        "#label={}&encrypted_key={}",
        label_and_pin.label,
        general_purpose::URL_SAFE_NO_PAD.encode(encrypted)
    );

    let navigate = leptos_router::use_navigate();
    request_animation_frame(move || {
        _ = navigate(&format!("{ACCOUNT}/{hash}"), Default::default());
    });
    view! { <pre>"Navigating to Account page..."</pre> }.into_view()
}
