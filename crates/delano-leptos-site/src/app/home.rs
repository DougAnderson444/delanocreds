use leptos::{leptos_dom::helpers::location_hash, *};
use leptos_router::unescape;
use leptos_router::*;

use crate::app::screens::CreateKey;
use crate::app::screens::LabelAndPin;
use crate::app::screens::Splash;

/// The Label and Encrypted key params in the hash value
#[derive(Params)]
struct SavedParams {
    pub label: String,
    pub encrypted_key: String,
}

#[component]
pub(crate) fn Home(cx: Scope) -> impl IntoView {
    let active_view = create_rw_signal::<View>(cx, View::default());

    let (label_and_pin, set_label_n_pin) = create_signal(cx, LabelAndPin::default());

    // share the ability to set and read pin info to all children
    provide_context(cx, set_label_n_pin);

    let hash = location_hash().as_ref().map(|hash| unescape(hash));

    // This is like a Single Page App Router
    match hash {
        Some(h) if !h.is_empty() => {
            create_effect(cx, move |_| {
                match label_and_pin.get() {
                    LabelAndPin { label, .. } if label.is_empty() => {
                        // No label, so show create screen
                        log::info!("Hash: {:?} but no label yet", h);
                        active_view.update(|v| *v = view! {cx, <Splash /> })
                    }
                    lap => {
                        // There is a label, so use it to create the key
                        log::info!("Label {:?} and Hash: {:?}", lap.label, h);
                        active_view.update(|v| *v = view! {cx, <CreateKey label_and_pin=lap /> })
                    }
                }
            })
        }
        _ => {
            create_effect(cx, move |_| {
                match label_and_pin.get() {
                    LabelAndPin { label, .. } if label.is_empty() => {
                        // No label, so show create screen
                        log::info!("No Hash, no label");
                        active_view.update(|v| *v = view! {cx, <Splash /> })
                    }
                    lap => {
                        // There is a label, so use it to create the key
                        log::info!("No hash, new Label {:?}", lap.label);
                        active_view.update(|v| *v = view! {cx, <CreateKey label_and_pin=lap /> })
                    }
                }
            })
        }
    };

    move || active_view.get()
}
