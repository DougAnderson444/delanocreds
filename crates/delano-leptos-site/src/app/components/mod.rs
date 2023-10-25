//! Reusable components for the site.

/// Accept Offers
pub(crate) mod accept;
/// Reactive Input fields for [Attribute]s.
pub mod attributes;
/// Retrieves and displays (or not) the Encrypted Key from local storage / url hash.
pub mod encrypted_key;
/// Error View
pub(crate) mod error;
/// The List component (bulleted list of items).
pub(crate) mod list;
/// Navigation Bar
pub(crate) mod nav;
/// Issue Credentials component.
pub(crate) mod offer;
/// The QR Code component.
pub(crate) mod qrcode;

cfg_if::cfg_if! {
    if #[cfg(web_sys_unstable_apis)] {
        use wasm_bindgen_futures::spawn_local;
        /// Copy the given string to the clipboard.
        pub fn copy_to_clipboard(value: String) {
            let _task = spawn_local(async move {
                let window = web_sys::window().expect("window"); // { obj: val };
                let nav = window.navigator().clipboard();
                match nav {
                    Some(a) => {
                        let p = a.write_text(&value);
                        match wasm_bindgen_futures::JsFuture::from(p)
                            .await {
                                Ok(_) => {
                                    log::debug!("copied to clipboard");
                                        }
                                Err(e) => {
                                    log::warn!("failed to copy to clipboard: {:?}", e);
                                }
                            }
                    }
                    None => {
                        log::warn!("Clipboard not available in this browser.");
                    }
                };
            });
        }
    } else {
        #[allow(dead_code)]
        pub fn copy_to_clipboard(_: String) {
            log::debug!("copy_to_clipboard() not implemented on this platform");
        }
    }
}
