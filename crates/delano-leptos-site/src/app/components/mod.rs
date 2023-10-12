//! Reusable components for the site.

/// The List component (bulleted list of items).
pub(crate) mod list;
/// The QR Code component.
pub(crate) mod qrcode;

cfg_if::cfg_if! {
    if #[cfg(web_sys_unstable_apis)] {
        use wasm_bindgen_futures::spawn_local;
        /// Copy the given string to the clipboard.
        pub fn copy_to_clipboard() {
            let _task = spawn_local(async move {
                let window = web_sys::window().expect("window"); // { obj: val };
                let nav = window.navigator().clipboard();
                match nav {
                    Some(a) => {
                        let p = a.write_text("please god work");
                        let result = wasm_bindgen_futures::JsFuture::from(p)
                            .await
                            .expect("clipboard populated");
                       log::info!("clippyboy worked, {:?}", result);
                    }
                    None => {
                        log::warn!("failed to copy clippyboy");
                    }
                };
            });
        }
    } else {
        #[allow(dead_code)]
        pub fn copy_to_clipboard() {
            log::debug!("copy_to_clipboard() not implemented on this platform");
        }
    }
}
