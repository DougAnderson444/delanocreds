//! Shows the Encrypted Key from local storage, if any
use base64::{engine::general_purpose, Engine as _};
use gloo_storage::Storage;
use leptos::leptos_dom::helpers::location_hash;
use leptos::*;
use leptos_router::unescape;

/// The EncryptedKey type
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct EncryptedKey(pub Vec<u8>);

/// Trys to convert from String to [EncryptedKey] struct by decoding base64 into bytes
impl TryFrom<&String> for EncryptedKey {
    type Error = base64::DecodeError;

    fn try_from(value: &String) -> Result<Self, Self::Error> {
        let bytes = general_purpose::URL_SAFE_NO_PAD.decode(value.as_bytes())?;
        Ok(Self(bytes))
    }
}

/// TryFrom owned String
impl TryFrom<String> for EncryptedKey {
    type Error = base64::DecodeError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        let bytes = general_purpose::URL_SAFE_NO_PAD.decode(value.as_bytes())?;
        Ok(Self(bytes))
    }
}

impl ToString for EncryptedKey {
    fn to_string(&self) -> String {
        general_purpose::URL_SAFE_NO_PAD.encode(&self.0)
    }
}

/// This function check for a url hash for encrypted_key and also checks local storage
/// For this demo there can only be one saved key, but for a real world app perhaps there are
/// many keys
/// TODO: Add a way to select which key to use
/// If there is both a local storage key and a url hash key, the url hash key takes precedence
/// If there is neither, the returned view is empty (show nothing)
///
/// The key is saved as a string in Storage/URL, so this component converts it to a Vec<u8> for
/// use in the app
#[component]
pub fn ShowEncryptedKey(set_encrypted_key: WriteSignal<EncryptedKey>) -> impl IntoView {
    // check the hash, if any, use it first.
    let hash = location_hash().as_ref().map(|hash| unescape(hash));

    match hash {
        Some(h) if !h.is_empty() => {
            log::info!("hash: {}", h);
            // parse hash string by & delimiter, see if there is an encrypted_key
            let mut key = None;
            for pairs in h.split('&') {
                let mut kv = pairs.split('=');
                if let (Some(k), Some(v)) = (kv.next(), kv.next()) {
                    if k == "encrypted_key" {
                        key = Some(v.to_string());
                        break;
                    }
                }
            }
            match key {
                Some(key) if EncryptedKey::try_from(&key).is_ok() => {
                    let k = EncryptedKey::try_from(&key).expect("to be ok");
                    set_encrypted_key.set(k);
                    view! { <EncryptedKeyComponent key=key/> }.into_view()
                }
                _ => view! {}.into_view(),
            }
        }
        // No valid hash, check local storage
        _ => {
            log::info!("no URL hash, check storage");
            let storage = gloo_storage::LocalStorage::raw();
            log::info!("storage: {:?}", storage);
            match storage.get("encrypted_key") {
                Ok(Some(key)) if EncryptedKey::try_from(&key).is_ok() => {
                    log::debug!("Found encrypted_key in local storage: {}", key);
                    let k = EncryptedKey::try_from(&key).expect("to be ok");
                    log::debug!("k: {:?}", k);
                    set_encrypted_key.set(k);

                    view! { <EncryptedKeyComponent key=key/> }
                }
                _ => view! {}.into_view(),
            }
        }
    }
}

/// Component to Show EncryptedKey
#[component]
fn EncryptedKeyComponent(key: String) -> impl IntoView {
    view! {
        <div class="w-full">
            <h3>"Encrypted Key"</h3>
            <input type="text" value=key readonly=true class="text-xs w-full text-center"/>
        </div>
    }
}
