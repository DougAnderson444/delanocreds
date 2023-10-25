//! QR Code Leptos Component
use leptos::*;
use qrcode_generator::QrCodeEcc;
use web_sys::Blob;

/// Reactive QR Code component that takes a reactive signal of bytes and displays a QR Code
#[component]
pub fn ReactiveQRCode(signal: ReadSignal<String>) -> impl IntoView {
    move || {
        let qrvalue = signal.get().as_bytes().to_vec();
        view! { <QrCode qrvalue=qrvalue/> }
    }
}

/// Static QRCOde Component that takes a Vec<u8> and displays a QR Code once.
#[component]
pub fn QrCode(qrvalue: Vec<u8>) -> impl IntoView {
    log::debug!("QrCode component data length: {:?}", qrvalue.len());

    let buf: Vec<u8> = match qrcode_generator::to_png_to_vec(qrvalue, QrCodeEcc::Low, 1024) {
        Ok(buf) => buf,
        Err(e) => {
            log::error!("Error generating QR Code: {:?}", e);
            return view! { <div class="p-2 m-2 space-y-4" inner_html="Error generating QR Code"></div> };
        }
    };

    // Make a Blob from the bytes
    // We needa JS UInt8Array, so we need to convert our Rust value to ByteBuf first
    let js_u8_array = match serde_wasm_bindgen::to_value(&[serde_bytes::ByteBuf::from(buf)]) {
        Ok(js_bytes) => js_bytes,
        Err(e) => {
            log::error!("Error serializing bytes: {:?}", e);
            return view! { <div class="p-2 m-2 space-y-4" inner_html="Error serializing Qr Code bytes"></div> };
        }
    };

    let mut bag = web_sys::BlobPropertyBag::new();
    bag.type_("image/png");
    let blob = match Blob::new_with_u8_array_sequence_and_options(&js_u8_array, &bag) {
        Ok(blob) => blob,
        Err(e) => {
            log::error!("Error creating Blob: {:?}", e);
            return view! { <div class="p-2 m-2 space-y-4" inner_html="Error creating Qr Code Blob"></div> };
        }
    };

    log::debug!("QrCode component blob size: {:?}", blob.size());

    // Use createObjectURL to make a URL for the blob
    let url = match web_sys::Url::create_object_url_with_blob(&blob) {
        Ok(url) => url,
        Err(e) => {
            log::error!("Error creating URL: {:?}", e);
            return view! { <div class="p-2 m-2 space-y-4" inner_html="Error creating Qr Code URL"></div> };
        }
    };
    view! {
        <div class="p-2 m-2 space-y-4">
            <img src=url/>
        </div>
    }
}
