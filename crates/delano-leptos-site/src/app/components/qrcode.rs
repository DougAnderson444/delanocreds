//! QR Code Leptos Component
use leptos::*;
use qrcode::render::svg;
use qrcode::{EcLevel, QrCode, Version};

/// Wraps each child in an `<li>` and embeds them in a `<ul>`.
#[component]
pub fn QrCode(qrvalue: Vec<u8>) -> impl IntoView {
    log::debug!("QrCode component data length: {:?}", qrvalue.len());

    // calculate QR Code version parameter between 1 and 40 based on the length of the qrvalue
    // the longer th  qrvalue, the higher the parameter
    // maxmium length of qrvalue is 4296
    // Ensure Minimum 1, Maximum 40, round to whole number
    let version_parameter = (qrvalue.len() as f32 / 50.0).ceil().max(1.0).min(40.0) as i16;
    log::debug!(
        "QrCode component version parameter: {:?}",
        version_parameter
    );

    let code = match QrCode::with_version(qrvalue, Version::Normal(version_parameter), EcLevel::L) {
        Ok(code) => code,
        Err(e) => {
            log::error!("Error generating QR Code: {:?}", e);
            return view! { <div class="p-2 m-2 space-y-4" inner_html="Error generating QR Code"></div> };
        }
    };
    let image = code
        .render()
        .min_dimensions(200, 200)
        .dark_color(svg::Color("#300000"))
        .light_color(svg::Color("#ffffff"))
        .build();
    view! { <div class="p-2 m-2 space-y-4" inner_html=image></div> }
}
