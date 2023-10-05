mod app;

use app::*;
use cfg_if::cfg_if;
use leptos::*;

cfg_if! {
    if #[cfg(feature = "wasm-logger")] {
        fn init_log() {
            console_error_panic_hook::set_once();
            wasm_logger::init(wasm_logger::Config::default());
        }
    } else {
        fn init_log() {}
    }
}

fn main() {
    init_log();

    mount_to_body(|| view! { <App/> })
}
