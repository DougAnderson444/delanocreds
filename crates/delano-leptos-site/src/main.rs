mod app;

use app::*;
use cfg_if::cfg_if;
use leptos::*;

cfg_if! {
    if #[cfg(feature = "console_log")] {
        fn init_log() {
            use log::Level;
            console_log::init_with_level(log::Level::Debug).expect("log should initilize fine");
        }
    } else {
        fn init_log() {}
    }
}

fn main() {
    init_log();

    mount_to_body(|| view! { <App/> })
}
