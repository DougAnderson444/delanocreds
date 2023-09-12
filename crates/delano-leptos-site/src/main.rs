mod app;

use app::*;
use leptos::*;

fn main() {
    _ = console_log::init_with_level(log::Level::Debug);

    mount_to_body(|cx| view! { cx, <App /> })
}
