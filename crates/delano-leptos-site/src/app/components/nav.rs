//! The Navigation bar
use leptos::*;

#[component]
pub fn Nav() -> impl IntoView {
    let formatting = "text-sm font-semibold text-gray-900 outline outline-sky-500 p-1 m-1 rounded";
    view! {
        <div class="my-0 mx-auto max-w-3xl text-center">
            <h2 class="p-6 text-4xl font-bold">"Delanocreds."</h2>
            <h3 class="italic">
                "Exchange " <span class=formatting>"street cred"</span> " with your contacts"
            </h3>
        </div>
    }
}
