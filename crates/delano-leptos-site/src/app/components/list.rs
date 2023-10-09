// A Leptos UL component

use leptos::*;

/// Wraps each child in an `<li>` and embeds them in a `<ul>`.
#[component]
pub fn List(children: Children) -> impl IntoView {
    // children(cx) returns a `Fragment`, which has a
    // `nodes` field that contains a Vec<View>
    // this means we can iterate over the children
    // to create something new!
    let children = children()
        .nodes
        .into_iter()
        .map(|child| view! { <CheckedItem>{child}</CheckedItem> })
        .collect::<Vec<_>>();

    view! { <ul class="p-2 m-2 space-y-4">{children}</ul> }
}

#[component]
pub fn CheckedItem(children: Children) -> impl IntoView {
    view! {
        <li class="flex items-center">
            <svg
                class="h-6 w-6 flex-none fill-sky-100 stroke-sky-500 stroke-2"
                stroke-linecap="round"
                stroke-linejoin="round"
            >
                <circle cx="12" cy="12" r="11"></circle>
                <path d="m8 13 2.165 2.165a1 1 0 0 0 1.521-.126L16 9" fill="none"></path>
            </svg>
            <p class="ml-4">{children()}</p>
        </li>
    }
}