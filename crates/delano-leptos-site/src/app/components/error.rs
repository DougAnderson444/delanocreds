use leptos::*;

/// An Error component that shows a whoopsie message
#[component]
pub fn Error(message: String) -> impl IntoView {
    view! {
        <div class="bg-red-100 rounded p-2">"Whoops! "{message}</div>
    }
}
