mod home;
mod list;
mod screens;

use leptos::*;
use leptos_router::*;

use home::Home;

#[component]
pub fn App(cx: Scope) -> impl IntoView {
    view! { cx,
        <Router>
            <Routes>
                <Route path="/delanocreds/" view=move |cx| view! {cx, <Home/> }/>
            </Routes>
        </Router>
    }
}
