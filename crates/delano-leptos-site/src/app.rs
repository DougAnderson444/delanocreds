// Where the Router routes are defined
mod routes;
/// Where Global State is structured
mod state;

mod list;
mod screens;

use leptos::*;
use leptos_router::*;

use routes::home::Home;
use seed_keeper_core::Zeroizing;
use state::*;
/// The Label and Encrypted key params in the hash value
///
/// `label` - A 6+ character string, usually a username, email, or phrase to identify the key
/// `pin` - A 4+ digit pin to encrypt the key
#[derive(Default, Clone, Debug)]
pub(crate) struct LabelAndPin {
    pub label: String,
    pub(crate) pin: Zeroizing<String>,
}

#[component]
pub fn App(cx: Scope) -> impl IntoView {
    // Make the state available to all children
    let (label_and_pin, set_label_n_pin) = create_signal(cx, LabelAndPin::default());

    // share the ability to set and read pin info to all children
    provide_context(cx, set_label_n_pin);

    view! { cx,
        <Router>
            <nav>
                <div class="my-0 mx-auto max-w-3xl text-center">
                    <h2 class="p-6 text-4xl font-bold">"Delanocreds."</h2>
                </div>
            </nav>
            <Routes>
                <Route path="/delanocreds/" view=Home/>
            </Routes>
        </Router>
    }
}
