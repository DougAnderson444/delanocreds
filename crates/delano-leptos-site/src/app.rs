//! The Delanocreds app.

/// Components available throughotu the app and routes:
mod components;
/// Constants module
mod constants;
/// Routes for the app path
mod routes;
/// Where Global State is structured
mod state;

use constants::{ACCOUNT, HOME};
use leptos::*;
use leptos_router::*;
use routes::account::Account;
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
pub fn App() -> impl IntoView {
    // Make the state available to all children
    let (_, set_label_n_pin) = create_signal(LabelAndPin::default());
    let (manager, set_manager) = create_signal(ManagerState::default());

    // share the ability to set and read pin info to all children
    provide_context(set_label_n_pin);
    provide_context(manager);
    provide_context(set_manager);

    view! {
        <Router>
            <div class="relative flex min-h-screen flex-col justify-center overflow-hidden">
                <nav>
                    <div class="my-0 mx-auto max-w-3xl text-center">
                        <h2 class="p-6 text-4xl font-bold">"Delanocreds."</h2>
                    </div>
                </nav>
                <div class="p-2 my-0 mx-auto max-w-3xl">
                    <Routes>
                        <Route path=HOME view=Home/>
                        <Route path=ACCOUNT view=Account/>
                        <Route path="/*any" view=|| view! { <h1>"Not Found"</h1> }/>
                    </Routes>
                </div>
            </div>
        </Router>
    }
}
