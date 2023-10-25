//! The Delanocreds app.

/// Components available throughotu the app and routes:
mod components;
/// Constants module
mod constants;
/// Routes for the app path
mod routes;
/// Where Global State is structured
mod state;

use components::nav::Nav;
use constants::{HOME, TEST};
use state::*;

use leptos::*;
use leptos_router::*;
use seed_keeper_core::Zeroizing;

use routes::account::AccountRoutes;
use routes::home::Home;
use routes::test::Test;

/// The Label and Encrypted key params in the hash value
///
/// `label` - A 8+ character string, usually a username, email, or phrase to identify the key
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
            <div class="relative flex min-h-screen flex-col justify-start overflow-hidden">
                <nav>
                    <Nav/>
                </nav>
                <div class="p-2 my-0 mx-auto max-w-3xl">
                    <Routes>
                        <Route path=HOME view=Home/>
                        <AccountRoutes/>
                        <Route path=TEST view=Test/>
                        <Route path="/*any" view=|| view! { <h1>"Not Found"</h1> }/>
                    </Routes>
                </div>
            </div>
        </Router>
    }
}
