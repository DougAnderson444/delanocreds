mod bindings;

mod api;
mod attributes;
mod credential;
mod output;
mod page;
mod util;

pub use api::Loaded;

use credential::CredentialStruct;
use output::OutputStruct;
use page::StructPage;

use wurbo::jinja::{Entry, Index, Rest, Templates};
use wurbo::prelude_bindgen;

use bindings::delano::wallet;
use bindings::delano::wit_ui::context_types::{self, Context};
use bindings::delano::wit_ui::wurbo_in;
use bindings::exports::delano::wit_ui::wurbo_out::Guest as WurboGuest;

use std::ops::Deref;

struct Component;

const INDEX_HTML: &str = "index.html";
const CREATE_HTML: &str = "create.html";
const OUTPUT_HTML: &str = "output.html";
const ACCEPT_HTML: &str = "accept.html";
const VERIFY_HTML: &str = "verify.html";

/// We need to provide the templates for the macro to pull in
fn get_templates() -> Templates {
    Templates::new(
        Index::new(INDEX_HTML, include_str!("templates/index.html")),
        Entry::new(OUTPUT_HTML, include_str!("templates/output.html")),
        Rest::new(vec![
            // "attributes.html"
            Entry::new(CREATE_HTML, include_str!("templates/create.html")),
            // "maxentries.html"
            Entry::new("maxentries.html", include_str!("templates/maxentries.html")),
            // kov.html
            Entry::new("kov.html", include_str!("templates/kov.html")),
            // accept.html
            Entry::new(ACCEPT_HTML, include_str!("templates/accept.html")),
            // verify.html
            Entry::new(VERIFY_HTML, include_str!("templates/verify.html")),
        ]),
    )
}

// Macro builds the Component struct and implements the Guest trait for us, saving copy-and-paste
prelude_bindgen! {WurboGuest, Component, StructContext, Context, LAST_STATE}

/// This is a wrapper around [Context] that implements StructObject on the wrapper.
/// Enables the conversion of Context to StructContext so we can render with minijinja.
#[derive(Debug, Clone, Default)]
struct StructContext {
    app: StructPage,
    state: api::State,
    output: OutputStruct,
    target: Option<String>,
}

impl StructContext {
    /// with this target template, instead of defaulting to entry or output template
    fn with_target(mut self, target: String) -> Self {
        self.target = Some(target);
        self
    }
}

impl StructObject for StructContext {
    /// Remember to add match arms for any new fields.
    fn get_field(&self, name: &str) -> Option<Value> {
        match name {
            "app" => Some(Value::from_struct_object(self.app.clone())),
            "state" => Some(Value::from_struct_object(self.state.clone())),
            "output" => Some(Value::from_struct_object(self.output.clone())),
            _ => None,
        }
    }
    /// So that debug will show the values
    fn static_fields(&self) -> Option<&'static [&'static str]> {
        Some(&["app", "state", "output"])
    }
}

impl From<&context_types::Context> for StructContext {
    fn from(context: &context_types::Context) -> Self {
        match context {
            context_types::Context::AllContent(everything) => {
                StructContext::from(everything.clone())
            }
            context_types::Context::Addattribute => {
                StructContext::from(api::State::from_latest().builder.push_attribute())
                    .with_target(INDEX_HTML.to_string())
            }
            context_types::Context::Editattribute(kvctx) => {
                StructContext::from(api::State::from_latest().update_attributes(kvctx))
                    .with_target(OUTPUT_HTML.to_string())
            }
            context_types::Context::Editmaxentries(max) => {
                StructContext::from(api::State::from_latest().builder.with_max_entries(max))
                    .with_target(OUTPUT_HTML.to_string())
            }
            // AKA "Extend"
            // Creates a New Entry in the credential. This can only be done once (ie. only 1
            // additional Entry can be added)
            context_types::Context::Newentry => {
                StructContext::from(api::State::from_latest().builder.push_entry())
                    .with_target(INDEX_HTML.to_string())
            }
            // Generate an Offer with the current data
            context_types::Context::Generateoffer => {
                StructContext::from(api::State::from_latest().with_offer())
                    .with_target(OUTPUT_HTML.to_string())
            }
            // Generate a Proof with the current data
            context_types::Context::Generateproof => {
                StructContext::from(api::State::from_latest().with_proof())
                    .with_target(OUTPUT_HTML.to_string())
            }
            context_types::Context::Publishproof => {
                // emit publish event
                StructContext::from(api::State::from_latest().publish_proof())
                    .with_target(OUTPUT_HTML.to_string())
            }
        }
    }
}

impl From<context_types::Everything> for StructContext {
    fn from(context: context_types::Everything) -> Self {
        // persist the last state, if any
        let last = { LAST_STATE.lock().unwrap().clone().unwrap_or_default() };
        let state = match last.state.loaded {
            // If previous state loaded None, then use the current state loaded
            api::Loaded::None => api::State::from(context.load),
            // If previous state loaded anything, then use the previous state loaded
            _ => {
                let latest = api::State::from(context.load);
                let previous = last.state.loaded;
                // combine last.state and State::from(context.load)
                api::State {
                    loaded: previous,
                    ..latest
                }
            }
        };

        StructContext {
            app: StructPage::from(context.page),
            output: OutputStruct::default(),
            state,
            target: None,
        }
    }
}

impl From<CredentialStruct> for StructContext {
    fn from(ctx: CredentialStruct) -> Self {
        let mut last = { LAST_STATE.lock().unwrap().clone().unwrap_or_default() };
        last.state.builder = ctx;
        last.state.offer = None;
        last.state.proof = None;
        last
    }
}

impl From<api::State> for StructContext {
    fn from(state: api::State) -> Self {
        let mut last = { LAST_STATE.lock().unwrap().clone().unwrap_or_default() };
        last.state = state;
        last
    }
}
