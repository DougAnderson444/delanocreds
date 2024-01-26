mod bindings;

mod api;
mod attributes;
mod credential;
mod input;
mod output;
mod page;
mod util;

use credential::CredentialStruct;
// use input::Input;
// use issuer::IssuerStruct;
use output::OutputStruct;
use page::StructPage;

use wurbo::jinja::{Entry, Index, Rest, Templates};
use wurbo::prelude_bindgen;

use bindings::delano::wallet;
use bindings::delano::wit_ui::context_types::{self, Context};
use bindings::delano::wit_ui::wurbo_in;
use bindings::exports::delano::wit_ui::wurbo_out::Guest as WurboGuest;

use std::ops::Deref;
// use std::sync::OnceLock;

struct Component;

// static ACCEPT_ID: OnceLock<String> = OnceLock::new();

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
    credential: CredentialStruct,
    loaded: api::Loaded,
    output: OutputStruct,
    target: Option<String>,
}

impl StructContext {
    /// with this target
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
            "credential" => Some(Value::from_struct_object(self.credential.clone())),
            "loaded" => Some(Value::from_struct_object(self.loaded.clone())),
            "output" => Some(Value::from_struct_object(self.output.clone())),
            _ => None,
        }
    }
    /// So that debug will show the values
    fn static_fields(&self) -> Option<&'static [&'static str]> {
        Some(&["app", "output", "credential", "loaded"])
    }
}

impl From<&context_types::Context> for StructContext {
    fn from(context: &context_types::Context) -> Self {
        match context {
            context_types::Context::AllContent(everything) => {
                StructContext::from(everything.clone())
            }
            context_types::Context::Addattribute => {
                StructContext::from(CredentialStruct::from_latest().push_attribute())
                    .with_target(INDEX_HTML.to_string())
            }
            context_types::Context::Editattribute(kvctx) => {
                let updated_cred_struct = CredentialStruct::from_latest().edit_attribute(kvctx);

                let mut state = { LAST_STATE.lock().unwrap().clone().unwrap_or_default() };
                if let api::Loaded::Offer { hints, cred } = &mut state.loaded {
                    hints
                        .iter_mut()
                        .zip(updated_cred_struct.entries.iter())
                        .for_each(|(hint, entry)| {
                            *hint = entry.clone();
                        });
                    state.loaded = api::Loaded::Offer {
                        cred: cred.to_vec(),
                        hints: hints.clone(),
                    };
                }

                StructContext {
                    loaded: state.loaded,
                    ..StructContext::from(updated_cred_struct).with_target(OUTPUT_HTML.to_string())
                }
            }
            context_types::Context::Editmaxentries(max) => {
                StructContext::from(CredentialStruct::with_max_entries(max))
                    .with_target(OUTPUT_HTML.to_string())
            }
            // Creates a New Entry in the credential. This can only be done once (ie. only 1
            // additional Entry can be added)
            context_types::Context::Newentry => {
                StructContext::from(CredentialStruct::from_latest().push_entry())
                    .with_target(INDEX_HTML.to_string())
            }
        }
    }
}

impl From<context_types::Everything> for StructContext {
    fn from(context: context_types::Everything) -> Self {
        StructContext {
            app: StructPage::from(context.page),
            credential: CredentialStruct::from(api::Loaded::from(context.load.clone())),
            output: OutputStruct::default(),
            // TODO: Loadables::from(context.load), // <== parse the variant into the matching struct
            loaded: context.load.into(),
            target: None,
        }
    }
}

impl From<CredentialStruct> for StructContext {
    fn from(ctx: CredentialStruct) -> Self {
        let mut state = { LAST_STATE.lock().unwrap().clone().unwrap_or_default() };
        state.credential = ctx;
        // state.offer =
        state
    }
}
