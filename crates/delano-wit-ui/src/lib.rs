cargo_component_bindings::generate!();

mod attributes;
mod input;
mod issuer;
mod offer;
mod output;
mod page;
mod util;

// use input::Input;
use issuer::IssuerStruct;
use offer::OfferStruct;
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
const ATTRIBUTES_HTML: &str = "attributes.html";
const OUTPUT_HTML: &str = "output.html";
const ACCEPT_HTML: &str = "accept.html";

/// We need to provide the templates for the macro to pull in
fn get_templates() -> Templates {
    Templates::new(
        Index::new(INDEX_HTML, include_str!("templates/index.html")),
        Entry::new(OUTPUT_HTML, include_str!("templates/output.html")),
        Rest::new(vec![
            // "attributes.html"
            Entry::new(ATTRIBUTES_HTML, include_str!("templates/attributes.html")),
            // "maxentries.html"
            Entry::new("maxentries.html", include_str!("templates/maxentries.html")),
            // offer.html
            Entry::new("offer.html", include_str!("templates/offer.html")),
            // kov.html
            Entry::new("kov.html", include_str!("templates/kov.html")),
            // accept.html
            Entry::new(ACCEPT_HTML, include_str!("templates/accept.html")),
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
    issuer: IssuerStruct,
    offer: OfferStruct,
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
            "issuer" => Some(Value::from_struct_object(self.issuer.clone())),
            "output" => Some(Value::from_struct_object(self.output.clone())),
            "offer" => Some(Value::from_struct_object(self.offer.clone())),
            _ => None,
        }
    }
    /// So that debug will show the values
    fn static_fields(&self) -> Option<&'static [&'static str]> {
        Some(&["app"])
    }
}

impl From<&context_types::Context> for StructContext {
    fn from(context: &context_types::Context) -> Self {
        match context {
            context_types::Context::AllContent(everything) => {
                StructContext::from(everything.clone())
            }
            context_types::Context::Issuing(issuer) => {
                StructContext::from(IssuerStruct::from(issuer))
                    .with_target(ATTRIBUTES_HTML.to_string())
            }
            context_types::Context::Addattribute => {
                StructContext::from(IssuerStruct::from_latest().push_attribute())
                    .with_target(INDEX_HTML.to_string())
            }
            context_types::Context::Editattribute(kvctx) => StructContext::from(
                StructContext::from(IssuerStruct::from_latest().edit_attribute(kvctx))
                    .with_target(OUTPUT_HTML.to_string()),
            ),
            context_types::Context::Editissuermaxentries(max) => {
                StructContext::from(IssuerStruct::with_max_entries(max))
                    .with_target(OUTPUT_HTML.to_string())
            }
            context_types::Context::Offer(offer) => {
                StructContext::from(OfferStruct::from(offer.clone()))
                    .with_target(ACCEPT_HTML.to_string())
            }
        }
    }
}

impl From<context_types::Everything> for StructContext {
    fn from(context: context_types::Everything) -> Self {
        StructContext {
            app: StructPage::from(context.page),
            issuer: IssuerStruct::from(context.issue),
            offer: OfferStruct::from(context.offer),
            output: OutputStruct::default(),
            target: None,
        }
    }
}

impl From<IssuerStruct> for StructContext {
    fn from(issuer_ctx: IssuerStruct) -> Self {
        let mut state = { LAST_STATE.lock().unwrap().clone().unwrap_or_default() };
        state.issuer = issuer_ctx.clone();
        state
    }
}

impl From<OfferStruct> for StructContext {
    fn from(offer_ctx: OfferStruct) -> Self {
        let mut state = { LAST_STATE.lock().unwrap().clone().unwrap_or_default() };
        state.offer = offer_ctx.clone();
        println!("setting state: {:?}", state);
        state
    }
}
