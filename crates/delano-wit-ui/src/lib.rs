cargo_component_bindings::generate!();

mod input;
mod issuer;
mod output;
mod page;
mod state;

// use input::Input;
// use output::Output;
use issuer::IssuerStruct;
use page::StructPage;

use wurbo::jinja::{Entry, Index, Rest, Templates};
use wurbo::prelude_bindgen;

use bindings::component::delano_wit_ui::context_types::{self, Context};
use bindings::component::delano_wit_ui::wurbo_in;
use bindings::exports::component::delano_wit_ui::wurbo_out::Guest as WurboGuest;

use std::ops::Deref;

struct Component;

/// We need to provide the templates for the macro to pull in
fn get_templates() -> Templates {
    Templates::new(
        Index::new("page.html", include_str!("templates/index.html")),
        Entry::new("output.html", include_str!("templates/output.html")),
        Rest::new(vec![Entry::new(
            "input.html",
            include_str!("templates/input.html"),
        )]),
    )
}

// Macro builds the Component struct and implements the Guest trait for us, saving copy-and-paste
prelude_bindgen! {WurboGuest, Component, StructContext, Context, LAST_STATE}

/// This is a wrapper around [Context] that implements StructObject on the wrapper.
/// Enables the conversion of Context to StructContext so we can render with minijinja.
#[derive(Debug, Clone)]
struct StructContext {
    app: StructPage,
    issuer: IssuerStruct,
    // output: Output,
}

impl StructObject for StructContext {
    fn get_field(&self, name: &str) -> Option<Value> {
        match name {
            "app" => Some(Value::from_struct_object(self.app.clone())),
            "issuer" => Some(Value::from_struct_object(self.issuer.clone())),
            // "output" => Some(Value::from(self.output.clone())),
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
            context_types::Context::AllContent(ctx) => StructContext::from(ctx.clone()),
            context_types::Context::Issuing(ctx) => StructContext::from(IssuerStruct::from(ctx)),
        }
    }
}

impl From<context_types::Everything> for StructContext {
    fn from(context: context_types::Everything) -> Self {
        StructContext {
            app: StructPage::from(context.page),
            issuer: IssuerStruct::from(context.issue),
        }
    }
}

/// StructContext: From<IssuerStruct>
impl From<IssuerStruct> for StructContext {
    fn from(context: IssuerStruct) -> Self {
        Self {
            app: StructPage::from(None),
            issuer: context,
        }
    }
}
/// StructContext: From<IssuerStruct>
impl From<&IssuerStruct> for StructContext {
    fn from(context: &IssuerStruct) -> Self {
        Self {
            app: StructPage::from(None),
            issuer: context.clone(),
        }
    }
}
