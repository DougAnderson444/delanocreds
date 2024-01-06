use super::*;

use std::sync::OnceLock;

/// Element id for the maxentries.html template, which can only be set once.
static MAXENTRIES_ID: OnceLock<String> = OnceLock::new();
/// attributes_html_id
static ATTRIBUTES_HTML_ID: OnceLock<String> = OnceLock::new();

/// Page is the wrapper for Input and Output
#[derive(Debug, Clone, Default)]
pub(crate) struct StructPage(Option<context_types::Page>);

impl StructObject for StructPage {
    fn get_field(&self, name: &str) -> Option<Value> {
        match name {
            "id" => Some(Value::from(utils::rand_id())),
            "name" => Some(Value::from(
                self.as_ref().map(|v| v.name.clone()).unwrap_or_default(),
            )),
            "version" => Some(Value::from(
                self.as_ref().map(|v| v.version.clone()).unwrap_or_default(),
            )),
            "description" => Some(Value::from(
                self.as_ref()
                    .map(|v| v.description.clone())
                    .unwrap_or_default(),
            )),
            "maxentries_id" => Some(Value::from(
                MAXENTRIES_ID.get_or_init(|| utils::rand_id()).to_owned(),
            )),
            "attributes_html_id" => Some(Value::from(
                ATTRIBUTES_HTML_ID
                    .get_or_init(|| utils::rand_id())
                    .to_owned(),
            )),
            _ => None,
        }
    }
    /// So that debug will show the values
    fn static_fields(&self) -> Option<&'static [&'static str]> {
        Some(&["id", "name", "version", "description"])
    }
}

impl From<Option<context_types::Page>> for StructPage {
    fn from(context: Option<context_types::Page>) -> Self {
        Self(context)
    }
}

impl From<context_types::Page> for StructPage {
    fn from(context: context_types::Page) -> Self {
        Self(Some(context))
    }
}

impl Deref for StructPage {
    type Target = Option<context_types::Page>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
