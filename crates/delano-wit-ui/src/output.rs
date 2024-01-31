use super::*;

use std::sync::OnceLock;

static OUTPUT_ID: OnceLock<String> = OnceLock::new();

/// Page is the wrapper for Input and Output
#[derive(Debug, Clone, Default)]
pub(crate) struct OutputStruct;

impl StructObject for OutputStruct {
    fn get_field(&self, name: &str) -> Option<Value> {
        match name {
            // use OnceLock as output id should not changes after first set
            "id" => Some(Value::from(OUTPUT_ID.get_or_init(|| rand_id()).to_owned())),
            _ => None,
        }
    }

    /// So that debug will show the values
    fn static_fields(&self) -> Option<&'static [&'static str]> {
        Some(&["id"])
    }
}
