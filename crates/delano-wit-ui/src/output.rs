use super::*;

use std::sync::OnceLock;

static OUTPUT_ID: OnceLock<String> = OnceLock::new();

/// Page is the wrapper for Input and Output
#[derive(Debug, Clone, Default)]
pub(crate) struct OutputStruct;

impl Object for OutputStruct {
    fn get_value(self: &Arc<Self>, key: &Value) -> Option<Value> {
        match key.as_str()? {
            // use OnceLock as output id should not changes after first set
            "id" => Some(Value::from(OUTPUT_ID.get_or_init(|| rand_id()).to_owned())),
            _ => None,
        }
    }
}
