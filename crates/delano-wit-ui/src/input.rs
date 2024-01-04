// use super::*;

// /// Input Context that could be received
// #[derive(Debug, Clone)]
// pub(crate) struct Input(context_types::Input);
//
// impl StructObject for StructPage {
//     fn get_field(&self, name: &str) -> Option<Value> {
//         match name {
//             "id" => Some(Value::from(utils::rand_id())),
//             _ => None,
//         }
//     }
//     /// So that debug will show the values
//     fn static_fields(&self) -> Option<&'static [&'static str]> {
//         Some(&["id"])
//     }
// }
//
// impl From<context_types::Page> for StructPage {
//     fn from(context: context_types::Page) -> Self {
//         StructPage(context)
//     }
// }
//
// impl Deref for StructPage {
//     type Target = context_types::Page;
//
//     fn deref(&self) -> &Self::Target {
//         &self.0
//     }
// }
