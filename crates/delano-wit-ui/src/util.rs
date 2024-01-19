use std::fmt::Debug;

use convert_case::{Case, Casing};

/// A function that prints out any type and returns the first variant in Kebab case
pub fn variant_string<T: Debug>(t: T) -> String {
    let printed = format!("{:?}", t);
    let parts = printed
        .split(|c: char| !c.is_alphanumeric())
        .collect::<Vec<_>>();
    parts[2].to_case(Case::Kebab)
}
