use serde::{Deserialize, Serialize};
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

/// Serializes to CBOR bytes
pub(crate) fn try_cbor<T>(value: &T) -> Result<Vec<u8>, String>
where
    T: Sized + Serialize,
{
    let mut bytes = Vec::new();
    match ciborium::into_writer(&value, &mut bytes) {
        Ok(_) => Ok(bytes),
        Err(e) => Err(format!("CBORCodec Error serializing to bytes: {}", e)),
    }
}

/// Deserialize from CBOR bytes
pub fn try_from_cbor<T>(bytes: &[u8]) -> Result<T, String>
where
    for<'a> T: Sized + Deserialize<'a>,
{
    match ciborium::from_reader(&bytes[..]) {
        Ok(item) => Ok(item),
        Err(e) => Err(format!("CBORCodec Error deserializing from bytes: {}", e)),
    }
}
