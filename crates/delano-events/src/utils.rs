use base64ct::{Base64UrlUnpadded, Encoding};
use serde::{Deserialize, Serialize};

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

/// Wrappers wrap/unwrap a type by serializing it and encoding it (sercoded) to a Base string.
/// Default is CBOR and Base64UrlUnpadded.
pub trait PayloadEncoding {
    /// Tries to serialize then encode using Base64UrlUnpadded
    fn serialize_encode(&self) -> Result<String, String>
    where
        Self: Serialize + Sized,
    {
        let serialized = try_cbor(self)?;
        let encoded = Base64UrlUnpadded::encode_string(&serialized);
        Ok(encoded)
    }

    /// Decode the string then deserialize into this Type
    fn decode_deserialize(val: &str) -> Result<Self, String>
    where
        Self: Sized + for<'a> Deserialize<'a>,
    {
        let decoded = Base64UrlUnpadded::decode_vec(val)
            .map_err(|e| format!("Base64UrlUnpadded Error decoding: {}", e))?;
        try_from_cbor(&decoded)
    }
}
