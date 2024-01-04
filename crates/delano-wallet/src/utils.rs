use delanocreds::Nonce;

// Processes nonce bytes according to whether a Nonce is provided
// If nonce is 32 bytes, convert it directly into a Scalar
// otherwise, hash it into a 32 byte digest, then convert it into a Scalar
pub(crate) fn maybe_nonce(nonce: Option<&[u8]>) -> Result<Option<Nonce>, String> {
    match nonce {
        Some(n) => nonce_by_len(n).map(Some),
        None => Ok(None),
    }
}

// Processes nonce bytes according to length
// If nonce is 32 bytes, convert it directly into a Scalar
// otherwise, hash it into a 32 byte digest, then convert it into a Scalar
pub(crate) fn nonce_by_len(nonce: &[u8]) -> Result<Nonce, String> {
    if nonce.len() == 32 {
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(nonce);
        Ok(Nonce::try_from(bytes)
            .map_err(|e| format!("Nonce conversion error try from bytes: {:?}", e))?)
    } else {
        Ok(Nonce::from(nonce))
    }
}
