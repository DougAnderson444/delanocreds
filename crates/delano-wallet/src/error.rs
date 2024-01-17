//! Crate errors

#[derive(thiserror::Error, Debug)]
pub enum Error {
    /// Error gettign seed, with iner String message
    #[error("Error getting seed: {0}")]
    GetSeed(String),

    /// Error from string
    #[error("Error: {0}")]
    String(String),
}

impl From<String> for Error {
    fn from(s: String) -> Self {
        Error::String(s)
    }
}
