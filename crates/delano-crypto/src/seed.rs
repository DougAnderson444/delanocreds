use secrecy::{ExposeSecret, Secret};

type Seedling = [u8; 32];

/// Seed holds a [Secret] array of [u8; 32]
pub struct Seed {
    inner: Secret<Seedling>,
}

impl Seed {
    /// Creates a new seed from a given 32-byte array
    /// Wraps the array in a [Secret] so that it is not exposed
    pub fn new(seed: Seedling) -> Self {
        Self {
            inner: Secret::new(seed),
        }
    }

    /// Exposes the seed
    pub(crate) fn into_inner(self) -> Seedling {
        *self.inner.expose_secret()
    }
}
