//! Module to hold Offer code
use super::*;

use serde::{Deserialize, Serialize};

/// Offers will be sent to others over the wire, and injested by Wasm Interface types.
/// When this happens, we need to serialize the bytes in accordance with WIT so they can be
/// Deserialized on the other end, in this case, kebab-case.
#[derive(Debug, Clone, Serialize, Deserialize)]
// #[serde(tag = "tag", content = "val")]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum Context {
    Offer {
        /// The Credential bytes
        cred: Vec<u8>,
        /// The Hints
        hints: Vec<Vec<attributes::AttributeKOV>>,
    },
}

#[cfg(test)]
mod tests {
    use delanocreds::CBORCodec;
    use delanocreds::{Credential, Issuer, Nym};

    use super::*;

    /// A dummy Credential for testing and development
    /// Created from [delanocreds::Credential]
    fn dummy_cred() -> Credential {
        let issuer = Issuer::default();
        let nym = Nym::new();

        let root_entry = delanocreds::Entry::new(&[]);
        let nonce = delanocreds::Nonce::default();
        // Issue the (Powerful) Root Credential to Alice
        let cred = match issuer
            .credential()
            .with_entry(root_entry.clone())
            .max_entries(&3)
            .issue_to(&nym.nym_proof(&nonce), Some(&nonce))
        {
            Ok(cred) => cred,
            Err(e) => panic!("Error issuing cred: {:?}", e),
        };
        cred
    }
    #[test]
    fn test_dummy_cred() {
        let cred = dummy_cred().to_bytes();

        // print the bytes
        println!("{:?}", cred);
    }
}
