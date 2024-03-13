#![feature(once_cell_try)]

// cargo_component_bindings::generate!();

mod bindings;
mod conversions;
mod error;
mod utils;

use bindings::delano::wallet;
use bindings::delano::wallet::types::{Attribute, OfferConfig, Provables};
use bindings::exports::delano::wallet::actions::Guest;
use bindings::seed_keeper::wallet::config::get_seed;

use delano_keys::kdf::{ExposeSecret, Manager, Zeroizing};
use delano_keys::{
    kdf::Scalar,
    //    vk::VKCompressed
};
use delanocreds::keypair::{CredProofCompressed, IssuerPublicCompressed, NymProofCompressed};
use delanocreds::CredentialCompressed;
use delanocreds::{
    verify_proof, CredProof, Credential, Entry, Initial, Issuer, IssuerPublic, MaxCardinality,
    MaxEntries, Nonce, Nym, NymProof, Secret,
};
use error::Error;

use std::sync::OnceLock;
use utils::nonce_by_len;

// We cannot have &self in the WIT model
// so we use static variables to store the state between functions
// See https://crates.io/crates/lazy_static
static EXPANDED: OnceLock<Secret<Vec<Scalar>>> = OnceLock::new();
static NYM: OnceLock<Nym<Initial>> = OnceLock::new();
static ISSUER: OnceLock<Issuer> = OnceLock::new();

/// Uses the seed keeper to get a seed, then expands it into a secret key using Deterministic
/// Hierarchical Derivation (delano_keys)
fn expand() -> Result<Secret<Vec<Scalar>>, Error> {
    let seed = get_seed().map_err(|e| Error::GetSeed(e.to_string()))?;
    // derive secret key fromseed using delano_keys
    let seed = Zeroizing::new(seed);
    let manager: Manager = Manager::from_seed(seed);

    let account = manager.account(1);

    Ok(account.expand_to(MaxEntries::default().into()))
}

/// Gets or tries to init NYM if get_seed (through get_expanded()) returns Ok, returns Err otherwise.
/// NYM is the keypair that we use to create credentials.
fn assert_nym() -> Result<(), Error> {
    NYM.get_or_try_init(|| -> Result<Nym<Initial>, Error> {
        let expanded =
            EXPANDED.get_or_try_init(|| -> Result<Secret<Vec<Scalar>>, Error> { Ok(expand()?) })?;

        Ok(Nym::from_secret(expanded.expose_secret().clone()[0].into()))
    })?;
    Ok(())
}

/// Gets or tries to init ISSUER if get_seed (through get_expanded()) returns Ok, returns Err otherwise.
fn assert_issuer() -> Result<(), Error> {
    ISSUER.get_or_try_init(|| -> Result<Issuer, Error> {
        let expanded =
            EXPANDED.get_or_try_init(|| -> Result<Secret<Vec<Scalar>>, Error> { Ok(expand()?) })?;

        Ok(Issuer::new_with_secret(
            expanded.expose_secret().clone().into(),
            MaxCardinality::default(),
        ))
    })?;
    Ok(())
}

struct Component;

bindings::export!(Component with_types_in bindings);

impl Guest for Component {
    /// Return proof of [Nym] given the Nonce
    fn get_nym_proof(nonce: Vec<u8>) -> Result<wallet::types::NymProofCompressed, String> {
        assert_nym().map_err(|e| e.to_string())?;
        let nym = NYM
            .get()
            .expect("NYM should be initialized by assert_nym, but it wasn't");
        let nonce = utils::nonce_by_len(&nonce)?;
        let nym_proof = nym.nym_proof(&nonce);
        Ok(NymProofCompressed::from(nym_proof).into())
    }

    /// Issue a credential to a holder's [Nym].
    ///
    /// ## Verifying the [Nym] using [NymProof] and [Nonce]
    /// If you are issung an extenal credential, you may wish to validate the holder's nym. In this case,
    /// pass the optional [Nonce] as a 32 byte Vec<u8>.
    ///
    /// If no nonce is passed, this validation step is skipped, for example if you are issuing the root credential
    /// to yourself.
    ///
    /// Note on the Nonce: `nonce` - If the Nonce is 32 bytes long, it will be directly converted into a Scalar, otherwise it
    /// will be _hashe_ into 32 byte digest then converted into a Scalar.
    ///
    /// # Returns
    /// [CBORCodec] encoded CredentialCompressed bytes.
    fn issue(
        attributes: Vec<wallet::types::Attribute>,
        maxentries: u8,
        options: Option<wallet::types::IssueOptions>,
    ) -> Result<wallet::types::CredentialCompressed, String> {
        assert_issuer().map_err(|e| e.to_string())?;
        let issuer = ISSUER
            .get()
            .expect("ISSUER should be initialized by assert_issuer, but it wasn't");

        let entry = Entry::try_from(attributes)
            .map_err(|e| format!("Error converting attribute bytes into Entry: {:?}", e))?;

        let (nym_proof, nonce) = match options {
            Some(options) => {
                let nonce = utils::maybe_nonce(options.nonce.as_deref())?;
                let nym_proof = NymProof::try_from(NymProofCompressed::from(options.nymproof))
                    .map_err(|e| {
                        format!("Error converting nym_proof bytes into NymProof: {:?}", e)
                    })?;
                (nym_proof, nonce)
            }
            _ => {
                // use our own nym_proof and nonce, self-issued credential
                let nonce = nonce_by_len(&[42u8; 32]).expect("should be able to create nonce");
                assert_nym().map_err(|e| format!("Error asserting nym: {:?}", e))?;
                let nym = NYM.get().expect("NYM should be initialized");
                let nym_proof = nym.nym_proof(&nonce);
                (nym_proof, Some(nonce))
            }
        };

        // Issue Credential will verify that the nonce, if any, matches the one we provided in the
        // request for nym_proof
        let cred = issuer
            .credential()
            .with_entry(entry)
            .max_entries(&maxentries.into())
            .issue_to(&nym_proof, nonce.as_ref())
            .map_err(|e| format!("Error issuing credential: {:?}", e))?;

        // serialize and return the cred
        let cred_compressed = CredentialCompressed::from(&cred);
        Ok(cred_compressed.into())
    }

    /// Given a credential that we have authorization of we issued it, or accepted it), create an offer for another nym
    fn offer(
        cred: wallet::types::CredentialCompressed,
        config: OfferConfig,
    ) -> Result<wallet::types::CredentialCompressed, String> {
        // Create an offer from the Entry with the given config
        // first, use our NYM to create an offer builder
        assert_nym().map_err(|e| e.to_string())?;
        let nym = NYM.get().expect("NYM should be initialized");

        // if offer_config is None, make entries empty array, else set to offer_config.redact.entries
        let (entries, redact) = match config.redact {
            None => (Vec::new(), Vec::new()),
            Some(redactables) => {
                // iterate throguh the redactables.entries and convert to [Entry]
                let entries = redactables
                    .entries
                    .iter()
                    .map(|entry| {
                        Entry::try_from(entry.clone())
                            .map_err(|e| format!("Error converting entry, {:?}", e))
                    })
                    .collect::<Result<Vec<_>, _>>()?;

                let redact = redactables
                    .remove
                    .iter()
                    .map(|attr| {
                        Attribute::try_from(attr.clone())
                            .map_err(|e| format!("Err converting redactable attr {:?}", e))
                    })
                    .collect::<Result<Vec<_>, _>>()?;

                (entries, redact)
            }
        };

        let cred =
            Credential::try_from(CredentialCompressed::from(cred)).map_err(|e| e.to_string())?;
        let mut offer_builder = nym.offer_builder(&cred, &entries);

        if let Some(additional_entry) = config.additional_entry {
            offer_builder.additional_entry(
                Entry::try_from(additional_entry)
                    .map_err(|e| format!("Additional entry failed {}", e.to_string()))?,
            );
        }

        for entry in redact {
            offer_builder.without_attribute(
                delanocreds::Attribute::try_from(entry)
                    .map_err(|e| format!("Redacting failed {}", e.to_string()))?,
            );
        }

        if let Some(max_entries) = config.max_entries {
            offer_builder.max_entries(*MaxEntries::new(max_entries.into()));
        }

        // Finally, build the offer
        let (offer, _provable_entries) = offer_builder
            .open_offer()
            .map_err(|e| format!("Error building offer: {:?}", e))?;

        // return the serialized Offer bytes & the provable entries
        // we do not return _provable_entries in order to keep it separated from the offer in order
        // to prevent both from falling into the rong hands. Rather, the application should create
        // some sort of "Hint" object to relay to the accepter of this offer.
        let offer_compressed = CredentialCompressed::from(offer.as_ref());
        Ok(offer_compressed.into())
    }

    /// Accept a CBOR Serialized Credential (apply our signing key to it so it can only be used by
    /// us)
    fn accept(
        offer: wallet::types::CredentialCompressed,
    ) -> Result<wallet::types::CredentialCompressed, String> {
        assert_nym().map_err(|e| e.to_string())?;
        let nym = NYM.get().expect("NYM should be initialized");

        let offer = Credential::try_from(CredentialCompressed::from(offer))
            .map_err(|e| format!("Error converting offer to Offer: {:?}", e))?;
        let accepted_cred = nym
            .accept(&offer.into())
            .map_err(|e| format!("Error accepting offer: {:?}", e))?;

        let accept_compressed = CredentialCompressed::from(&accepted_cred);
        Ok(accept_compressed.into())
    }

    /// Extend the given credential with the given entry
    fn extend(
        cred: wallet::types::CredentialCompressed,
        entry: wallet::types::Entry,
    ) -> Result<wallet::types::CredentialCompressed, String> {
        assert_nym().map_err(|e| e.to_string())?;
        let nym = NYM.get().expect("NYM should be initialized");

        let cred =
            Credential::try_from(CredentialCompressed::from(cred)).map_err(|e| e.to_string())?;
        let entry = Entry::try_from(entry).map_err(|e| e.to_string())?;

        let extended_cred = nym
            .extend(&cred, &entry)
            .map_err(|e| format!("Error extending credential: {:?}", e))?;

        let extended_compressed = CredentialCompressed::from(&extended_cred);
        Ok(extended_compressed.into())
    }

    /// Prove
    fn prove(values: Provables) -> Result<wallet::types::Proven, String> {
        assert_nym().map_err(|e| e.to_string())?;
        let nym = NYM.get().expect("NYM should be initialized");

        let cred = Credential::try_from(CredentialCompressed::from(values.credential))
            .map_err(|e| e.to_string())?;
        let entries = values
            .entries
            .iter()
            .map(|entry| Entry::try_from(entry.clone()).map_err(|e| e.to_string()))
            .collect::<Result<Vec<_>, _>>()?;

        let mut buildr = nym.proof_builder(&cred, &entries);

        // Iterate over values.selected and use `select_attribute` to add the selected attributes
        // to the proof builder
        for selected in values.selected {
            buildr
                .select_attribute(delanocreds::Attribute::try_from(selected).map_err(|e| {
                    format!("Error in prove converting selected to Attribute: {e}")
                })?);
        }

        let nonce: Nonce = utils::nonce_by_len(&values.nonce)?;

        let (proof, selected_entries) = buildr.prove(&nonce);

        Ok(wallet::types::Proven {
            proof: wallet::types::CredProofCompressed::from(CredProofCompressed::from(proof)),
            selected: selected_entries
                .iter()
                .map(|entry| entry.iter().map(|attr| attr.to_bytes()).collect())
                .collect(),
        })
    }

    /// Verify
    fn verify(values: wallet::types::Verifiables) -> Result<bool, String> {
        let issuer_public = IssuerPublic::try_from(IssuerPublicCompressed::from(
            values.issuer_public,
        ))
        .map_err(|e| {
            format!(
                "Error converting issuer_public to IssuerPublic: {:?}",
                e.to_string()
            )
        })?;
        let proof = CredProof::try_from(CredProofCompressed::from(values.proof))
            .map_err(|e| format!("Error converting proof to CredProof: {:?}", e.to_string()))?;
        let selected_attrs = values
            .selected
            .iter()
            .map(|entry| Entry::try_from(entry.clone()).map_err(|e| e.to_string()))
            .collect::<Result<Vec<_>, _>>()?;

        let nonce = utils::maybe_nonce(values.nonce.as_deref())?;

        let is_verified = verify_proof(&issuer_public, &proof, &selected_attrs, nonce.as_ref());

        Ok(is_verified)
    }

    /// Returns the Issuer Public Key
    fn issuer_public() -> Result<wallet::types::IssuerPublicCompressed, String> {
        assert_issuer().map_err(|e| e.to_string())?;
        let issuer = ISSUER
            .get()
            .expect("ISSUER should be initialized by assert_issuer, but it wasn't");

        Ok(IssuerPublicCompressed::from(&issuer.public).into())
    }
}
