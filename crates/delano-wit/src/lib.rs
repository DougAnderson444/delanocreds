cargo_component_bindings::generate!();

mod utils;

use bindings::component::delano_wit;
use bindings::component::delano_wit::deps::get_seed;
use bindings::component::delano_wit::types::{Attribute, OfferConfig, Provables};
use bindings::exports::component::delano_wit::actions::Guest;

use delano_keys::kdf::Scalar;
use delano_keys::kdf::{ExposeSecret, Manager, Zeroizing};
use delanocreds::{
    verify_proof, CBORCodec, CredProof, Credential, Entry, Initial, Issuer, IssuerPublic,
    MaxCardinality, MaxEntries, Nonce, Nym, NymProof, Offer, Secret,
};
use std::sync::Mutex;
use std::sync::OnceLock;

static EXPANDED: OnceLock<Secret<Vec<Scalar>>> = OnceLock::new();

fn get_expanded() -> Secret<Vec<Scalar>> {
    let seed = get_seed();
    // derive secret key fromseed using delano_keys
    let seed = Zeroizing::new(seed);
    let manager: Manager = Manager::from_seed(seed);

    let account = manager.account(1);

    account.expand_to(MaxEntries::default().into())
}

// We cannot have &self in the WIT model
// so we use static variables to store the state between functions
// See https://crates.io/crates/lazy_static
lazy_static::lazy_static! {
    static ref ISSUER: Mutex<Issuer> = {
        let expanded = EXPANDED.get_or_init(|| get_expanded());

        Mutex::new(Issuer::new_with_secret(expanded.expose_secret().clone().into(), MaxCardinality::default()))
    };

    static ref NYM: Mutex<Nym<Initial>> = {
        let expanded = EXPANDED.get_or_init(|| get_expanded());
        Mutex::new(Nym::from_secret(expanded.expose_secret().clone()[0].into()))
    };
}

struct Component;

impl Guest for Component {
    /// Return proof of [Nym] given the Nonce
    fn get_nym_proof(nonce: delano_wit::types::Nonce) -> Result<Vec<u8>, String> {
        let nym = NYM.lock().expect("should be able to lock NYM");
        let nonce = utils::nonce_by_len(&nonce)?;
        let nym_proof = nym.nym_proof(&nonce);
        let bytes = nym_proof
            .to_bytes()
            .map_err(|e| format!("Error converting nym proof to bytes: {:?}", e))?;
        Ok(bytes)
    }

    /// Issue a credential
    ///
    /// `nonce` - If the Nonce is 32 bytes long, it will be directly converted into a Scalar, otherwise it
    /// will be hashed into 32 byte digest then converted into a Scalar
    ///
    /// # Returns
    /// CBOR encoded CredentialCompressed bytes.
    fn issue(
        nymproof: Vec<u8>,
        attributes: Vec<delano_wit::types::Attribute>,
        maxentries: u8,
        nonce: Option<Vec<u8>>,
    ) -> Result<Vec<u8>, String> {
        let issuer = ISSUER.lock().unwrap();

        let entry = Entry::try_from(attributes).map_err(|e| e.to_string())?;
        let nym_proof = NymProof::from_bytes(&nymproof).map_err(|e| e.to_string())?;

        // if nonce is 32 bytes, convert it directly into a Scalar
        // otherwise, hash it into a 32 byte digest, then convert it into a Scalar
        let nonce = utils::maybe_nonce(nonce.as_deref())?;

        // check whether nym_proof.pedersen_open.open_randomness != *nonce
        if let Some(n) = nonce.as_ref() {
            if nym_proof.pedersen_open.open_randomness != *n {
                return Err(
                    // "Nonce does not match the nonce used to create the NymProof. expected {:?} "
                    format!(
                        "Nonce does not match the nonce used to create the NymProof. expected {:?} \
                        but got {:?}",
                        n, nym_proof.pedersen_open.open_randomness
                    ),
                );
            }
        }

        let cred = issuer
            .credential()
            .with_entry(entry)
            .max_entries(&maxentries.into())
            .issue_to(&nym_proof, nonce.as_ref())
            .map_err(|e| e.to_string())?;

        // serialize and return the cred
        let cred_bytes = cred
            .to_bytes()
            .map_err(|e| format!("Accept error converting cred to bytes: {:?}", e))?;

        Ok(cred_bytes)
    }

    /// Given a credential that we have authorization of we issued it, or accepted it), create an offer for another nym
    fn offer(cred: Vec<u8>, config: OfferConfig) -> Result<Vec<u8>, String> {
        // Create an offer from the Entry with the given config
        // first, use our NYM to create an offer builder
        let nym = NYM.lock().expect("should be able to lock NYM");

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

        let cred = Credential::from_bytes(&cred)
            .map_err(|e| format!("Error converting cred to Credential, {:?}", e))?;
        let mut offer_builder = nym.offer_builder(&cred, &entries);

        if let Some(additional_entry) = config.additional_entry {
            offer_builder
                .additional_entry(Entry::try_from(additional_entry).map_err(|e| e.to_string())?);
        }

        for entry in redact {
            offer_builder.without_attribute(
                delanocreds::Attribute::try_from(entry).map_err(|e| e.to_string())?,
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
        let cred = offer.to_bytes().map_err(|e| e.to_string())?;
        Ok(cred)
    }

    /// Accept a CBOR Serialized Credential (apply our signing key to it so it can only be used by
    /// us)
    fn accept(offer: Vec<u8>) -> Result<Vec<u8>, String> {
        let nym = NYM.lock().unwrap();

        let offer = Offer::from_bytes(&offer)
            .map_err(|e| format!("Error converting offer to Offer: {:?}", e))?;
        let accepted_cred = nym
            .accept(&offer)
            .map_err(|e| format!("Error accepting offer: {:?}", e))?;
        let bytes = accepted_cred
            .to_bytes()
            .map_err(|e| format!("Error converting accepted cred to bytes: {:?}", e))?;

        Ok(bytes)
    }

    /// Prove
    fn prove(values: Provables) -> Result<Vec<u8>, String> {
        let nym = NYM.lock().unwrap();

        let cred = Credential::from_bytes(&values.credential)
            .map_err(|e| format!("Error in prove converting bytes to Credential: {e}"))?;
        let entries = values
            .entries
            .iter()
            .map(|entry| Entry::try_from(entry.clone()).map_err(|e| e.to_string()))
            .collect::<Result<Vec<_>, _>>()?;

        let mut buildr = nym.proof_builder(&cred, &entries);

        // Iterate over values.selected and use `select_attribute` to add the selected attributes
        // to the proof builder
        for selected in values.selected {
            buildr.select_attribute(
                delanocreds::Attribute::try_from(selected).map_err(|e| e.to_string())?,
            );
        }

        let nonce: Nonce = utils::nonce_by_len(&values.nonce)?;

        let (proof, _selected_entries) = buildr.prove(&nonce);

        Ok(proof.to_bytes().map_err(|e| e.to_string())?)
    }

    /// Verify
    fn verify(values: delano_wit::types::Verifiables) -> Result<bool, String> {
        let issuer_public =
            IssuerPublic::from_bytes(&values.issuer_public).map_err(|e| e.to_string())?;
        let proof = CredProof::from_bytes(&values.proof).map_err(|e| e.to_string())?;
        let selected_attrs = values
            .attributes
            .iter()
            .map(|attr| delanocreds::Attribute::try_from(attr.clone()).map_err(|e| e.to_string()))
            .collect::<Result<Vec<_>, _>>()?;

        let nonce = utils::maybe_nonce(values.nonce.as_deref())?;

        let is_verified = verify_proof(
            &issuer_public,
            &proof,
            &[delanocreds::Entry(selected_attrs)],
            nonce.as_ref(),
        );

        Ok(is_verified)
    }
}
