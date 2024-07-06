//! Delanocreds wallet code
#![doc = include_str!("../README.md")]

use delano_keys::kdf::{ExposeSecret, Manager};
use delano_keys::{
    kdf::Scalar,
    //    vk::VKCompressed
};
use delanocreds::keypair::{CredProofCompressed, IssuerPublicCompressed, NymProofCompressed};
use delanocreds::{
    verify_proof, CredProof, Credential, Entry, Initial, Issuer, IssuerPublic, MaxCardinality,
    MaxEntries, Nonce, Nym, NymProof, Secret,
};

use delanocreds::utils;
use delanocreds::{Attribute, CredentialCompressed};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Delano Wallet
pub struct DelanoWallet {
    expanded: Secret<Vec<Scalar>>,
    nym: Nym<Initial>,
    issuer: Issuer,
}

/// Optionally pass in NymProof and.or None when issuing credentials
#[derive(Serialize, Deserialize)]
pub struct IssueOptions {
    pub nym_proof: NymProofCompressed,
    pub nonce: Option<Vec<u8>>,
}

/// Specifies what [Entry]s to include, and which [Attribute]s to exclude from the cred.
///
/// # Note on Removing Attributes:
///
/// The [Credential] Offer Builder will remove the entire [Entry] containing an [Attribute] to
/// be removed. If you want to keep other [Attribute]s contained in that [Entry], you'll need
/// to add those [Attribute]s as an additional [Entry] using [OfferConfig].
#[derive(Serialize, Deserialize)]
pub struct Selectables {
    pub entries: Vec<Entry>,
    pub remove: Vec<Attribute>,
}

#[derive(Serialize, Deserialize)]
pub struct OfferConfig {
    pub selected: Option<Selectables>,
    pub additional_entry: Option<Entry>,
    /// Optionally reduces the number of entries that can be added to the credential.
    pub max_entries: Option<u8>,
}

/// Values needed to be passed to the `prove` function
#[derive(Serialize, Deserialize)]
pub struct Provables {
    pub credential: CredentialCompressed,
    pub entries: Vec<Entry>,
    pub selected: Vec<Attribute>,
    pub nonce: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
pub struct Proven {
    pub proof: CredProofCompressed,
    pub selected: Vec<Entry>,
}

#[derive(Serialize, Deserialize)]
pub struct Verifiables {
    pub proof: CredProofCompressed,
    pub issuer_public: IssuerPublicCompressed,
    pub nonce: Option<Vec<u8>>,
    pub selected: Vec<Entry>,
}

impl DelanoWallet {
    /// Creates a new wallet from the given seed
    pub fn new(seed: impl AsRef<[u8]> + Zeroize + ZeroizeOnDrop) -> Self {
        let manager = Manager::from_seed(seed);

        let account = manager.account(1);

        let expanded = account.expand_to(MaxEntries::default().into());

        let nym = Nym::from_secret(expanded.expose_secret().clone()[0].into());

        let issuer = Issuer::new_with_secret(
            expanded.expose_secret().clone().into(),
            MaxCardinality::default(),
        );

        Self {
            expanded,
            nym,
            issuer,
        }
    }

    /// Return proof of [Nym] given the Nonce
    pub fn get_nym_proof(&self, nonce: Vec<u8>) -> NymProofCompressed {
        let nonce = utils::nonce_by_len(&nonce).unwrap_or_default();
        NymProofCompressed::from(self.nym.nym_proof(&nonce))
    }

    /// Issue a credential for the given [Attribute]s, allow extending up to [MaxEntries].
    /// Optionally pass in [IssueOptions] to specify the audience [NymProof] and [Nonce].
    pub fn issue(
        &self,
        attributes: Vec<Attribute>,
        max_entries: MaxEntries,
        options: Option<IssueOptions>,
    ) -> Result<CredentialCompressed, String> {
        let entry = Entry::try_from(attributes).map_err(|e| e.to_string())?;

        let (nym_proof, nonce) = match options {
            Some(options) => {
                let nonce = utils::maybe_nonce(options.nonce.as_deref().map(|n| n.as_ref()))?;
                let nym_proof = NymProof::try_from(NymProofCompressed::from(options.nym_proof))
                    .map_err(|e| {
                        format!("Error converting nym_proof bytes into NymProof: {:?}", e)
                    })?;
                (nym_proof, nonce)
            }
            _ => {
                let nonce = utils::nonce_by_len(&[0u8; 32]).map_err(|e| e.to_string())?;
                let nym_proof = self.nym.nym_proof(&nonce);
                (nym_proof, Some(nonce))
            }
        };
        let cred = self
            .issuer
            .credential()
            .with_entry(entry)
            .max_entries(&max_entries.into())
            .issue_to(&nym_proof, nonce.as_ref())
            .map_err(|e| format!("Error issuing credential: {:?}", e))?;

        // serialize and return the cred
        let cred_compressed = CredentialCompressed::from(&cred);
        Ok(cred_compressed.into())
    }

    // / Create an [CredentialCompressed] offer for the given [OfferConfig].
    pub fn offer(
        &self,
        cred: CredentialCompressed,
        config: OfferConfig,
    ) -> Result<CredentialCompressed, String> {
        let cred = Credential::try_from(cred).map_err(|e| e.to_string())?;

        let (entries, redact) = match config.selected {
            Some(includables) => {
                let entries = includables.entries;
                let redact = includables.remove;
                (entries, redact)
            }
            _ => (vec![], vec![]),
        };

        let mut offer_builder = self.nym.offer_builder(&cred, &entries);

        if let Some(additional_entry) = config.additional_entry {
            offer_builder.additional_entry(
                Entry::try_from(additional_entry)
                    .map_err(|e| format!("Additional entry failed {}", e.to_string()))?,
            );
        }

        for r in redact {
            offer_builder.without_attribute(r);
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
        // to prevent both from falling into the wrong hands. Rather, the application should create
        // some sort of "Hint" object to relay to the accepter of this offer.
        let offer_compressed = CredentialCompressed::from(offer.as_ref());
        Ok(offer_compressed.into())
    }

    /// Accept a [CredentialCompressed] offer and return a [CredentialCompressed] credential.
    pub fn accept(&self, offer: CredentialCompressed) -> Result<CredentialCompressed, String> {
        let offer = Credential::try_from(offer).map_err(|e| e.to_string())?;

        let accepted_cred = self
            .nym
            .accept(&offer.into())
            .map_err(|e| format!("Error accepting offer: {:?}", e))?;

        let accepted_compressed = CredentialCompressed::from(&accepted_cred);
        Ok(accepted_compressed.into())
    }

    /// Extend the given [CredentialCompressed] with the given [Entry].
    pub fn extend(
        &self,
        cred: CredentialCompressed,
        entry: Entry,
    ) -> Result<CredentialCompressed, String> {
        let cred = Credential::try_from(cred).map_err(|e| e.to_string())?;

        let extended_cred = self
            .nym
            .extend(&cred, &entry)
            .map_err(|e| format!("Error extending credential: {:?}", e))?;

        let extended_compressed = CredentialCompressed::from(&extended_cred);
        Ok(extended_compressed.into())
    }

    /// Prove the given [Provables], and return a [Proven] proof.
    pub fn prove(&self, provables: Provables) -> Result<Proven, String> {
        let cred = Credential::try_from(provables.credential).map_err(|e| e.to_string())?;

        let mut buildr = self.nym.proof_builder(&cred, &provables.entries);

        for s in provables.selected {
            buildr.select_attribute(s);
        }

        let nonce: Nonce = utils::nonce_by_len(&provables.nonce)?;

        let (proof, selected_entries) = buildr.prove(&nonce);

        let proof_compressed = CredProofCompressed::from(proof);

        Ok(Proven {
            proof: proof_compressed,
            selected: selected_entries,
        })
    }

    /// Verify the given [Verifiables]
    pub fn verify(&self, verifiables: Verifiables) -> Result<bool, String> {
        let issuer_public =
            IssuerPublic::try_from(verifiables.issuer_public).map_err(|e| e.to_string())?;
        let proof = CredProof::try_from(verifiables.proof).map_err(|e| e.to_string())?;

        let nonce = utils::maybe_nonce(verifiables.nonce.as_deref())?;

        let selected_entries = verifiables.selected;

        Ok(verify_proof(
            &issuer_public,
            &proof,
            &selected_entries,
            nonce.as_ref(),
        ))
    }
}