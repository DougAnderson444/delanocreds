use anyhow::Result;
use attributes::Attribute;
use entry::Entry;
use keypair::{spseq_uc::Credential, DelegatedCred, Issuer, IssuerError, NymPublic};

pub mod attributes;
pub mod config;
pub mod entry;
pub mod keypair;
pub mod set_commits;
pub mod types;
pub mod zkp;

// Test the README.md code snippets
// #![doc = include_str!("../README.md")]
// #[cfg(doctest)]
// pub struct ReadmeDoctests;

/// Builds a Credential
pub struct CredentialBuilder<'a> {
    entries: Vec<Entry>,
    extendable: usize,
    issuer: &'a Issuer,
}

impl<'a> CredentialBuilder<'a> {
    /// Create a new CredentialBuilder
    pub fn new(issuer: &'a Issuer) -> Self {
        Self {
            issuer,
            entries: Vec::new(),
            extendable: 0,
        }
    }

    /// Add an Entry to the Credential
    pub fn with_entry(&mut self, entry: Entry) -> &mut Self {
        self.entries.push(entry);
        self
    }

    /// Set the number of Entries that can be added to the Credential
    pub fn extendable(&mut self, extendable: &usize) -> &mut Self {
        self.extendable = *extendable;
        self
    }

    /// Finish building the Credetials, and Issue the Credential to a Nym
    pub fn issue_to(&self, nym_public: &NymPublic) -> Result<Credential, IssuerError> {
        // if self.extendable > 0, set to Some(self.extendable), else None
        let k_prime = self.extendable.checked_sub(0);
        self.issuer.issue_cred(&self.entries, k_prime, nym_public)
    }
}

/// Builds a Credential Offer
///
/// - `our_nym` is the Nym of the holder of the Credential
/// - `credential` is the Credential to offer
/// - `unprovable_attributes` is a Vec of Attributes that the holder will not prove
/// - `current_entries` is a Vec of Entries currently associated with the [Credential]
/// - `additional_entry` is an optional Entry to add to the [Credential] Offer
///
/// Given a Credential, holder can:
/// 1. Offer with redacted proving of Entry(s) to another Nym
/// 2. Offer with additional Attributes
/// 3. Generate a Proof themselves
pub struct OfferBuilder<'a> {
    our_nym: &'a keypair::Nym,
    credential: &'a Credential,
    unprovable_attributes: Vec<Attribute>,
    current_entries: Vec<Entry>,
    additional_entry: Option<Entry>,
}

impl<'a> OfferBuilder<'a> {
    pub fn new(
        our_nym: &'a keypair::Nym,
        credential: &'a Credential,
        current_entries: &[Entry],
    ) -> Self {
        Self {
            our_nym,
            credential,
            unprovable_attributes: Vec::new(),
            current_entries: current_entries.to_vec(),
            additional_entry: None,
        }
    }

    /// Allows the proving of [Attribute]s in an [Entry] in the [Credential] Offer.
    /// The [keypair::Nym] who accepts this offer can prove the allowed [Entry]s to a Verifier.
    ///
    /// Can add up to [keypair::MaxEntries] attributes as defined for this [Issuer].
    pub fn without_attribute(&mut self, redacted: Attribute) -> &mut Self {
        self.unprovable_attributes.push(redacted);
        self
    }

    /// Add one (1) additional Entry to the Credential Offer.
    /// Additional [Entry] Can contain up to [keypair::MaxCardinality] [Attribute]s
    /// as pubically parameterized ([set_commits::ParamSetCommitment]) for this [Issuer].
    ///
    /// If used multiple times, last one will overwrite all previous additions
    pub fn add_entry(&mut self, entry: Entry) -> &mut Self {
        self.additional_entry = Some(entry);
        self
    }

    /// Build the Offer
    pub fn offer_to(&self, their_nym: &NymPublic) -> Result<(keypair::CredOffer, Vec<Entry>)> {
        let mut cred_redacted = self.credential.clone();
        let mut provable_entries = self.current_entries.clone();

        // First, zerioize any attributes that are not authorized to be provable
        if !self.unprovable_attributes.is_empty() {
            // 1. iterate through the self.unprovable_attributes, set self.credential.opening_info to amcl_wrapper::field_elem::FieldElement::zero() for any current_entries containing matching unprovable_attributes
            // 2. create new self.credential with the new opening_vector_restricted value
            // 3. use new self.credential in `.offer()`
            let mut opening_vector_restricted = self.credential.opening_vector.clone();
            for unprovable_attribute in &self.unprovable_attributes {
                for (index, entry) in self.current_entries.iter().enumerate() {
                    if entry.contains(unprovable_attribute) {
                        opening_vector_restricted[index] =
                            amcl_wrapper::field_elem::FieldElement::zero();

                        // also update provable_entries
                        provable_entries[index] = Entry::new(&[]);
                    }
                }
            }

            // create copy of cred, replace opening_vector with opening_vector_restricted
            cred_redacted = Credential {
                opening_vector: opening_vector_restricted,
                ..self.credential.clone()
            };
        }

        // Second, add any additional entries
        if let Some(entry) = &self.additional_entry {
            provable_entries.push(entry.clone());
        }

        // TODO: Third, limit update key to given max
        // TODO: restrict delegation in how many further levels can be delegated (reduce update_key length)

        let offer = self
            .our_nym
            .offer(&cred_redacted, &self.additional_entry, their_nym)?;
        Ok((offer, provable_entries))
    }
}

/// Proof Builder
/// Takes selected [Attribute]s and a [Credential] and generates a [keypair::CredProof] for them.
struct ProofBuilder<'a> {
    all_attributes: Vec<Entry>,
    selected_attributes: Vec<Attribute>,
    cred: &'a DelegatedCred,
}

impl<'a> ProofBuilder<'a> {
    /// Create a new ProofBuilder
    pub fn new(all_attributes: &[Entry], cred: &'a DelegatedCred) -> Self {
        Self {
            all_attributes: all_attributes.to_vec(),
            selected_attributes: Vec::new(),
            cred,
        }
    }

    /// Add an [Attribute] to the Proof
    pub fn with_attribute(&mut self, attribute: Attribute) -> &mut Self {
        self.selected_attributes.push(attribute);
        self
    }

    /// Finish building the Proof
    pub fn prove(&self) -> (keypair::CredProof, Vec<Entry>) {
        // create selected_attr by filtering all_attributes for those in selected_attributes
        let selected_attr = self
            .all_attributes
            .iter()
            .map(
                // returns either an empty Entry or an Entry with only the selected attributes
                |entry| {
                    entry
                        .iter()
                        .filter(|attr| self.selected_attributes.contains(attr))
                        .cloned()
                        .collect::<Entry>()
                },
            )
            .collect::<Vec<Entry>>();

        // create proof
        let proof = self.cred.prove(&self.all_attributes, &selected_attr);

        (proof, selected_attr)
    }
}

#[cfg(test)]
mod test {

    use super::*;
    use crate::{
        attributes::Attribute,
        entry::Entry,
        keypair::{MaxEntries, Nym, UserKey},
    };

    #[test]
    fn test_credential_building() {
        // create an Issuer, a User, and issue a cred to a Nym
        let issuer = Issuer::default();
        let alice = UserKey::new();
        let nym = alice.nym(issuer.public.parameters.clone());

        let over_21 = Attribute::new("age > 21");
        let seniors_discount = Attribute::new("age > 65");
        let age_entry = Entry::new(&[over_21, seniors_discount]);

        // Method A: as chained methods
        let cred = match issuer
            .builder() // CredentialBuilder for this Issuer
            .with_entry(age_entry.clone())
            .extendable(&MaxEntries::default())
            .issue_to(&nym.public)
        {
            Ok(cred) => cred,
            Err(e) => panic!("Error issuing cred: {:?}", e),
        };

        assert_eq!(cred.commitment_vector.len(), 1);

        // Method B: as parameter
        let cred = match CredentialBuilder::new(&issuer)
            .with_entry(age_entry.clone())
            .extendable(&MaxEntries::default())
            .issue_to(&nym.public)
        {
            Ok(cred) => cred,
            Err(e) => panic!("Error issuing cred: {:?}", e),
        };

        assert_eq!(cred.commitment_vector.len(), 1);

        // Variant A: extendable, single Entry
        let cred = match CredentialBuilder::new(&issuer)
            .with_entry(age_entry.clone())
            .extendable(&MaxEntries::default())
            .issue_to(&nym.public)
        {
            Ok(cred) => cred,
            Err(e) => panic!("Error issuing cred: {:?}", e),
        };

        assert_eq!(cred.commitment_vector.len(), 1);
        assert_eq!(
            cred.update_key.as_ref().unwrap().len(),
            MaxEntries::default()
        );

        // Variant B: not extendable, multiple Entry
        let another_entry = Entry::new(&[Attribute::new("another entry")]);
        let cred = match issuer
            .builder()
            .with_entry(age_entry)
            .with_entry(another_entry)
            .issue_to(&nym.public)
        {
            Ok(cred) => cred,
            Err(e) => panic!("Error issuing cred: {:?}", e),
        };

        assert_eq!(cred.commitment_vector.len(), 2);

        // cred should have update_key is_none
        assert!(cred.update_key.is_none());
    }

    #[test]
    fn offer_tests() -> Result<()> {
        // Given a Root Credential, holder can:
        // 1. Offer the unchanged Credential to another Nym
        // 2. Offer with additional Attributes (use update_key to extend Entrys)
        // 3. Offer with redact proving of Entry(s) (zeroized opening_info)
        // 4. Offer with restricted further levels of delegation (update_key length)
        // 5. Generate a Proof themselves

        // create an Issuer, a User, and issue a cred to a Nym
        let issuer = Issuer::default();

        // Alice
        let alice = UserKey::new();
        let alice_nym = alice.nym(issuer.public.parameters.clone());

        // Bob
        let bob = UserKey::new();
        let bobby_nym = bob.nym(issuer.public.parameters.clone());

        // Charlie
        let charlie = UserKey::new();
        let charlie_nym = charlie.nym(issuer.public.parameters.clone());

        // Douglas
        let douglas = UserKey::new();
        let doug_nym = douglas.nym(issuer.public.parameters.clone());

        let over_21 = Attribute::new("age > 21");
        let seniors_discount = Attribute::new("age > 65");
        let age_entry = Entry::new(&[over_21, seniors_discount]);

        let cred = match issuer
            .builder()
            .with_entry(age_entry.clone())
            .extendable(&MaxEntries::default())
            .issue_to(&alice_nym.public)
        {
            Ok(cred) => cred,
            Err(e) => panic!("Error issuing cred: {:?}", e),
        };

        // cred should have Some update_key
        assert!(cred.update_key.is_some());

        // 1. Offer the unchanged Credential to another Nym
        let offer = alice_nym.offer(&cred, &None, &bobby_nym.public)?;

        // offer.cred should have Some update_key
        assert!(offer.cred.update_key.is_some());

        // Bob can accept
        let bobby_cred = bobby_nym.accept(&offer);

        // bobby_cred.cred shoudl have Some update_key too
        assert!(bobby_cred.cred.update_key.is_some());

        // and prove age_entry
        let proof = bobby_cred.prove(&[age_entry.clone()], &[age_entry.clone()]);

        // which can be verified
        assert!(keypair::verify_proof(&issuer.public.vk, &proof, &[age_entry.clone()]).unwrap());

        // 2. Offer with additional Attributes, using OfferBuilder
        let handsome_attribute = Attribute::new("also handsome");
        let additional_entry = Entry::new(&[handsome_attribute.clone()]);

        let cred = bobby_cred.cred.clone(); //grab a copy before it's moved out in Nym::from()

        // let offer = Nym::from(bobby_cred).offer(
        //     &cred,
        //     &None, // Some(additional_entry),
        //     &charlie_nym.public,
        // );

        let (offer, provable_entries) =
            OfferBuilder::new(&Nym::from(bobby_cred), &cred, &[age_entry.clone()])
                .add_entry(additional_entry)
                .offer_to(&charlie_nym.public)?;

        // Should be 2 Entry(s) in the provable_entries
        assert_eq!(provable_entries.len(), 2);

        // CredOffer should have 2 opening_vectors
        assert_eq!(offer.cred.opening_vector.len(), 2);

        // Charlie can accept
        let charlie_cred = charlie_nym.accept(&offer);

        // credential should have commit length of 2 as well
        assert_eq!(charlie_cred.cred.commitment_vector.len(), 2);

        // cred opening_vector should have 2 entries
        assert_eq!(charlie_cred.cred.opening_vector.len(), 2);

        // and Charlie can prove additional entry using ProofBuilder
        let (proof, selected_entries) = ProofBuilder::new(&provable_entries, &charlie_cred)
            .with_attribute(handsome_attribute.clone())
            .prove();

        // which can be verified
        assert!(keypair::verify_proof(&issuer.public.vk, &proof, &selected_entries).unwrap());

        // 3. Charlie can Offer a redacted version of the Entry(s) to Doug
        let cred = charlie_cred.cred.clone(); //grab a copy before it's moved out in Nym::from()
        let (offer, provable_entries) =
            OfferBuilder::new(&Nym::from(charlie_cred), &cred, &provable_entries)
                .without_attribute(handsome_attribute.clone())
                .offer_to(&doug_nym.public)?;

        // Should be 2 Entry(s) in the provable_entries, but only 1 non-empty
        assert_eq!(provable_entries.len(), 2);
        assert_eq!(provable_entries[0].len(), 2); // over_21, seniors_discount
        assert_eq!(provable_entries[1].len(), 0); // empty, redacted entry with the handsome attribute

        Ok(())
    }
}
