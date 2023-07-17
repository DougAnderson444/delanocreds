#![doc = include_str!("../README.md")]

use anyhow::Result;
pub use attributes::Attribute;
pub use entry::Entry;
pub use entry::MaxEntries;
pub use keypair::{spseq_uc::Credential, verify_proof, Issuer, IssuerError, NymPublic, UserKey};

pub mod attributes;
pub mod config;
pub mod entry;
pub mod keypair;
pub mod set_commits;
pub mod types;
pub mod zkp;

// Test the README.md code snippets
#[cfg(doctest)]
pub struct ReadmeDoctests;

/// Builds a Root [Credential] and issues it to a [keypair::Nym]
///
/// # Example
///
/// ```
/// use delanocreds::{Issuer, UserKey, Entry, Attribute, CredentialBuilder, MaxEntries};
///
/// let issuer = Issuer::default();
/// let alice = UserKey::new();
/// let nym = alice.nym(issuer.public.parameters.clone());
/// let root_entry = Entry::new(&[Attribute::new("age > 21")]);
/// let cred = issuer
///     .credential() // CredentialBuilder for this Issuer
///     .with_entry(root_entry.clone()) // adds a Root Entry
///     .max_entries(&MaxEntries::default()) // set the Entry ceiling
///     .issue_to(&nym.public); // issues to a Nym
/// ```
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
    pub fn max_entries(&mut self, extendable: &usize) -> &mut Self {
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
/// - `our_nym` is the [keypair::Nym] of the holder of the [Credential]
/// - `credential` is the [Credential] to offer
/// - `unprovable_attributes` is a Vec of [Attribute]s that the holder will not prove
/// - `current_entries` is a Vec of [Entry]s currently associated with the [Credential]
/// - `additional_entry` is an optional [Entry] to add to the [Credential] Offer
///
/// Given a [Credential], holder can:
/// 1. Offer with redacted proving of [Entry]s to another keypair::[Nym]
/// 2. Offer with additional [Attribute]s
/// 3. Generate a Proof themselves
///
/// # Example
///
/// ```
/// use delanocreds::{Issuer, Entry, Attribute, UserKey, CredentialBuilder, MaxEntries};
/// # fn main() -> anyhow::Result<()> {
/// let issuer = Issuer::default();
/// let alice = UserKey::new();
/// let nym = alice.nym(issuer.public.parameters.clone());
/// let root_entry = Entry::new(&[Attribute::new("age > 21")]);
/// let cred = CredentialBuilder::new(&issuer)
///     .with_entry(root_entry.clone()) // adds a Root Entry
///     .max_entries(&MaxEntries::default()) // set the Entry ceiling
///     .issue_to(&nym.public)?; // issues to a Nym
///
/// // 1. Offer the unchanged Credential to Bob's Nym
/// let bob = UserKey::new();
/// let bobby_nym = bob.nym(issuer.public.parameters.clone());
///
/// let (offer, provable_entries) = nym
///     .offer_builder(&cred, &[root_entry])
///     .offer_to(&bobby_nym.public)?;
/// # Ok(())
/// # }
pub struct OfferBuilder<'a> {
    our_nym: &'a keypair::Nym,
    credential: &'a Credential,
    unprovable_attributes: Vec<Attribute>,
    current_entries: Vec<Entry>,
    additional_entry: Option<Entry>,
    max_entries: usize,
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
            // set to cred update_key length
            max_entries: credential.update_key.as_ref().map_or(0, |k| k.len()),
        }
    }

    /// Allows the proving of [Attribute]s in an [Entry] in the [Credential] Offer.
    /// The [keypair::Nym] who accepts this offer can prove the allowed [Entry]s to a Verifier.
    ///
    /// Can add up to [entry::MaxEntries] attributes as defined for this [Issuer].
    pub fn without_attribute(&mut self, redacted: Attribute) -> &mut Self {
        self.unprovable_attributes.push(redacted);
        self
    }

    /// Add one (1) additional Entry to the Credential Offer.
    /// Additional [Entry] Can contain up to [keypair::MaxCardinality] [Attribute]s
    /// as pubically parameterized ([set_commits::ParamSetCommitment]) for this [Issuer].
    ///
    /// If used multiple times, last one will overwrite all previous additions
    pub fn additional_entry(&mut self, entry: Entry) -> &mut Self {
        self.additional_entry = Some(entry);
        self
    }

    /// Set the maximum number of Entries that can be added to the Credential by a delegatee Nym.
    pub fn max_entries(&mut self, limit: usize) -> &mut Self {
        self.max_entries = std::cmp::min(
            limit,
            self.credential.update_key.as_ref().map_or(0, |k| k.len()),
        );
        self
    }

    /// Build the Offer
    pub fn offer_to(&self, their_nym: &NymPublic) -> Result<(keypair::Offer, Vec<Entry>)> {
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
                ..cred_redacted
            };
        }

        // Second, add any additional entries
        if let Some(entry) = &self.additional_entry {
            provable_entries.push(entry.clone());
        }

        // Third, limit update_key to given extendable limit
        // which restricts delegation in how many further levels can be delegated (reduce update_key length in cred)
        cred_redacted.update_key = match self.max_entries {
            0 => None,
            _ => Some(
                self.credential
                    .update_key
                    .as_ref()
                    .unwrap()
                    .iter()
                    .take(self.max_entries)
                    .cloned()
                    .collect::<Vec<_>>(),
            ),
        };

        let offer = self
            .our_nym
            .offer(&cred_redacted, &self.additional_entry, their_nym)?;

        Ok((offer, provable_entries))
    }
}

/// Proof Builder
/// Takes selected [Attribute]s and a [Credential] and generates a [keypair::CredProof] for them.
///
/// # Example
///
/// ```
/// use delanocreds::{Issuer, UserKey, Entry, Attribute, CredentialBuilder, MaxEntries, verify_proof};
/// # fn main() -> anyhow::Result<()> {
/// let issuer = Issuer::default();
/// let alice = UserKey::new();
/// let nym = alice.nym(issuer.public.parameters.clone());
/// let over_21 = Attribute::new("age > 21");
/// let root_entry = Entry::new(&[over_21.clone()]);
/// let cred = CredentialBuilder::new(&issuer)
///     .with_entry(root_entry.clone()) // adds a Root Entry
///     .max_entries(&MaxEntries::default()) // set the Entry ceiling
///     .issue_to(&nym.public)?; // issues to a Nym
///
/// // Nym can prove the credential using the ProofBuilder
/// let (proof, selected_entries) = nym
///     .proof_builder(&cred, &[root_entry])
///     .select_attribute(over_21.clone())
///     .prove();
///
/// // Nym can verify the proof
/// assert!(verify_proof(&issuer.public.vk, &proof, &selected_entries).unwrap());
///
/// // Confirm that over_21 is not contained within the selected_entries
/// let contains_over_21 = selected_entries
///     .into_iter()
///     .any(|entry| entry.contains(&over_21));
/// assert!(contains_over_21);
///
/// # Ok(())
/// # }
pub struct ProofBuilder<'a> {
    nym: &'a keypair::Nym,
    cred: &'a Credential,
    all_attributes: Vec<Entry>,
    selected_attributes: Vec<Attribute>,
}

impl<'a> ProofBuilder<'a> {
    /// Create a new ProofBuilder
    pub fn new(nym: &'a keypair::Nym, cred: &'a Credential, all_attributes: &[Entry]) -> Self {
        Self {
            nym,
            cred,
            all_attributes: all_attributes.to_vec(),
            selected_attributes: Vec::new(),
        }
    }

    /// Add an [Attribute] to the Proof
    pub fn select_attribute(&mut self, attribute: Attribute) -> &mut Self {
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
        let proof = self
            .nym
            .prove(self.cred, &self.all_attributes, &selected_attr);

        (proof, selected_attr)
    }
}

#[cfg(test)]
mod lib_api_tests {

    use super::*;
    use crate::{
        attributes::Attribute,
        entry::{Entry, MaxEntries},
        keypair::UserKey,
    };

    #[test]
    fn test_credential_building() -> Result<()> {
        // create an Issuer, a User, and issue a cred to a Nym
        let issuer = Issuer::default();
        let alice = UserKey::new();
        let nym = alice.nym(issuer.public.parameters.clone());

        let over_21 = Attribute::new("age > 21");
        let seniors_discount = Attribute::new("age > 65");
        let root_entry = Entry::new(&[over_21, seniors_discount]);

        // Method A: as chained methods
        let cred = issuer
            .credential() // CredentialBuilder for this Issuer
            .with_entry(root_entry.clone()) // adds a Root Entry
            .max_entries(&MaxEntries::default()) // set the Entry ceiling
            .issue_to(&nym.public)?; // issues to a Nym

        assert_eq!(cred.commitment_vector.len(), 1);

        // Method B: as parameter
        let cred = CredentialBuilder::new(&issuer)
            .with_entry(root_entry.clone())
            .max_entries(&MaxEntries::default())
            .issue_to(&nym.public)?;

        assert_eq!(cred.commitment_vector.len(), 1);

        // Variant A: extendable, single Entry
        let cred = CredentialBuilder::new(&issuer)
            .with_entry(root_entry.clone())
            .max_entries(&MaxEntries::default())
            .issue_to(&nym.public)?;

        assert_eq!(cred.commitment_vector.len(), 1);
        assert_eq!(
            cred.update_key.as_ref().unwrap().len(),
            MaxEntries::default()
        );

        // Variant B: not extendable, multiple Entry
        let another_entry = Entry::new(&[Attribute::new("another entry")]);
        let cred = issuer
            .credential()
            .with_entry(root_entry)
            .with_entry(another_entry)
            .issue_to(&nym.public)?;

        assert_eq!(cred.commitment_vector.len(), 2);

        // cred should have update_key is_none
        assert!(cred.update_key.is_none());

        Ok(())
    }

    #[test]
    fn offer_tests() -> Result<()> {
        // Given a Root Credential, holder can:
        // 1. Offer the unchanged Credential to another Nym (Alice to Bob)
        // 2. Offer with additional Attributes (Bob to Charlie)
        // 3. Offer with redact proving of Entry(s) (Charlie to Douglas)
        // 4. Offer with restricted further levels of delegation, cannot add additonal_entrys past a certain limit (Douglas to Evan)
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

        // Evan
        let evan = UserKey::new();
        let evan_nym = evan.nym(issuer.public.parameters.clone());

        let over_21 = Attribute::new("age > 21");
        let seniors_discount = Attribute::new("age > 65");
        let root_entry = Entry::new(&[over_21.clone(), seniors_discount]);

        // Issue the (Powerful) Root Credential to Alice
        let cred = match issuer
            .credential()
            .with_entry(root_entry.clone())
            .max_entries(&MaxEntries::default()) // DEFAULT_MAX_ENTRIES: usize = 6
            .issue_to(&alice_nym.public)
        {
            Ok(cred) => cred,
            Err(e) => panic!("Error issuing cred: {:?}", e),
        };

        // 1. Offer the unchanged Credential to Bob's Nym
        let (offer, provable_entries) = alice_nym
            .offer_builder(&cred, &[root_entry])
            .offer_to(&bobby_nym.public)?;

        // Bob can accept
        let bobby_cred = bobby_nym.accept(&offer);

        // and prove all entries
        let proof = bobby_nym.prove(&bobby_cred, &provable_entries, &provable_entries);
        assert!(keypair::verify_proof(&issuer.public.vk, &proof, &provable_entries).unwrap());

        // or Bob can prove just the selected attribute `over_21` using ProofBuilder
        let (proof, selected_entries) = bobby_nym
            .proof_builder(&bobby_cred, &provable_entries)
            .select_attribute(over_21)
            .prove();
        assert!(keypair::verify_proof(&issuer.public.vk, &proof, &selected_entries).unwrap());

        // 2. Offer with additional Attributes, using OfferBuilder
        let handsome_attribute = Attribute::new("also handsome");
        let additional_entry = Entry::new(&[handsome_attribute.clone()]);

        let (offer, provable_entries) = bobby_nym
            .offer_builder(&bobby_cred, &provable_entries)
            .additional_entry(additional_entry)
            .offer_to(&charlie_nym.public)?;

        // Charlie can accept
        let charlie_cred = charlie_nym.accept(&offer);

        // and Charlie's Nym can prove additional selected attribute using ProofBuilder
        let (proof, selected_entries) = charlie_nym
            .proof_builder(&charlie_cred, &provable_entries)
            .select_attribute(handsome_attribute.clone())
            .prove();
        assert!(keypair::verify_proof(&issuer.public.vk, &proof, &selected_entries).unwrap());

        // 3. Charlie can Offer a redacted version of the Entry(s) to Doug
        let (offer, provable_entries) = charlie_nym
            .offer_builder(&charlie_cred, &provable_entries)
            .without_attribute(handsome_attribute.clone())
            .offer_to(&doug_nym.public)?;

        assert_eq!(provable_entries.len(), 2); // Should be 2 Entry(s) in the provable_entries, but only 1 non-empty
        assert_eq!(provable_entries[0].len(), 2); // over_21, seniors_discount
        assert_eq!(provable_entries[1].len(), 0); // empty, redacted entry with the handsome attribute

        // Doug can accept
        let doug_cred = doug_nym.accept(&offer);

        // and Doug's proof excludes the handsome_attribute
        let (_proof, selected_entries) = doug_nym
            .proof_builder(&doug_cred, &provable_entries)
            .select_attribute(handsome_attribute.clone())
            .prove();

        // show handsome_attribute is not contained within the selected_entries
        let contains_handsome = selected_entries
            .into_iter()
            .any(|entry| entry.contains(&handsome_attribute));

        // Verify handsome_attribute is not contained within the selected_entries
        assert!(!contains_handsome);

        // 4. Douglas can Offer a restricted version of the Credential to Evan
        let (offer, provable_entries) = doug_nym
            .offer_builder(&doug_cred, &provable_entries)
            .max_entries(3)
            .offer_to(&evan_nym.public)?;

        // there are already 2 entries, so Even can add one more but not two more
        let evan_entry = Entry::new(&[Attribute::new("evan entry #1")]);

        // Evan can accept
        let evan_cred = evan_nym.accept(&offer);

        // Evan can adds an entry
        let even_nym_2 = evan.nym(issuer.public.parameters.clone());
        let (offer, provable_entries) = evan_nym
            .offer_builder(&evan_cred, &provable_entries)
            .additional_entry(evan_entry)
            .offer_to(&even_nym_2.public)?;

        // Evan2 can accept
        let evan_2_cred = even_nym_2.accept(&offer);

        // Evan2 can prove added entry attributes
        let (proof, selected_entries) = even_nym_2
            .proof_builder(&evan_2_cred, &provable_entries)
            .select_attribute(Attribute::new("evan entry #1"))
            .prove();
        assert!(keypair::verify_proof(&issuer.public.vk, &proof, &selected_entries).unwrap());

        // Adding beyond Max Entries of 3 should fail
        let even_nym_3 = evan.nym(issuer.public.parameters);

        let res = even_nym_2
            .offer_builder(&evan_2_cred, &provable_entries)
            .additional_entry(Entry::new(&[Attribute::new("bigger than Max Entry")]))
            .offer_to(&even_nym_3.public);

        assert!(res.is_err());

        Ok(())
    }
}
