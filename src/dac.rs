//! This is implementation of delegatable anonymous credential using SPSQE-UC signatures and set commitment.
//! See  the following for the details:
//! - Practical Delegatable Anonymous Credentials From Equivalence Class Signatures, PETS 2023.
//!    https://eprint.iacr.org/2022/680
use super::spseq_uc;
use crate::set_commits::Commitment;
use crate::set_commits::CrossSetCommitment;
use crate::spseq_uc::Credential;
use crate::spseq_uc::EqcSign;
use crate::spseq_uc::MaxCardinality;
// use crate::spseq_uc::OpeningInformation;
use crate::spseq_uc::RandomizedPubKey;
use crate::spseq_uc::SecretWitness;
use crate::spseq_uc::Signature;
use crate::spseq_uc::VK;
use crate::utils::{InputType, PedersenOpen};
use crate::zkp::{ChallengeState, DamgardTransform, Generator, Schnorr};
use amcl_wrapper::field_elem::FieldElement;
use amcl_wrapper::group_elem::GroupElement;
use amcl_wrapper::group_elem_g1::G1;
use sha2::{Digest, Sha256};

/// DAC
/// - `spseq_uc`: EqcSign, equivalence class signature
/// - `zkp`: DamgardTransform, zero-knowledge proof
pub struct Dac {
    spseq_uc: EqcSign,
    zkp: DamgardTransform,
}

/// User
/// - `pk_u`: G1, public key of the user
/// - `sk_u`: SecretWitness, secret witness of the user
pub struct User {
    pk_u: G1,
    sk_u: SecretWitness,
}

/// Nym
/// - `secret`: [SecretWitness], secret witness of the user
/// - `proof`: [NymProof], proof of the user
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct Nym {
    secret: SecretWitness,
    proof: NymProof,
}

/// NymProof
/// - `challenge`: Challenge, challenge of the user
/// - `pedersen_open`: PedersenOpen, opening information of the user
/// - `pedersen_commit`: G1, commitment of the user
/// - `public_key`: RandomizedPubKey, public key of the Nym
/// - `response`: FieldElement, response of the user
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct NymProof {
    pub challenge: FieldElement,
    pub pedersen_open: PedersenOpen,
    pub pedersen_commit: G1,
    pub public_key: RandomizedPubKey,
    pub response: FieldElement,
}

/// CredReceived (cred_R)
/// - `orphan`: [Signature], orphan signature of the user
/// - `sig`: Credential, credential of the user
pub struct CredReceived {
    orphan: Signature,
    sig: Credential,
}

/// DelegateeCred
/// - `nym`: Nym, pseudonym of the user
/// - `cred`: Credential, credential of the user
pub struct DelegateeCred {
    pub nym: RandomizedPubKey,
    pub cred: Credential,
}

/// Credentials Proof
///
/// # Arguments
/// - `sigma`: Sigma, signature of the user
/// - `commitment_vector`: Vec<G1>, commitment vector of the user
/// - `witness_pi`: G1, witness of the user
/// - `proof_nym_p`: NymProof, proof of the pseudonym
#[derive(Clone)]
pub struct CredProof {
    sigma: Signature,
    commitment_vector: Vec<G1>,
    witness_pi: G1,
    proof_nym_p: NymProof,
}

// implementing the trait `std::convert::AsRef` from Nym
impl AsRef<Nym> for Nym {
    fn as_ref(&self) -> &Nym {
        self
    }
}

impl User {}

impl Dac {
    /// New constructor
    /// # Arguments
    /// t: max cardinality of the set. Cardinality of the set is in [1, t]. t is a public parameter.
    ///
    /// # Returns
    /// DAC
    pub fn new(t: MaxCardinality) -> Dac {
        Dac {
            spseq_uc: EqcSign::new(t),
            zkp: DamgardTransform::new(),
        }
    }

    pub fn user_keygen(&self) -> User {
        let (sk_u, pk_u) = self.spseq_uc.user_keygen();

        User { pk_u, sk_u }
    }

    /// Generate a new pseudonym and auxiliary information.
    pub fn nym_gen(&self, user: User) -> Nym {
        // pick randomness
        let psi = FieldElement::random();
        let chi = FieldElement::random();
        let g_1 = G1::generator();

        // pk_u: &G1, chi: &FieldElement, psi: &FieldElement, g_1: &G1
        let nym: RandomizedPubKey = spseq_uc::rndmz_pk(&user.pk_u, &chi, &psi, &g_1);
        let secret_wit = psi * (user.sk_u + chi);

        // create a proof for nym
        let (pedersen_commit, pedersen_open) = self.zkp.announce();

        // TODO: create func or Builder for this
        let state = ChallengeState {
            name: "schnorr".to_owned(),
            g: Generator::G1(self.zkp.pedersen.g.clone()),
            hash: Sha256::digest(pedersen_commit.to_bytes(false)).into(),
            statement: vec![Generator::G1(self.zkp.pedersen.h.clone())], // TODO: Do we want to use the default statement?
        };

        let challenge = DamgardTransform::challenge(&state);

        // (challenge: &Challenge, announce_randomness: &FieldElement, stm: &G2, secret_wit: &FieldElement)
        let response = DamgardTransform::response(
            &challenge,
            &pedersen_open.announce_randomness,
            &nym,
            &secret_wit,
        );

        let proof_nym = NymProof {
            challenge,
            pedersen_open,
            pedersen_commit,
            public_key: nym,
            response,
        };

        Nym {
            secret: secret_wit,
            proof: proof_nym,
        }
    }

    /// Issues a root credential to a user.
    /// # Arguments
    /// - vk: &Vec<VK>, verification keys of the set
    /// - attr_vector: &Vec<InputType>, attributes of the user
    /// - sk: &Vec<FieldElement>, secret keys of the set
    /// - nym: &Nym, pseudonym of the user
    /// - k_prime: Option<usize>, the number of attributes to be delegated. If None, all attributes are delegated.
    /// - proof_nym_u: NymProof, proof of the pseudonym
    pub fn issue_cred(
        &self,
        vk: &[VK],
        attr_vector: &Vec<InputType>,
        sk: &[FieldElement],
        k_prime: Option<usize>,
        nym_proof: NymProof,
    ) -> spseq_uc::Credential {
        // check if proof of nym is correct
        if self.zkp.verify(&nym_proof) {
            // check if delegate keys is provided
            let cred = self
                .spseq_uc
                .sign(&nym_proof.public_key, sk, attr_vector, k_prime);
            assert!(self.spseq_uc.verify(
                vk,
                &nym_proof.public_key,
                &cred.commitment_vector,
                &cred.sigma
            )); //, "signature/credential is not correct";
            cred
        } else {
            panic!("proof of nym is not valid");
        }
    }

    /// Delegator. Create an initial delegatable credential from a user U to a user R (an interactive protocol).
    /// - `index_l`: index of `update_key` to be used for the added element,
    ///             `[1..n]` (starts at 1)
    pub fn delegator(
        &self,
        cred_u: Credential,
        vk: &[VK],
        addl_attrs: Option<&InputType>,
        index_l: usize,
        sk_ca: &SecretWitness,
        proof_nym: &NymProof,
    ) -> CredReceived {
        // check the proof
        // assert self.zkp.verify(challenge, pedersen_open, pedersen_commit, stm, response)
        assert!(self.zkp.verify(proof_nym));

        let mu = FieldElement::one();
        let cred_r = self.spseq_uc.change_rel(addl_attrs, index_l, cred_u, &mu);

        // self.spseq_uc.send_convert_sig(vk, sk_ca, cred_u.sigma)
        let orphan = self
            .spseq_uc
            .send_convert_sig(vk, sk_ca, cred_r.sigma.clone());

        // (orphan sig, commitment_l, cred_r, opening_info)
        CredReceived {
            orphan,
            sig: cred_r,
        }
    }

    /// Delegated User (delegatee) uses this function to anonimize the credential to a pseudonym of themself.
    ///
    /// The delegatee can use this function to create a pseudonym for a given credential.
    /// This way, they can use the credential anonymously, only revealing the identity of the issuer.
    /// Delegatee creates a delegatable credential to a user R
    // delegatee(cred_R_U, sub_mess_str, secret_nym_R, nym_R) -> (sigma_prime, rndmz_commitment_vector, rndmz_opening_vector, nym_P, chi)
    pub fn delegatee(
        &self,
        vk_ca: &[VK],
        cred: &CredReceived, // credential got from delegator
        nym_r: &Nym,
    ) -> (DelegateeCred, FieldElement) {
        let sigma_new =
            self.spseq_uc
                .receive_convert_sig(vk_ca, &nym_r.secret, cred.orphan.clone());

        // verify the signature of the credential first
        assert!(self.spseq_uc.verify(
            vk_ca,
            &nym_r.proof.public_key,
            &cred.sig.commitment_vector,
            &sigma_new
        ));

        // replace the sigma in the cred signature
        let signature_changed = Credential {
            sigma: sigma_new,
            commitment_vector: cred.sig.commitment_vector.clone(),
            opening_vector: cred.sig.opening_vector.clone(),
            update_key: cred.sig.update_key.clone(),
        };

        // pick randomness mu, psi
        let randomize_update_key = false;
        let mu = FieldElement::one();
        let psi = FieldElement::random();

        // run changrep to randomize and hide the whole credential
        let (nym_p, cred_p, chi) = self.spseq_uc.change_rep(
            vk_ca,                   // verification key
            &nym_r.proof.public_key, //
            &signature_changed,      // sigma_change
            &mu,
            &psi,
            randomize_update_key,
        );

        // update aux_r with chi and psi
        let aux_p_secret_wit = (nym_r.secret.clone() + chi) * psi;

        // return output a new credential for the additional attribute set as well as the new user
        // a EqcSignature needs: sigma, commitment_vector, opening_vector (if further delegation allowed), update_key (if updates to the attributes allowed)
        (
            DelegateeCred {
                // sigma: cred_p.sigma,
                // commitment_vector: cred_p.commitment_vector,
                // opening_vector: cred_p.opening_vector,
                nym: nym_p,
                cred: cred_p, // chi,
            },
            aux_p_secret_wit,
        )
    }

    /// Prove a Credential
    /// Generates a proof of a credential for a given pseudonym and selective disclosure D.
    ///
    /// - `vk`: &[VK], verification keys of the set
    /// - `nym_r`: &G1, pseudonym of the user
    /// - `aux_r`: &FieldElement, secret witness of the user
    /// - `cred`: &Credential, credential of the user
    /// - `all_attributes`: &[InputType], attributes of the user
    /// - `selected_attrs`: &[InputType], attributes to be disclosed
    pub fn proof_cred(
        &self,
        vk: &[VK],
        nym_r: &G1,
        aux_r: &FieldElement,
        cred_r: &Credential,
        all_attributes: &[InputType],
        selected_attrs: &[InputType],
    ) -> CredProof {
        let mu = FieldElement::one();
        let psi = FieldElement::random();

        // run change rep to randomize credential and user pk (i.e., create a new nym)
        // vk: &[VK], pk_u: &G1, orig_sig: &EqcSignature, mu: &FieldElement, psi: &FieldElement, b: bool
        let randomize_update_key = false;
        let (nym_p, cred_p, chi) =
            self.spseq_uc
                .change_rep(vk, nym_r, cred_r, &mu, &psi, randomize_update_key);

        // create a Pedersen zkp announcement
        let (pedersen_commit, pedersen_open) = self.zkp.announce();

        // get a challenge
        let state = ChallengeState {
            name: "schnorr".to_owned(),
            g: Generator::G1(self.zkp.pedersen.g.clone()),
            hash: Sha256::digest(pedersen_commit.to_bytes(false)).into(),
            statement: vec![Generator::G1(self.zkp.pedersen.h.clone())],
        };
        let challenge = DamgardTransform::challenge(&state);

        // prover creates a respoonse (or proof)
        // update aux_r with chi and psi
        let secret_wit = (aux_r + chi) * psi;
        let response = DamgardTransform::response(
            &challenge,
            &pedersen_open.announce_randomness,
            &nym_p,
            &secret_wit,
        );

        let proof_nym_p = NymProof {
            challenge,
            pedersen_open,
            pedersen_commit,
            public_key: nym_p,
            response,
        };

        // create a witness for the attributes set that needed to be disclosed
        // selected_attrs needs to be of length equal to or less than cred_p.commitment_vector
        let (witness, commit_vector) = selected_attrs.iter().enumerate().fold(
            (Vec::new(), Vec::new()),
            |(mut witness, mut commitment_vectors), (i, selected_attr)| {
                if let Some(opened) = CrossSetCommitment::open_subset(
                    &self.spseq_uc.csc_scheme.param_sc,
                    &all_attributes[i],
                    &cred_p.opening_vector[i],
                    selected_attr,
                ) {
                    witness.push(opened);
                }
                commitment_vectors.push(cred_p.commitment_vector[i].clone());
                (witness, commitment_vectors)
            },
        );

        let witness_pi = CrossSetCommitment::aggregate_cross(&witness, &commit_vector);

        // output the whole proof = (sigma_prime, rndmz_commitment_vector, nym_P, Witness_pi, proof_nym_p)
        CredProof {
            sigma: cred_p.sigma,
            commitment_vector: cred_p.commitment_vector, // type: Vec<G1>
            witness_pi,                                  // type: G1
            proof_nym_p, // type: (FieldElement, PedersenOpening, PedersenCommitment, G1, FieldElement)
        }
    }

    /// Verify proof of a credential
    pub fn verify_proof(
        &self,
        vk: &[VK],
        proof: &CredProof,
        selected_attrs: &Vec<InputType>,
    ) -> bool {
        // filter set commitments regarding the selected attributes
        let commitment_vectors = proof.commitment_vector[..selected_attrs.len()].to_vec();

        // check the proof is valid for each
        let check_verify_cross = CrossSetCommitment::verify_cross(
            &self.spseq_uc.csc_scheme.param_sc,
            &commitment_vectors,
            selected_attrs,
            &proof.witness_pi,
        );

        let check_zkp_verify = self.zkp.verify(&proof.proof_nym_p);

        let verify_sig = self.spseq_uc.verify(
            vk,
            &proof.proof_nym_p.public_key,
            &proof.commitment_vector,
            &proof.sigma,
        );

        eprintln!("check_verify_cross: {check_verify_cross}");
        eprintln!("check_zkp_verify: {check_zkp_verify}");
        eprintln!("verify_sig: {}", verify_sig);
        // assert both check_verify_cross and check_zkp_verify are true && spseq_uc.verify
        check_verify_cross && check_zkp_verify && verify_sig
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::spseq_uc::AttributesLength;
    use crate::utils::InputType;

    #[test]
    fn test_root_cred() {
        // Test the creation of a root credential.
        let age = "age = 30";
        let name = "name = Alice ";
        let drivers = "driver license = 12";
        let gender = "gender = male";
        let company = "company = ACME";
        let drivers_type_b = "driver license type = B";
        // let insurance = "Insurance = 2";
        // let car_type = "Car type = BMW";

        let message1_str = vec![age.to_owned(), name.to_owned(), drivers.to_owned()];
        let message2_str = vec![
            gender.to_owned(),
            company.to_owned(),
            drivers_type_b.to_owned(),
        ];

        let max_cardinality = 5;
        let l_message = AttributesLength(10);
        let dac = Dac::new(MaxCardinality(max_cardinality));

        // create user key pair
        let user = dac.user_keygen();
        let (sk_ca, vk_ca) = dac.spseq_uc.sign_keygen(l_message);

        // create nym  and a proof for nym
        let nym = dac.nym_gen(user);

        // create a root credential
        let cred = dac.issue_cred(
            &vk_ca,
            &vec![
                InputType::VecString(message1_str),
                InputType::VecString(message2_str),
            ],
            &sk_ca,
            Some(3),
            nym.proof.clone(),
        );

        // check the correctness of root credential
        // assert (spseq_uc.verify(pp_sign, vk_ca, nym_u, commitment_vector, sigma))
        assert!(dac.spseq_uc.verify(
            &vk_ca,
            &nym.proof.public_key,
            &cred.commitment_vector,
            &cred.sigma
        ));
    }

    #[test]
    fn test_delegate_only() {
        // Test issuing/delegating a credential of user U to a user R.
        let age = "age = 30";
        let name = "name = Alice ";
        let drivers = "driver license = 12";
        let gender = "gender = male";
        let company = "company = ACME";
        let drivers_type_b = "driver license type = B";
        // let insurance = "Insurance = 2";
        // let car_type = "Car type = BMW";

        let message1_str = vec![age.to_owned(), name.to_owned(), drivers.to_owned()];
        let message2_str = vec![
            gender.to_owned(),
            company.to_owned(),
            drivers_type_b.to_owned(),
        ];

        // Test proving a credential to verifiers
        let all_attributes = vec![
            InputType::VecString(message1_str),
            InputType::VecString(message2_str),
        ];

        let max_cardinality = 6; // TODO: Better contraints -- max cardinality impacts aggregation total too
        let l_message = AttributesLength(10);
        let dac = Dac::new(MaxCardinality(max_cardinality));
        // TODO: Move sk_ca, vk_ca to DAC inner? Depends if you figure it'll be used with multiple keypairs
        let (sk_ca, vk_ca) = dac.spseq_uc.sign_keygen(l_message);

        // create user key pair
        let user = dac.user_keygen();
        // create pseudonym for User
        let nym_u = dac.nym_gen(user);

        // Issue cred to Nym_U
        let k_prime = None; // no updates allowed
        let cred = dac.issue_cred(
            &vk_ca,
            &all_attributes,
            &sk_ca,
            k_prime,
            nym_u.proof.clone(),
        );

        // generate key pair of user R
        let user_r: User = dac.user_keygen();
        // generate a pseudonym for the User_R with corresponding secret key of nym + proof of nym
        let nym_r: Nym = dac.nym_gen(user_r);

        // create a credential for new nym_R: delegator P -> delegatee R
        let cred_r_u: CredReceived =
            dac.delegator(cred.clone(), &vk_ca, None, 3, &nym_u.secret, &nym_r.proof);

        // verify change_rel
        assert!(dac.spseq_uc.verify(
            &vk_ca,
            &nym_u.proof.public_key, //pubkey used to make signature `cred`, used in change_rel
            &cred.commitment_vector, //
            &cred.sigma
        ));

        let (cred_p, aux_p) = dac.delegatee(&vk_ca, &cred_r_u, &nym_r);

        assert!(dac.spseq_uc.verify(
            &vk_ca,
            &cred_p.nym,
            &cred_p.cred.commitment_vector,
            &cred_p.cred.sigma
        ));

        // TODO: Generate proof and verify from new cred
        // For us to generate a proof, we need:
        // 1. A credential assigned to nym_p
        // 2. The associated secret key of nym_p

        // when delegatee() is run, changerep assigns the cred to a randomized pk given random psi and chi.
        // We either need to
        // A) use the sk for the randomized pk, or
        // B) change the rep back to pk and use the sk for the original pk

        // let selected_attrs = vec![
        //     InputType::VecString(vec![age.to_owned(), name.to_owned()]),
        //     InputType::VecString(vec![]),
        // ];

        // prepare a proof
        let proof = dac.proof_cred(
            &vk_ca,
            &cred_p.nym,
            &aux_p,
            &cred_p.cred,
            &all_attributes,
            &all_attributes,
        );

        assert!(dac.verify_proof(&vk_ca, &proof, &all_attributes));
    }

    #[test]
    fn test_prove_subset_creds() {
        // Test issuing/delegating a credential of user U to a user R.
        let age = "age = 30";
        let name = "name = Alice";
        let drivers = "driver license = 12";
        let gender = "gender = male";
        let company = "company = ACME";
        let drivers_type_b = "driver license type = B";
        let insurance = "Insurance = 2";
        let car_type = "Car type = BMW";

        let message1_str = vec![age.to_owned(), name.to_owned(), drivers.to_owned()];
        let message2_str = vec![
            gender.to_owned(),
            company.to_owned(),
            drivers_type_b.to_owned(),
        ];
        let message3_str = vec![insurance.to_owned(), car_type.to_owned()];

        // Test proving a credential to verifiers
        let all_attributes = vec![
            InputType::VecString(message1_str),
            InputType::VecString(message2_str),
            InputType::VecString(message3_str),
        ];

        let max_cardinality = 8;
        let l_message = AttributesLength(5);
        let dac = Dac::new(MaxCardinality(max_cardinality));
        // TODO: Move sk_ca, vk_ca to DAC inner? Depends if you figure it'll be used with multiple keypairs
        let (sk_ca, vk_ca) = dac.spseq_uc.sign_keygen(l_message);

        // create user key pair
        let user = dac.user_keygen();
        // create pseudonym for User
        let nym_p = dac.nym_gen(user);

        // Issue cred to nym_p
        let k_prime = Some(4); // k_prime must be: 0 < k_prime < l_message
        let cred = dac.issue_cred(
            &vk_ca,
            &all_attributes,
            &sk_ca,
            k_prime,
            nym_p.proof.clone(),
        );

        // subset of each message set
        let sub_list1_str = vec![age.to_owned(), name.to_owned()];
        let sub_list2_str = vec![gender.to_owned(), company.to_owned()];

        // TODO: redesign the API to choose selected attrs as indexes of all attributes
        let selected_attrs = vec![
            InputType::VecString(sub_list1_str),
            InputType::VecString(sub_list2_str),
        ];

        // prepare a proof
        let proof = dac.proof_cred(
            &vk_ca,
            &nym_p.proof.public_key,
            &nym_p.secret,
            &cred,
            &all_attributes,
            &selected_attrs,
        );

        assert!(dac.verify_proof(&vk_ca, &proof, &selected_attrs));
    }

    #[test]
    fn test_delegate_subset() {
        // Test issuing/delegating a credential of user U to a user R.
        let age = "age = 30";
        let name = "name = Alice";
        let drivers = "driver license = 12";
        let gender = "gender = male";
        let company = "company = ACME";
        let drivers_type_b = "driver license type = B";
        let insurance = "Insurance = 2";
        let car_type = "Car type = BMW";

        let message1_str = vec![age.to_owned(), name.to_owned(), drivers.to_owned()];
        let message2_str = vec![
            gender.to_owned(),
            company.to_owned(),
            drivers_type_b.to_owned(),
        ];
        let message3_str = vec![insurance.to_owned(), car_type.to_owned()];

        // Test proving a credential to verifiers
        let all_attributes = vec![
            InputType::VecString(message1_str),
            InputType::VecString(message2_str),
            InputType::VecString(message3_str),
        ];

        let max_cardinality = 8;
        let l_message = AttributesLength(5);
        let dac = Dac::new(MaxCardinality(max_cardinality));
        // TODO: Move sk_ca, vk_ca to DAC inner? Depends if you figure it'll be used with multiple keypairs
        let (sk_ca, vk_ca) = dac.spseq_uc.sign_keygen(l_message);

        // create user key pair
        let alice = dac.user_keygen();
        // create pseudonym for User
        let alice_nym = dac.nym_gen(alice);

        // Issue cred to Nym_U
        let position = 5; // index of the update key to be used for the added element
        let index_l = all_attributes.len() + position;
        let k_prime = Some(std::cmp::max(index_l, l_message.into())); // k_prime must be: MIN(messages_vector.len()) < k_prime < MAX(l_message)
        let cred = dac.issue_cred(
            &vk_ca,
            &all_attributes,
            &sk_ca,
            k_prime,
            alice_nym.proof.clone(),
        );

        let robert = dac.user_keygen();
        // generate a pseudonym for Robert
        let bobby_nym = dac.nym_gen(robert);

        // Alice needs to nullify the first level of the opening vector so that Bobby doesn't have fll CRUD
        // capabilities. This is done by setting the first level of the opening vector to zero value FieldElement
        // setting cred.opening_vector = vec![FieldElement::zero(), ..rest]
        let mut opening_vector_restricted = cred.opening_vector;
        opening_vector_restricted[2] = FieldElement::zero();

        let cred_restricted = Credential {
            sigma: cred.sigma,
            commitment_vector: cred.commitment_vector,
            // restrict opening to read only
            opening_vector: opening_vector_restricted,
            update_key: cred.update_key,
        };

        // create a credential for new nym_R: delegator P -> delegatee R
        let alice_del_to_bobby: CredReceived = dac.delegator(
            cred_restricted,
            &vk_ca,
            None,
            index_l,
            &alice_nym.secret,
            &bobby_nym.proof,
        );

        let (bobbys_delegated, aux_bobby) = dac.delegatee(&vk_ca, &alice_del_to_bobby, &bobby_nym);

        assert!(dac.spseq_uc.verify(
            &vk_ca,
            &bobbys_delegated.nym,
            &bobbys_delegated.cred.commitment_vector,
            &bobbys_delegated.cred.sigma
        ));

        // subset of each message set
        let sub_list1_str = vec![age.to_owned(), name.to_owned()];
        let sub_list2_str = vec![gender.to_owned(), company.to_owned()];

        let selected_attrs = vec![
            InputType::VecString(sub_list1_str),
            InputType::VecString(sub_list2_str),
        ];

        // Bobby generate proof on read_only cred at level 2 of attribute hierarchy
        let proof = dac.proof_cred(
            &vk_ca,
            &bobbys_delegated.nym,
            &aux_bobby,
            &bobbys_delegated.cred,
            &all_attributes,
            &selected_attrs,
        );

        assert!(dac.verify_proof(&vk_ca, &proof, &selected_attrs));
    }
}
