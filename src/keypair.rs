//! This is implementation of delegatable anonymous credential using SPSQE-UC signatures and set commitment.
//! See  the following for the details:
//! - Practical Delegatable Anonymous Credentials From Equivalence Class Signatures, PETS 2023.
//!    [https://eprint.iacr.org/2022/680](https://eprint.iacr.org/2022/680)
use crate::set_commits::Commitment;
use crate::set_commits::CrossSetCommitment;
use crate::set_commits::ParamSetCommitment;
use crate::utils::convert_entry_to_bn;
use crate::{
    utils::{Entry, PedersenOpen},
    zkp::Schnorr,
    zkp::{ChallengeState, DamgardTransform, Generator},
};
use amcl_wrapper::errors::SerzDeserzError;
use amcl_wrapper::extension_field_gt::GT;
use amcl_wrapper::univar_poly::UnivarPolynomial;
use amcl_wrapper::{
    field_elem::FieldElement, group_elem::GroupElement, group_elem_g1::G1, group_elem_g2::G2,
};
use secrecy::{ExposeSecret, Secret};
use sha2::{Digest, Sha256};
use spseq_uc::OpeningInformation;
use spseq_uc::UpdateError;
use spseq_uc::{Credential, RandomizedPubKey};
use std::ops::Deref;
use std::ops::Mul;

pub mod spseq_uc;

#[derive(Debug, Clone, PartialEq)]
pub struct MaxCardinality(pub usize);

impl From<&usize> for MaxCardinality {
    fn from(item: &usize) -> Self {
        MaxCardinality(*item)
    }
}

impl From<usize> for MaxCardinality {
    fn from(item: usize) -> Self {
        MaxCardinality(item)
    }
}
impl From<MaxCardinality> for usize {
    fn from(item: MaxCardinality) -> Self {
        item.0
    }
}

impl Deref for MaxCardinality {
    type Target = usize;
    fn deref(&self) -> &usize {
        &self.0
    }
}

impl MaxCardinality {
    pub fn new(item: usize) -> Self {
        MaxCardinality(item)
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct MaxEntries(pub usize);

impl From<usize> for MaxEntries {
    fn from(item: usize) -> Self {
        MaxEntries(item)
    }
}
impl From<MaxEntries> for usize {
    fn from(item: MaxEntries) -> Self {
        item.0
    }
}

impl Deref for MaxEntries {
    type Target = usize;
    fn deref(&self) -> &usize {
        &self.0
    }
}

impl MaxEntries {
    pub fn new(item: usize) -> Self {
        MaxEntries(item)
    }
}

/// Root Issuer aka Certificate Authority
/// - `public_parameters`: [`ParamSetCommitment`], public parameters of the user
/// - `sk`: [`Secret`], secret keys of the user
/// - `vk`: `Vec<VK>`, [VK] verification keys of the user
pub struct Signer {
    pub public_parameters: ParamSetCommitment,
    sk: Secret<Vec<FieldElement>>,
    pub vk: Vec<VK>,
}

/// Verification Key
/// This key has elements from both G1 and G2,
/// so to make a Vector of [VK], we need to use enum
#[derive(Debug, Clone)]
pub enum VK {
    G1(G1),
    G2(G2),
}

impl Signer {
    pub fn new(t: MaxCardinality, l_message: MaxEntries) -> Signer {
        let public_parameters = CrossSetCommitment::new(t).public_parameters();

        // compute secret keys for each item in l_message
        // sk has to be at least 2 longer than l_message, to compute `list_z` in `sign()` function which adds +2
        let sk = Secret::new(
            (0..l_message.0 + 2)
                .map(|_| FieldElement::random())
                .collect::<Vec<_>>(),
        );

        let mut vk: Vec<VK> = sk
            .expose_secret()
            .iter()
            .map(|sk_i| VK::G2(public_parameters.g_2.scalar_mul_const_time(sk_i)))
            .collect::<Vec<_>>();

        // compute X_0 keys that is used for delegation
        let x_0 = public_parameters
            .g_1
            .scalar_mul_const_time(&sk.expose_secret()[0]);
        vk.insert(0, VK::G1(x_0)); // vk is now of length l_message + 1 (or sk + 1)

        Signer {
            public_parameters,
            sk,
            vk,
        }
    }

    /// Issues a root credential to a user.
    /// # Arguments
    /// - `vk`: Vector of [VK] verification keys of the set
    /// - attr_vector: `&Vec<Entry>`, attributes of the user
    /// - sk: `&Vec<FieldElement>`, secret keys of the set
    /// - nym: &Nym, pseudonym of the user
    /// - k_prime: `Option<usize>`, the number of attributes to be delegated. If None, no attributes are updatable.
    /// - proof_nym_u: NymProof, proof of the pseudonym
    pub fn issue_cred(
        &self,
        attr_vector: &[Entry],
        k_prime: Option<usize>,
        nym_public: &NymPublic,
    ) -> Result<Credential, SerzDeserzError> {
        // check if proof of nym is correct
        if DamgardTransform::verify(&nym_public.proof, &nym_public.damgard) {
            // check if delegate keys is provided
            let cred = self.sign(&nym_public.proof.public_key, attr_vector, k_prime)?;
            assert!(verify(
                &self.vk,
                &nym_public.proof.public_key,
                &cred.commitment_vector,
                &cred.sigma
            ));
            Ok(cred)
        } else {
            panic!("proof of nym is not valid");
        }
    }

    /// Generates a signature for the commitment and related opening information along with update key.
    /// # Arguments
    /// pk_u: user public key
    /// messages_vector: vector of messages
    /// k_prime: index defining number of delegatable attributes in update key
    ///
    /// # Returns
    /// signature, opening information, update key
    fn sign(
        &self,
        pk_u: &G1,
        messages_vector: &[Entry],
        k_prime: Option<usize>,
    ) -> Result<Credential, SerzDeserzError> {
        // encode all messagse sets of the messages vector as set commitments
        let (commitment_vector, opening_vector): (Vec<G1>, Vec<FieldElement>) = messages_vector
            .iter()
            .map(|mess| encode(&self.public_parameters, mess))
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .unzip();

        // pick randomness for y_g1
        let y_rand = FieldElement::random();

        // compute sign -> sigma = (Z, Y, hat Ym t)
        let list_z = commitment_vector
            .iter()
            .enumerate()
            .map(|(i, c)| c.scalar_mul_const_time(&self.sk.expose_secret()[i + 2]))
            .collect::<Vec<_>>();

        // temp_point = sum of all ec points in list_Z
        let temp_point = list_z.iter().fold(G1::identity(), |acc, x| acc + x);

        // Z is y_rand mod_inverse(order) times temp_point
        let z = y_rand.inverse() * temp_point;

        // Y = y_rand * g_1
        let y_g1 = self.public_parameters.g_1.scalar_mul_const_time(&y_rand);

        // Y_hat = y_rand * g_2
        let y_hat = self.public_parameters.g_2.scalar_mul_const_time(&y_rand);

        // t = sk[1] * Y + sk[0] * pk_u
        let t = y_g1.scalar_mul_const_time(&self.sk.expose_secret()[1])
            + pk_u.scalar_mul_const_time(&self.sk.expose_secret()[0]);

        let sigma = Signature { z, y_g1, y_hat, t };

        // check if the update key is requested
        // then compute update key using k_prime,
        // otherwise compute signature without it
        let mut update_key = None;
        if let Some(k_prime) = k_prime {
            let mut k_prime = k_prime;

            if k_prime > messages_vector.len() {
                // k_prime upper bounds: enusre k_prime is at most sk.len() - 2, which is l_message length from sign_keygen()
                k_prime = k_prime.min(self.sk.expose_secret().len() - 2);

                let mut usign = Vec::new();
                usign.resize(k_prime, Vec::new()); // update_key is k < k' < l, same length as l_message.length, which is same as sk

                // only valid keys are between commitment length (k) an length (l), k_prime.length = k < k' < l
                for k in (messages_vector.len() + 1)..=k_prime {
                    let mut uk = Vec::new();
                    for i in 0..self.public_parameters.max_cardinality {
                        let uk_i = self.public_parameters.pp_commit_g1[i]
                            .scalar_mul_const_time(&y_rand.inverse())
                            .scalar_mul_const_time(&self.sk.expose_secret()[k + 1]); // this is `k + 1` because sk[0] and sk[1] are used for t
                        uk.push(uk_i);
                    }
                    usign[k - 1] = uk; // first element is index 0 (message m is index m-1)
                }
                update_key = Some(usign);

                return Ok(Credential {
                    sigma,
                    update_key,
                    commitment_vector,
                    opening_vector,
                });
            }
            // k_prime of equal or lesser value than current message length has no effect
            // since the whole point of k_prime is to extend the message length!
        }

        Ok(Credential {
            sigma,
            update_key,
            commitment_vector,
            opening_vector,
        })
    }
}

/// Encodes a message set into a set commitment with opening information
fn encode(
    public_parameters: &ParamSetCommitment,
    mess_set: &Entry,
) -> Result<(G1, OpeningInformation), SerzDeserzError> {
    CrossSetCommitment::commit_set(public_parameters, mess_set)
}

/// Verifies a signature for a given message set
/// # Arguments
/// - `vk`: verification key
/// - `pk_u`: user public key
/// - `commitment_vector`: vector of commitments
/// - `sigma`: signature
pub fn verify(vk: &[VK], pk_u: &G1, commitment_vector: &[G1], sigma: &Signature) -> bool {
    let g_1 = &G1::generator();
    let g_2 = &G2::generator();
    let Signature { z, y_g1, y_hat, t } = sigma;

    let right_side = GT::ate_pairing(z, y_hat);

    let pairing_op = commitment_vector
        .iter()
        .zip(vk.iter().skip(3))
        .map(|(c, vkj3)| {
            if let VK::G2(vkj3) = vkj3 {
                GT::ate_pairing(c, vkj3)
            } else {
                panic!("Invalid verification key");
            }
        })
        .collect::<Vec<_>>();

    // left_side = product_GT(pairing_op)
    let left_side = pairing_op.iter().fold(GT::one(), GT::mul);

    if let VK::G2(vk2) = &vk[2] {
        if let VK::G2(vk1) = &vk[1] {
            GT::ate_pairing(y_g1, g_2) == GT::ate_pairing(g_1, y_hat)
                && GT::ate_pairing(t, g_2)
                    == GT::ate_pairing(y_g1, vk2) * GT::ate_pairing(pk_u, vk1)
                && right_side == left_side
        } else {
            panic!("Invalid verification key");
        }
    } else {
        panic!("Invalid verification key");
    }
}

pub struct UserKey {
    sk_u: Secret<FieldElement>,
    pk_u: G1,
}

impl Default for UserKey {
    fn default() -> Self {
        Self::new()
    }
}

impl UserKey {
    pub fn new() -> UserKey {
        let sk_u = Secret::new(FieldElement::random());
        UserKey {
            pk_u: G1::generator().scalar_mul_const_time(sk_u.expose_secret()),
            sk_u,
        }
    }

    /// Generates a pseudonym for the user tuned to this Signer's Pulic Parameters.
    pub fn nym(&self, public_parameters: ParamSetCommitment) -> Nym {
        // pick randomness
        let psi = FieldElement::random();
        let chi = FieldElement::random();
        let g_1 = G1::generator();

        // pk_u: &G1, chi: &FieldElement, psi: &FieldElement, g_1: &G1
        let nym: RandomizedPubKey = spseq_uc::rndmz_pk(&self.pk_u, &chi, &psi, &g_1);
        let secret_wit = Secret::new(psi * (self.sk_u.expose_secret() + chi));

        // create a proof for nym
        let damgard = DamgardTransform::new();
        let (pedersen_commit, pedersen_open) = damgard.announce();

        // TODO: create func or Builder for this
        let state = ChallengeState {
            name: "schnorr".to_owned(),
            g: Generator::G1(damgard.pedersen.g.clone()),
            hash: Sha256::digest(pedersen_commit.to_bytes(false)).into(),
            statement: vec![Generator::G1(damgard.pedersen.h.clone())], // TODO: Do we want to use the default statement?
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
            public: NymPublic {
                proof: proof_nym,
                damgard,
                public_parameters,
            },
        }
    }
}

/// Nym
/// - `secret`: [`Secret`], secret witness of the user
/// - pub `public`: [`NymPublic`], proof of the user
pub struct Nym {
    secret: Secret<FieldElement>,
    pub public: NymPublic,
}

/// Pseudonym Public information
/// - `proof`: [`NymProof`], proof of the user
/// - `damgard`: [`DamgardTransform`], damgard transform of the user
/// - `public_parameters`: [`ParamSetCommitment`], public parameters of the user
#[derive(Clone)]
pub struct NymPublic {
    pub proof: NymProof,
    pub damgard: DamgardTransform,
    pub public_parameters: ParamSetCommitment,
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

impl Nym {
    /// Creates an offer for a credential.
    /// Note: This orphan signture can be accepted by any holder once created,
    /// so it is important to keep it secret until it is used (accepted).
    pub fn offer(
        &self,
        cred: &Credential,
        vk: &[VK],
        addl_attrs: &Option<Entry>,
        their_nym: &NymPublic,
    ) -> CredOffer {
        // check the proof
        // assert self.zkp.verify(challenge, pedersen_open, pedersen_commit, stm, response)
        assert!(DamgardTransform::verify(
            &their_nym.proof,
            &their_nym.damgard
        ));

        let mut cred_r = cred.clone();
        if let Some(addl_attrs) = addl_attrs {
            let mu = FieldElement::one();
            if let Ok(cred_pushed) = self.change_rel(addl_attrs, cred_r.clone(), &mu) {
                cred_r = cred_pushed;
            }
        }

        // self.spseq_uc.send_convert_sig(vk, sk_ca, cred_u.sigma)
        let orphan = self.send_convert_sig(vk, cred_r.sigma.clone());

        // (orphan sig, commitment_l, cred_r, opening_info)
        CredOffer {
            orphan,
            cred: cred_r,
            vk: vk.to_vec(),
        }
    }

    /// Delegated User (delegatee) uses this function to anonimize the credential to a pseudonym of themself.
    ///
    /// The delegatee can use this function to create a pseudonym for a given credential.
    /// This way, they can use the credential anonymously, only revealing the identity of the issuer.
    /// Delegatee creates a delegatable credential to a user R
    // delegatee(cred_R_U, sub_mess_str, secret_nym_R, nym_R) -> (sigma_prime, rndmz_commitment_vector, rndmz_opening_vector, nym_P, chi)
    pub fn accept(
        &self,
        cred: &CredOffer, // credential got from delegator
    ) -> DelegatedCred {
        let sigma_new = self.receive_cred(&cred.vk, cred.orphan.clone());

        // verify the signature of the credential first
        assert!(verify(
            &cred.vk,
            &self.public.proof.public_key,
            &cred.cred.commitment_vector,
            &sigma_new
        ));

        // replace the sigma in the cred signature
        let signature_changed = Credential {
            sigma: sigma_new,
            commitment_vector: cred.cred.commitment_vector.clone(),
            opening_vector: cred.cred.opening_vector.clone(),
            update_key: cred.cred.update_key.clone(),
        };

        // pick randomness mu, psi
        let updatable = false;
        let mu = FieldElement::one();
        let psi = FieldElement::random();

        // run change_rep to randomize and hide the whole credential
        // this way the cred proof nym can't be traced to the cred issue nym!
        let (nym_p, cred_p, chi) = spseq_uc::change_rep(
            &cred.vk,
            &self.public.proof.public_key,
            &signature_changed,
            &mu,
            &psi,
            updatable,
        );

        // update aux_r with chi and psi
        let aux_p_secret_wit = Secret::new((self.secret.expose_secret() + chi) * psi);

        // return output a new credential for the additional attribute set as well as the new user
        // a EqcSignature needs: sigma, commitment_vector, opening_vector (if further delegation allowed), update_key (if updates to the attributes allowed)
        DelegatedCred {
            // sigma: cred_p.sigma,
            // commitment_vector: cred_p.commitment_vector,
            // opening_vector: cred_p.opening_vector,
            nym: nym_p,
            cred: cred_p, // chi,
            secret: aux_p_secret_wit,
            vk: cred.vk.to_vec(),
            nym_public: self.public.clone(),
        }
    }

    /// Delegate by Converting a Signature.
    /// It is an algorithm run by a user who wants to delegate a
    /// signature σ. It takes as input the public verification key vk, a secret key sku and the signature.
    /// It outputs an orphan signature σ. Creates a temporary (orphan) signature
    /// used by the delegatee to finish converting the signature.
    ///
    /// # Arguments
    /// vk: Verification Key
    /// sk_u: Secret Key
    /// sigma: Sigma {Z, Y, Y_hat, t} signature
    ///
    /// # Returns
    /// temporary orphan signature
    fn send_convert_sig(&self, vk: &[VK], sigma: Signature) -> Signature {
        let Signature { z, y_g1, y_hat, t } = sigma;

        // update component t of signature to remove the old key
        if let VK::G1(vk0) = &vk[0] {
            let t_new = t + (vk0 * self.secret.expose_secret()).negation();
            Signature {
                z,
                y_g1,
                y_hat,
                t: t_new,
            }
        } else {
            panic!("Invalid verification key");
        }
    }
    /// Receive Converted Signature
    /// On input a temporary (orphan) sigma signature and returns a new signature for the new public key.
    ///
    /// # Arguments
    ///
    /// vk: Verification Key
    /// sk_r: Secret Key
    /// orphan: Signature {Z, Y, Y_hat, t}
    ///
    /// # Returns
    /// new signature for the new public key
    fn receive_cred(&self, vk: &[VK], mut orphan: Signature) -> Signature {
        if let VK::G1(vk0) = &vk[0] {
            orphan.t += vk0 * self.secret.expose_secret();
            orphan
        } else {
            panic!("Invalid verification key");
        }
    }

    /// Push AttributeEntry onto the end of Message Stack.
    /// Appends new randomized commitment and opening for the new entry.
    /// Updates the signature for a new commitment vector including 𝐶_L for message_l using update_key
    ///
    /// Referred to as `change_rel` or "Change Relations" in the paper.
    ///
    /// # Arguments
    /// - `message_l`: message set at index `index_l` that will be added in message vector
    /// - `index_l`: index of `update_key` to be used for the added element,
    ///             `[1..n]` (starts at 1)
    /// - `signature`: EqcSignature {sigma, update_key, commitment_vector, opening_vector}
    /// - `mu`: optional randomness, default to 1. Only applies when same randomness is used previosuly in changerep
    ///
    /// # Returns
    /// new signature including the message set at index l
    fn change_rel(
        &self,
        addl_attrs: &Entry,
        orig_sig: Credential,
        mu: &FieldElement,
    ) -> Result<Credential, UpdateError> {
        // Validate the input. There must be room between the length of the current commitment vector
        // and the length of the update key to append a new entry.
        // valid input if: index_l = orig_sig.commitment_vector.len() + 1 && orig_sig.commitment_vector.len() + 1 <= orig_sig.update_key.as_ref().unwrap().len()
        let index_l = orig_sig.commitment_vector.len() + 1;

        match &orig_sig.update_key {
            // can only change attributes if we have the messages and an update_key
            Some(usign) if index_l <= usign.len() => {
                let Signature { z, y_g1, y_hat, t } = orig_sig.sigma;
                let (commitment_l, opening_l) = encode(&self.public.public_parameters, addl_attrs)?;

                let rndmz_commitment_l = mu * &commitment_l;
                let rndmz_opening_l = mu * &opening_l;

                // add the commitment CL for index L into the signature,
                // the update commitment vector and opening for this new commitment
                // if let  &orig_sig.update_key is Some usign

                // check if usign has index matching index_l or not
                // if yes, then update the signature
                // if no, then add the new commitment and opening to the signature
                if index_l <= usign.len() {
                    let set_l = convert_entry_to_bn(addl_attrs)?;
                    let monypolcoefficient = UnivarPolynomial::new_with_roots(&set_l[..]);

                    let list = usign.get(index_l - 1).unwrap();
                    let sum_points_uk_i = list
                        .iter()
                        .zip(monypolcoefficient.coefficients().iter())
                        .fold(G1::identity(), |acc, (list_i, monypolcoefficient_i)| {
                            acc + list_i.scalar_mul_const_time(monypolcoefficient_i)
                        });

                    let gama_l = sum_points_uk_i.scalar_mul_const_time(&opening_l);

                    let z_tilde = z + &gama_l;

                    let sigma_tilde = Signature {
                        z: z_tilde,
                        y_g1,
                        y_hat,
                        t,
                    };

                    let mut commitment_vector_tilde = orig_sig.commitment_vector;
                    commitment_vector_tilde.push(rndmz_commitment_l);

                    let mut opening_vector_tilde = orig_sig.opening_vector;
                    opening_vector_tilde.push(rndmz_opening_l);

                    Ok(Credential {
                        sigma: sigma_tilde,
                        update_key: orig_sig.update_key,
                        commitment_vector: commitment_vector_tilde, // Commitment_vector_new
                        opening_vector: opening_vector_tilde,       // Opening_vector_new
                    })
                } else {
                    panic!("index_l is the out of scope");
                }
            }
            _ => Err(UpdateError::Error),
        }
    }
}

impl AsRef<Nym> for Nym {
    fn as_ref(&self) -> &Nym {
        self
    }
}

#[derive(Clone)]
pub struct Signature {
    z: G1,
    y_g1: G1,
    y_hat: G2,
    t: G1,
}

/// CredOffer (cred_R)
/// - `orphan`: [Signature], orphan signature of the user
/// - `sig`: Credential, credential of the user
/// - `vk`: Vec<VK>, verification key of the user
pub struct CredOffer {
    orphan: Signature,
    cred: Credential,
    vk: Vec<VK>,
}

/// Credentials Proof
///
/// # Arguments
/// - `sigma`: [`Signature`], signature of the user
/// - `commitment_vector`: `Vec<G1>`, commitment vector of the user
/// - `witness_pi`: [`G1`], witness of the user
/// - `nym_public`: [`NymPublic`], proof of the pseudonym
pub struct CredProof {
    sigma: Signature,
    commitment_vector: Vec<G1>,
    witness_pi: G1,
    nym_public: NymPublic, // proof_nym_p: NymProof,
}

/// DelegateeCred
/// - `nym`: Nym, pseudonym of the user
/// - `cred`: Credential, credential of the user
pub struct DelegatedCred {
    pub nym: RandomizedPubKey,
    pub cred: Credential,
    secret: Secret<FieldElement>,
    vk: Vec<VK>,
    nym_public: NymPublic,
}

impl DelegatedCred {
    /// Prove a Credential
    /// Generates a proof of a credential for a given pseudonym and selective disclosure attributes.
    /// - `all_attributes`: &[Entry], attributes of the user
    /// - `selected_attrs`: &[Entry], attributes to be disclosed
    pub fn prove(&self, all_attributes: &[Entry], selected_attrs: &[Entry]) -> CredProof {
        let mu = FieldElement::one();
        let psi = FieldElement::random();

        // run change rep to randomize credential and user pk (i.e., create a new nym)
        // vk: &[VK], pk_u: &G1, orig_sig: &EqcSignature, mu: &FieldElement, psi: &FieldElement, b: bool
        let updatable = false;
        let (nym_p, cred_p, chi) =
            spseq_uc::change_rep(&self.vk, &self.nym, &self.cred, &mu, &psi, updatable);

        // create a Pedersen zkp announcement
        let (pedersen_commit, pedersen_open) = self.nym_public.damgard.announce();

        // get a challenge
        let state = ChallengeState {
            name: "schnorr".to_owned(),
            g: Generator::G1(self.nym_public.damgard.pedersen.g.clone()),
            hash: Sha256::digest(pedersen_commit.to_bytes(false)).into(),
            statement: vec![Generator::G1(self.nym_public.damgard.pedersen.h.clone())],
        };
        let challenge = DamgardTransform::challenge(&state);

        // prover creates a respoonse (or proof)
        // update aux_r with chi and psi
        let secret_wit = Secret::new((self.secret.expose_secret() + chi) * psi);
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
        let (witness_vector, commit_vector) = selected_attrs.iter().enumerate().fold(
            (Vec::new(), Vec::new()),
            |(mut witness, mut commitment_vectors), (i, selected_attr)| {
                if let Ok(Some(opened)) = CrossSetCommitment::open_subset(
                    &self.nym_public.public_parameters,
                    &all_attributes[i],
                    &cred_p.opening_vector[i],
                    selected_attr,
                ) {
                    witness.push(opened); //can only have as many witnesses as there are openable selected attributes
                    commitment_vectors.push(cred_p.commitment_vector[i].clone());
                    // needs to be the same length as the witness vector
                }
                (witness, commitment_vectors)
            },
        );

        let witness_pi = CrossSetCommitment::aggregate_cross(&witness_vector, &commit_vector);

        // output the whole proof = (sigma_prime, rndmz_commitment_vector, nym_P, Witness_pi, proof_nym_p)
        CredProof {
            sigma: cred_p.sigma,
            commitment_vector: cred_p.commitment_vector,
            witness_pi,
            nym_public: NymPublic {
                proof: proof_nym_p,
                ..self.nym_public.clone()
            },
        }
    }
}

/// Verify proof of a credential
pub fn verify_proof(
    vk: &[VK],
    proof: &CredProof,
    selected_attrs: &[Entry],
) -> Result<bool, SerzDeserzError> {
    // filter set commitments regarding the selected attributes
    // TODO: Make this either set of indexes or keys, so make selecting more flexible
    // Get the selected attributes from the entire attributes vector (indexes or keys)
    let commitment_vectors = proof.commitment_vector[..selected_attrs.len()].to_vec();

    // check the proof is valid for each
    let check_verify_cross = CrossSetCommitment::verify_cross(
        &proof.nym_public.public_parameters,
        &commitment_vectors,
        selected_attrs,
        &proof.witness_pi,
    )?;

    let check_zkp_verify =
        DamgardTransform::verify(&proof.nym_public.proof, &proof.nym_public.damgard);

    // signature is based on the original commitment vector. Unless we adapt it when the restriction is applied?
    let verify_sig = verify(
        vk,
        &proof.nym_public.proof.public_key,
        &proof.commitment_vector,
        &proof.sigma,
    );

    // assert both check_verify_cross and check_zkp_verify are true && spseq_uc.verify
    Ok(check_verify_cross && check_zkp_verify && verify_sig)
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::attributes::{attribute, Attribute};
    use crate::utils::entry;

    struct TestMessages {
        message1_str: Vec<Attribute>,
        message2_str: Vec<Attribute>,
        message3_str: Vec<Attribute>,
    }

    // make a setup fn that generates message_strs
    fn setup_tests() -> TestMessages {
        let age = attribute("age = 30");
        let name = attribute("name = Alice ");
        let drivers = attribute("driver license = 12");
        let gender = attribute("gender = male");
        let company = attribute("company = ACME");
        let insurance = attribute("Insurance = 2");
        let car_type = attribute("Car type = BMW");

        let message1_str = vec![age, name];

        let message2_str = vec![gender, company, drivers];
        let message3_str = vec![insurance, car_type];

        TestMessages {
            message1_str,
            message2_str,
            message3_str,
        }
    }

    #[test]
    fn test_sign() -> Result<(), SerzDeserzError> {
        // create new Signer with max_cardinality = 5 and max_entries = 10
        let signer = Signer::new(MaxCardinality::new(5), MaxEntries::new(10));

        // create a user key
        let user = UserKey::new();

        // get some test entries
        let messages_vectors = setup_tests();

        // create a signature
        let cred = signer.sign(
            &user.pk_u,
            &[
                Entry(messages_vectors.message1_str),
                Entry(messages_vectors.message2_str),
            ],
            None,
        )?;

        assert!(verify(
            &signer.vk,
            &user.pk_u,
            &cred.commitment_vector,
            &cred.sigma
        ));
        Ok(())
    }

    // Generate a signature, run changrep function and verify it
    #[test]
    fn test_changerep() -> Result<(), SerzDeserzError> {
        // Signer with 5 and 10
        let signer = Signer::new(MaxCardinality::new(5), MaxEntries::new(10));

        // create a user key
        let user = UserKey::new();

        // get some test entries
        let messages_vectors = setup_tests();

        // create a signature
        let k_prime = Some(4);
        let signature_original = signer.sign(
            &user.pk_u,
            &[
                Entry(messages_vectors.message1_str),
                Entry(messages_vectors.message2_str),
            ],
            k_prime,
        )?;

        // run changerep function (without randomizing update_key) to
        // randomize the sign, pk_u and commitment vector
        let updatable = false;
        let mu = FieldElement::random();
        let psi = FieldElement::random();

        let (rndmz_pk_u, signature, _chi) = spseq_uc::change_rep(
            &signer.vk,
            &user.pk_u,
            &signature_original,
            &mu,
            &psi,
            updatable,
        );

        assert!(verify(
            &signer.vk,
            &rndmz_pk_u,
            &signature.commitment_vector,
            &signature.sigma
        ));

        Ok(())
    }

    /// Generate a signature, run changrep function using update_key, randomize update_key (uk) and verify it
    /// This test is similar to test_changerep, but it randomizes the update_key
    /// and verifies the signature using the randomized update_key
    #[test]
    fn test_changerep_update_key() -> Result<(), SerzDeserzError> {
        // Signer with 5 and 10
        let signer = Signer::new(MaxCardinality::new(5), MaxEntries::new(10));

        // create a user key
        let user = UserKey::new();

        // get some test entries
        let messages_vectors = setup_tests();

        // create a signature
        let k_prime = Some(4);
        let signature_original = signer.sign(
            &user.pk_u,
            &[
                Entry(messages_vectors.message1_str),
                Entry(messages_vectors.message2_str),
            ],
            k_prime,
        )?;

        // run changerep function (with randomizing update_key) to
        // randomize the sign, pk_u and commitment vector
        let updatable = true;
        let mu = FieldElement::random();
        let psi = FieldElement::random();

        let (rndmz_pk_u, signature, _chi) = spseq_uc::change_rep(
            &signer.vk,
            &user.pk_u,
            &signature_original,
            &mu,
            &psi,
            updatable,
        );

        assert!(verify(
            &signer.vk,
            &rndmz_pk_u,
            &signature.commitment_vector,
            &signature.sigma
        ));

        Ok(())
    }

    /// Generate a signature, run changrel function one the signature, add one additional commitment using update_key (uk) and verify it
    /// This test is similar to test_changerep_uk, but it adds one additional commitment to the signature
    #[test]
    fn test_changerel_from_sign() -> Result<(), UpdateError> {
        // Generate a signature, run changrel function one the signature, add one additional commitment using update_key (uk) and verify it

        // Signer with 5 and 10
        let signer = Signer::new(MaxCardinality::new(5), MaxEntries::new(10));

        // create a user key
        let user = UserKey::new();

        // create a nym for this user and Signer
        let nym = user.nym(signer.public_parameters.clone());

        // get some test entries
        let messages_vectors = setup_tests();

        // create a signature
        let k_prime = Some(3);
        let messages_vector = &vec![
            Entry(messages_vectors.message1_str),
            Entry(messages_vectors.message2_str),
        ];
        let signature_original =
            signer.sign(&nym.public.proof.public_key, messages_vector, k_prime)?;

        // assrt that signature has update_key of length k_prime
        // how to convert a usize to integer:
        // convert an integer to usize using as_usize() method
        assert_eq!(
            signature_original
                .update_key
                .as_ref()
                .expect("There to be an update key")
                .len(),
            k_prime.expect("a number")
        );

        // signature_original.update_key should be zero from index 0 to messages_vector.len()
        // entries from messages_vector.len() +1 to k_prime - 1 should have non-zero values
        for k in 0..messages_vector.len() {
            assert_eq!(
                signature_original
                    .update_key
                    .as_ref()
                    .expect("There to be an update key")[k],
                Vec::new()
            );
        }

        for k in messages_vector.len()..k_prime.expect("a number") {
            assert_ne!(
                signature_original
                    .update_key
                    .as_ref()
                    .expect("There to be an update key")[k],
                Vec::new()
            );
        }

        // run changerel function (with update_key) to add commitment C3 (for message3_str) to the sign where index L = 3
        let message_l = Entry(messages_vectors.message3_str);
        // µ ∈ Zp means that µ is a random element in Zp. Zp is the set of integers modulo p.
        let mu = FieldElement::one();

        let signature_changed = nym.change_rel(&message_l, signature_original, &mu)?;

        // assert!(sign_scheme.verify(&vk, &pk_u, &cred_chged.commitment_vector, &cred_chged.sigma));
        assert!(verify(
            &signer.vk,
            &nym.public.proof.public_key,
            &signature_changed.commitment_vector,
            &signature_changed.sigma
        ));

        Ok(())
    }

    /// run changrel on the signature that is coming from changerep (that is already randomized) and verify it
    #[test]
    fn test_changerel_from_rep() -> Result<(), UpdateError> {
        // Signer with 5 and 10
        let signer = Signer::new(MaxCardinality::new(5), MaxEntries::new(10));

        // create a user key
        let user = UserKey::new();

        // create a nym for this user and Signer
        let nym = user.nym(signer.public_parameters.clone());

        // get some test entries
        let messages_vectors = setup_tests();

        // create a signature
        let k_prime = Some(4);
        let messages_vector = &vec![
            Entry(messages_vectors.message1_str),
            Entry(messages_vectors.message2_str),
        ];
        let signature_original =
            signer.sign(&nym.public.proof.public_key, messages_vector, k_prime)?;

        // run changerep function (with randomizing update_key) to
        // randomize the sign, pk_u and commitment vector
        let updatable = true;
        let mu = FieldElement::random();
        let psi = FieldElement::random();

        let (rndmz_pk_u, signature_prime, _chi) = spseq_uc::change_rep(
            &signer.vk,
            &nym.public.proof.public_key,
            &signature_original,
            &mu,
            &psi,
            updatable,
        );

        // verify the signature_prime
        assert!(verify(
            &signer.vk,
            &rndmz_pk_u,
            &signature_prime.commitment_vector,
            &signature_prime.sigma
        ));

        // change_rel
        let message_l = Entry(messages_vectors.message3_str);
        let cred_tilde = nym.change_rel(&message_l, signature_prime, &mu)?;

        // verify the signature
        assert!(verify(
            &signer.vk,
            &rndmz_pk_u,
            &cred_tilde.commitment_vector,
            &cred_tilde.sigma
        ));

        Ok(())
    }

    /// run convert protocol (send_convert_sig, receive_convert_sig) to switch a pk_u to new pk_u and verify it
    #[test]
    fn test_convert() -> Result<(), SerzDeserzError> {
        // 1. sign_keygen
        let signer = Signer::new(MaxCardinality::new(5), MaxEntries::new(10));

        // 2. user_keygen and nym
        let user = UserKey::new();
        let nym = user.nym(signer.public_parameters.clone());

        // 3. sign
        let messages_vectors = setup_tests();
        let k_prime = Some(4);
        let messages_vector = &vec![
            Entry(messages_vectors.message1_str),
            Entry(messages_vectors.message2_str),
        ];

        let signature_original = signer
            .sign(&nym.public.proof.public_key, messages_vector, k_prime)
            .expect("valid tests");

        // 4. create second user_keygen pk_u_new, sk_new
        let user_new = UserKey::new();
        let nym_new = user_new.nym(signer.public_parameters.clone());

        // 5. send_convert_sig to create sig orphan
        let orphan = nym.send_convert_sig(&signer.vk, signature_original.sigma);

        // 6. receive_convert_sig takes sig orphan to create sk_new and sig orphan
        let sigma_new = nym_new.receive_cred(&signer.vk, orphan);

        // 7. verify the signature using sigma_new
        assert!(verify(
            &signer.vk,
            &nym_new.public.proof.public_key,
            &signature_original.commitment_vector,
            &sigma_new
        ));

        Ok(())
    }

    #[test]
    fn test_issue_root_cred() -> Result<(), SerzDeserzError> {
        // 1. sign_keygen
        let signer = Signer::new(MaxCardinality::new(5), MaxEntries::new(10));

        // 2. user_keygen and nym
        let user = UserKey::new();
        let nym = user.nym(signer.public_parameters.clone());

        // 3. sign
        let messages_vectors = setup_tests();
        let k_prime = Some(4);
        let messages_vector = &vec![
            Entry(messages_vectors.message1_str),
            Entry(messages_vectors.message2_str),
        ];

        // Use `issue_cred` to issue a Credential to a Use's Nym
        let cred = signer.issue_cred(messages_vector, k_prime, &nym.public)?;

        // check the correctness of root credential
        // assert (spseq_uc.verify(pp_sign, vk_ca, nym_u, commitment_vector, sigma))
        assert!(verify(
            &signer.vk,
            &nym.public.proof.public_key,
            &cred.commitment_vector,
            &cred.sigma
        ));
        Ok(())
    }

    #[test]
    fn test_delegate_only() -> Result<(), SerzDeserzError> {
        // 1. offer
        // 2. accept
        // 3. prove
        // 4. verify proof

        let signer = Signer::new(MaxCardinality::new(5), MaxEntries::new(10));
        let user = UserKey::new();
        let nym = user.nym(signer.public_parameters.clone());

        let messages_vectors = setup_tests();
        let k_prime = Some(4);
        let messages_vector = &vec![
            Entry(messages_vectors.message1_str),
            Entry(messages_vectors.message2_str),
        ];

        let cred = signer.issue_cred(messages_vector, k_prime, &nym.public)?;

        // User to whose Nym we will offer the credential
        let user_r = UserKey::new();
        let nym_r = user_r.nym(signer.public_parameters.clone());

        let addl_attrs = None;

        // Create the Offer
        let offer = nym.offer(&cred, &signer.vk, &addl_attrs, &nym_r.public);

        // verify change_rel
        assert!(verify(
            &signer.vk,
            &nym.public.proof.public_key,
            &cred.commitment_vector,
            &cred.sigma
        ));

        // nym_r accepts
        let cred_p = nym_r.accept(&offer);

        // verify the signature
        assert!(verify(
            &signer.vk,
            &cred_p.nym, // RandomizedPubKey, NOT nym_r.public.proof.public_key,
            &cred_p.cred.commitment_vector,
            &cred_p.cred.sigma
        ));

        // prepare a proof
        let proof = cred_p.prove(messages_vector, messages_vector);

        // verify_proof
        assert!(verify_proof(&signer.vk, &proof, messages_vector)?);

        Ok(())
    }

    #[test]
    fn test_prove_subset_creds() -> Result<(), SerzDeserzError> {
        let age = attribute("age = 30");
        let name = attribute("name = Alice");
        let drivers = attribute("driver license = 12");
        let gender = attribute("gender = male");
        let company = attribute("company = ACME");
        let drivers_type_b = attribute("driver license type = B");
        let insurance = attribute("Insurance = 2");
        let car_type = attribute("Car type = BMW");

        let message1_str = vec![age.clone(), name.clone(), drivers];
        let message2_str = vec![gender.clone(), company.clone(), drivers_type_b];
        let message3_str = vec![insurance, car_type];

        // Test proving a credential to verifiers
        let all_attributes = vec![
            entry(&message1_str),
            entry(&message2_str),
            entry(&message3_str),
        ];

        let signer = Signer::new(MaxCardinality::new(5), MaxEntries::new(10));
        let user = UserKey::new();
        let nym_p = user.nym(signer.public_parameters.clone());

        let k_prime = Some(4);
        let cred = signer.issue_cred(&all_attributes, k_prime, &nym_p.public)?;

        // subset of each message set
        // iteratre through message1_str and return vector if element is either `age` or `name` Attribute
        let search_for = [age, name];
        let sub_list1_str = message1_str
            .iter()
            .filter(|&x| search_for.contains(x))
            .cloned()
            .collect::<Vec<Attribute>>();
        let sub_list2_str = vec![gender, company];

        // TODO: redesign the API to choose selected attrs as indexes of all attributes
        let selected_attrs = vec![Entry(sub_list1_str), Entry(sub_list2_str)];

        // prepare a proof
        let self_delegated_cred: DelegatedCred = DelegatedCred {
            nym: nym_p.public.proof.public_key.clone(),
            cred,
            secret: nym_p.secret,
            vk: signer.vk.clone(),
            nym_public: nym_p.public,
        };
        let proof = self_delegated_cred.prove(&all_attributes, &selected_attrs);

        // verify_proof
        assert!(verify_proof(&signer.vk, &proof, &selected_attrs)?);

        Ok(())
    }

    #[test]
    fn test_delegate_subset() -> Result<(), SerzDeserzError> {
        //start timer
        let start = std::time::Instant::now();

        // Delegate a subset of attributes
        let age = attribute("age = 30");
        let name = attribute("name = Alice");
        let drivers = attribute("driver license = 12");
        let gender = attribute("gender = male");
        let company = attribute("company = ACME");
        let drivers_type_b = attribute("driver license type = B");
        let insurance = attribute("Insurance = 2");
        let car_type = attribute("Car type = BMW");

        eprintln!("Age CID: {:?}", age.to_string());

        let message1_str = vec![age.clone(), name.clone(), drivers];
        let message2_str = vec![gender, company, drivers_type_b];
        let message3_str = vec![insurance.clone(), car_type];

        // Test proving a credential to verifiers
        let all_attributes = vec![
            entry(&message1_str),
            entry(&message2_str),
            entry(&message3_str),
        ];

        let l_message = MaxEntries::new(10);
        let signer = Signer::new(MaxCardinality::new(8), l_message);
        let alice = UserKey::new();
        let alice_nym = alice.nym(signer.public_parameters.clone());

        let position = 5; // index of the update key to be used for the added element
        let index_l = all_attributes.len() + position;
        let k_prime = Some(std::cmp::min(index_l, l_message.into())); // k_prime must be: MIN(messages_vector.len()) < k_prime < MAX(l_message)

        let cred = signer.issue_cred(&all_attributes, k_prime, &alice_nym.public)?;

        let robert = UserKey::new();
        let bobby_nym = robert.nym(signer.public_parameters.clone());

        let opening_vector_restricted = cred.opening_vector;
        // opening_vector_restricted[0] = FieldElement::zero(); // means the selected attributes cannot include the first commit in the vector

        let cred_restricted = Credential {
            sigma: cred.sigma,
            commitment_vector: cred.commitment_vector,
            // restrict opening to read only
            opening_vector: opening_vector_restricted,
            update_key: cred.update_key,
        };

        // offer to bobby_nym
        let alice_del_to_bobby =
            alice_nym.offer(&cred_restricted, &signer.vk, &None, &bobby_nym.public);

        // bobby_nym accepts
        let bobby_cred = bobby_nym.accept(&alice_del_to_bobby);

        // verify signature
        assert!(verify(
            &signer.vk,
            &bobby_cred.nym,
            &bobby_cred.cred.commitment_vector,
            &bobby_cred.cred.sigma
        ));

        // subset of each message set
        let sub_list1_str = vec![age, name];
        let sub_list2_str = vec![];
        let sub_list3_str = vec![insurance];

        let selected_attrs = vec![
            Entry(sub_list1_str),
            Entry(sub_list2_str),
            Entry(sub_list3_str),
        ];

        // prepare a proof
        let proof = bobby_cred.prove(&all_attributes, &selected_attrs);

        // verify_proof
        assert!(verify_proof(&signer.vk, &proof, &selected_attrs)?);

        eprintln!("Point : {:?}", start.elapsed());

        Ok(())
    }
}
