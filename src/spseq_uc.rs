use crate::set_commits::convert_mess_to_bn;
use crate::set_commits::Commitment;
use crate::set_commits::CrossSetCommitment;
use crate::set_commits::InputType;
use crate::set_commits::ParamSetCommitment;
use crate::utils::polyfromroots;
use amcl_wrapper::extension_field_gt::GT;
use amcl_wrapper::field_elem::FieldElement;
use amcl_wrapper::group_elem::GroupElement;
use amcl_wrapper::group_elem_g1::G1;
use amcl_wrapper::group_elem_g2::G2;
use std::collections::HashMap;
use std::ops::Mul;
pub struct Sigma {
    Z: G1,
    Y: G1,
    Y_hat: G2,
    T: G1,
}

pub enum VK {
    G1(G1),
    G2(G2),
}

pub type UpdateKey = Option<Vec<Vec<G1>>>;

/// This is implementation of delegatable anonymous credential using SPSQE-UC signatures and set commitment.
pub struct EQC_Sign {
    // public_parameters: ParamSetCommitment,
    // alpha_trapdoor: FieldElement,
    pub csc_scheme: CrossSetCommitment,
}

pub struct EQC_Signature {
    pub sigma: Sigma,
    pub update_key: UpdateKey,
    pub commitment_vector: Vec<G1>,
    pub opening_vector: Vec<FieldElement>,
}

impl EQC_Sign {
    /// New constructor. Initializes the EQC_Sign
    ///
    /// # Arguments
    /// t: max cardinality of the set. Cardinality of the set is in [1, t]. t is a public parameter.
    ///
    /// # Returns
    /// EQC_Sign
    pub fn new(t: usize) -> EQC_Sign {
        let csc_scheme = CrossSetCommitment::new(t);
        EQC_Sign { csc_scheme }
    }

    /// Setup. Sets up the signature scheme by creating public parameters and a secret key
    ///
    /// # Arguments
    /// &self
    ///
    /// # Returns
    /// public parameters and secret key tuple
    pub fn setup(&self) {
        todo!()
        // let (pp, sk) = csc::setup();
        // (pp, sk)
    }

    /// Generates signing key pair given the public parameters and length of the message
    /// # Arguments
    pub fn sign_keygen(&self, l_message: usize) -> (Vec<FieldElement>, Vec<VK>) {
        // compute secret keys for each item in l_message
        let mut sk = Vec::new();
        let mut vk: Vec<VK> = Vec::new();
        // sk has to be at least 2 longer than l_message, to compute `list_z` in `sign()` function which adds +2
        for i in 0..l_message + 2 {
            let sk_i = FieldElement::random();
            // compute public keys
            let vk_i = sk_i.clone() * &self.csc_scheme.param_sc.g_2;
            sk.push(sk_i);
            vk.push(VK::G2(vk_i));
        }
        // compute X_0 keys that is used for delegation
        let X_0 = sk[0].clone() * &self.csc_scheme.param_sc.g_1;
        vk.insert(0, VK::G1(X_0));
        (sk, vk) // vk is now of length l_message + 1 (or sk + 1)
    }

    /// Generates user key pair given the public parameters
    /// # Arguments
    fn user_keygen(&self) -> (FieldElement, G1) {
        let sk_u = FieldElement::random();
        let pk_u = sk_u.clone() * &self.csc_scheme.param_sc.g_1;
        (sk_u, pk_u)
    }

    /// Encodes a message set into a set commitment with opening information
    fn encode(&self, mess_set: &InputType) -> (G1, FieldElement) {
        CrossSetCommitment::commit_set(&self.csc_scheme.param_sc, mess_set)
    }

    /// Generates a signature for the commitment and related opening information along with update key.
    /// # Arguments
    /// pk_u: user public key
    /// sk: signing key
    /// messages_vector: vector of messages
    /// k_prime: index defining number of delegatable attributes in update key
    ///
    /// # Returns
    /// signature, opening information, update key
    fn sign(
        &self,
        pk_u: &G1,
        sk: &[FieldElement],
        messages_vector: &Vec<InputType>,
        k_prime: Option<usize>,
    ) -> EQC_Signature {
        // encode all messagse sets of the messages vector as set commitments
        let mut commitment_vector = Vec::new();
        let mut opening_vector = Vec::new();
        for mess in messages_vector {
            let (commitment, opening) = self.encode(mess);
            commitment_vector.push(commitment);
            opening_vector.push(opening);
        }

        // pick randomness y
        let y = FieldElement::random();

        // compute sign -> sigma = (Z, Y, hat Ym T)
        let mut list_z = Vec::new();
        for i in 0..commitment_vector.len() {
            let z_i = sk[i + 2].clone() * commitment_vector[i].clone();
            list_z.push(z_i);
        }

        // temp_point = sum of all ec points in list_Z
        let mut temp_point = G1::identity();
        for Z_i in list_z {
            temp_point += Z_i;
        }

        // Z is y mod_inverse(order) times temp_point
        let Z = y.inverse() * temp_point;

        // Y = y* g_1
        let Y = y.clone() * &self.csc_scheme.param_sc.g_1;

        // Y_hat = y * g_2
        let Y_hat = y.clone() * &self.csc_scheme.param_sc.g_2;

        // T = sk[1] * Y + sk[0] * pk_u
        let T = sk[1].clone() * Y.clone() + sk[0].clone() * pk_u;

        let sigma = Sigma { Z, Y, Y_hat, T };

        // check if the update key is requested
        // then compute update key using k_prime,
        // otherwise compute signature without it
        let mut update_key = None;
        if let Some(k_prime) = k_prime {
            let mut k_prime = k_prime;

            if k_prime > messages_vector.len() {
                // ensure k_prime is within range between k < k' < l, the max length of messages_vector
                // k_prime = k_prime.clamp(messages_vector.len(), sk.len());

                // usign = {}
                // for item in range(len(messages_vector) + 1, k_prime + 1): # In Python, this syntax means "from len(messages_vector) + 1 to k_prime + 1". In rust, the equiv would be "len(messages_vector) + 1..k_prime + 1"
                //     UK = [(y.mod_inverse(order) * sk[item + 1]) * pp_commit_G1[i] for i in range(max_cardinality)]
                //     usign[item] = UK
                //     update_key = usign

                let mut usign = Vec::new();
                usign.resize(k_prime, Vec::new()); // update_key is k < k' < l, same length as l_message.length, which is same as sk

                // only valid keys are between commitment length (k) an length (l), k_prime.length = k < k' < l
                for k in messages_vector.len() + 1..k_prime + 1 {
                    let mut uk = Vec::new();
                    for i in 0..self.csc_scheme.param_sc.max_cardinality {
                        let uk_i = y.inverse()
                            * sk[k + 1].clone()
                            * &self.csc_scheme.param_sc.pp_commit_G1[i];
                        uk.push(uk_i);
                    }
                    usign[k - 1] = uk.clone(); // first element is index 0 (message m is index m-1)
                }
                update_key = Some(usign);
                return EQC_Signature {
                    sigma,
                    update_key,
                    commitment_vector,
                    opening_vector,
                };
            } else {
                panic!("Not a good index, k_prime index should be greater than message length");
            }
        }

        EQC_Signature {
            sigma,
            update_key,
            commitment_vector,
            opening_vector,
        }
    }

    /// Verifies a signature for a given message set
    pub fn verify(
        &self,
        vk: &Vec<VK>,
        pk_u: &G1,
        commitment_vector: &Vec<G1>,
        sigma: &Sigma,
    ) -> bool {
        let g_1 = &self.csc_scheme.param_sc.g_1;
        let g_2 = &self.csc_scheme.param_sc.g_2;
        let Sigma { Z, Y, Y_hat, T } = sigma;

        let right_side = GT::ate_pairing(&Z, &Y_hat);

        // pairing_op = [group.pair(commitment_vector[j], vk[j + 3]) for j in range(len(commitment_vector))]
        let mut pairing_op = Vec::new();
        for j in 0..commitment_vector.len() {
            // the only VK that is not G2 is the first elem we inserted at 0 back in sign_keygen()
            if let VK::G2(vkj3) = &vk[j + 3] {
                let pair = GT::ate_pairing(&commitment_vector[j], &vkj3);
                pairing_op.push(pair);
            } else {
                panic!("Invalid verification key");
            }
        }

        // left_side = product_GT(pairing_op)
        let mut left_side = GT::one();
        for pair in pairing_op {
            left_side = GT::mul(left_side, &pair);
        }

        if let VK::G2(vk2) = &vk[2] {
            if let VK::G2(vk1) = &vk[1] {
                GT::ate_pairing(Y, g_2) == GT::ate_pairing(g_1, Y_hat)
                    && GT::ate_pairing(T, g_2)
                        == GT::ate_pairing(Y, vk2) * GT::ate_pairing(pk_u, vk1)
                    && right_side == left_side
            } else {
                panic!("Invalid verification key");
            }
        } else {
            panic!("Invalid verification key");
        }
    }

    /// Change representation of the signature message pair to a new commitment vector and user public key.
    /// This is used to update the signature message pair to a new user public key.
    /// The new commitment vector is computed using the old commitment vector and the new user public key.
    /// The new user public key is computed using the old user public key and the update key.
    /// The update key is computed during the signing process.
    ///
    /// # Arguments
    /// vk: the verification key
    /// pk_u: the user public key
    /// commitment_vector: the commitment vector
    /// opening_vector: opening information vector related to commitment vector
    /// sigma: the signature
    /// mu: randomness is used to randomize commitment vector and signature accordingly
    /// psi: randomness is used to randomize commitment vector and signature accordingly
    /// b: a flag to determine if it needs to randomize update_key as well or not
    /// update_key: it can be none, in which case there is no need for randomization
    ///
    /// # Returns
    /// returns an updated signature σ for a new commitment vector and corresponding openings
    pub fn change_rep(
        &self,
        vk: &Vec<VK>,
        pk_u: &G1,
        orig_sig: &EQC_Signature,
        mu: &FieldElement,
        psi: &FieldElement,
        b: bool,
    ) -> (G1, EQC_Signature) {
        // pick randomness, chi
        let chi = FieldElement::random();

        // randomize Commitment and opening vectors and user public key with randomness mu, chi
        let mut rndmz_commit_vector = Vec::new();
        for i in 0..orig_sig.commitment_vector.len() {
            let rndmz_commit_vector_i = mu * &orig_sig.commitment_vector[i];
            rndmz_commit_vector.push(rndmz_commit_vector_i);
        }

        let mut rndmz_opening_vector = Vec::new();
        for i in 0..orig_sig.opening_vector.len() {
            let rndmz_opening_vector_i = mu * &orig_sig.opening_vector[i];
            rndmz_opening_vector.push(rndmz_opening_vector_i);
        }

        // Randomize public key with two given randomness psi and chi.
        // rndmz_pk_u = psi * (pk_u + chi * g_1)
        let rndmz_pk_u = psi * &(pk_u + &chi * &self.csc_scheme.param_sc.g_1);

        // adapt the signiture for the randomized coomitment vector and PK_u_prime
        let Sigma { Z, Y, Y_hat, T } = &orig_sig.sigma;

        if let VK::G1(vk0) = &vk[0] {
            let sigma_prime = Sigma {
                Z: mu * &psi.inverse() * Z,
                Y: psi * Y,
                Y_hat: psi * Y_hat,
                T: psi * &(T + &chi * vk0),
            };

            // randomize update key with randomness mu
            let mut rndmz_update_key = None;
            if b {
                if let Some(update_key) = &orig_sig.update_key {
                    // Python code:
                    // usign = update_key
                    // usign_prime = {}
                    // for key in usign:
                    //     update_keylist = usign.get(key)
                    //     mainop = [(mu * psi.mod_inverse(order)) * update_keylist[i] for i in range(max_cardinality)]
                    //     usign_prime[key] = mainop
                    // rndmz_update_key = usign_prime
                    let usign = update_key;
                    let mut usign_prime = Vec::new();
                    usign_prime.resize(usign.len(), Vec::new());

                    for k in orig_sig.commitment_vector.len() + 1..usign.len() {
                        let mut mainop = Vec::new();
                        let update_keylist = usign.get(k - 1).expect("Valid");
                        for i in 0..self.csc_scheme.param_sc.max_cardinality {
                            let mainop_i = mu * &psi.inverse() * &update_keylist[i];
                            mainop.push(mainop_i);
                        }
                        usign_prime[k - 1] = mainop;
                    }
                    rndmz_update_key = Some(usign_prime);
                }
            }

            (
                rndmz_pk_u,
                EQC_Signature {
                    sigma: sigma_prime,
                    update_key: rndmz_update_key,
                    commitment_vector: rndmz_commit_vector,
                    opening_vector: rndmz_opening_vector,
                },
            )
        } else {
            panic!("Invalid verification key");
        }
    }

    /// Change Relations over the attributes
    /// Update the signature for a new commitment vector including 𝐶_L for message_l using update_key
    ///
    /// # Arguments
    /// message_l: message set at index l that will be added in message vector
    /// index_l: index l denotes the next position of message vector that needs to be fixed
    /// signature: EQC_Signature {sigma, update_key, commitment_vector, opening_vector}
    /// mu: optional randomness, default to 1. Only applies when same randomness is used previosuly in changerep
    ///
    /// # Returns
    /// new signature including the message set at index l
    pub fn change_rel(
        &self,
        message_l: &InputType,
        index_l: usize,
        orig_sig: &EQC_Signature,
        mu: &FieldElement,
    ) -> (EQC_Signature, FieldElement) {
        let Sigma { Z, Y, Y_hat, T } = &orig_sig.sigma;
        let (commitment_l, opening_l) = self.encode(message_l);

        let rndmz_commitment_l = mu * &commitment_l;
        let rndmz_opening_l = mu * &opening_l;

        // add the commitment CL for index L into the signature,
        // the update commitment vector and opening for this new commitment
        // if let  &orig_sig.update_key is Some usign
        if let Some(usign) = &orig_sig.update_key {
            // check if usign has index matching index_l or not
            // if yes, then update the signature
            // if no, then add the new commitment and opening to the signature
            if index_l <= usign.len() {
                let set_l = convert_mess_to_bn(message_l);
                let monypolcoefficient = polyfromroots(set_l);
                let list = usign.get(index_l - 1).unwrap();

                // points_uk_i = [(list[i]).mul(monypolcoefficient[i]) for i in range(len(monypolcoefficient))]
                let mut points_uk_i = Vec::new();
                for i in 0..monypolcoefficient.coefficients().len() {
                    let points_uk_i_i = list
                        .get(i)
                        .expect("Valid G1")
                        .mul(monypolcoefficient.coefficients()[i].clone());
                    points_uk_i.push(points_uk_i_i);
                }

                // sum all the points_uk_i
                let mut sum_points_uk_i = G1::identity();
                for item in points_uk_i {
                    sum_points_uk_i += item.clone();
                }

                let gama_l = sum_points_uk_i.mul(opening_l.clone());
                let z_tilde = Z + &gama_l;

                let sigma_tilde = Sigma {
                    Z: z_tilde,
                    Y: Y.clone(),
                    Y_hat: Y_hat.clone(),
                    T: T.clone(),
                };
                let mut commitment_vector_tilde = orig_sig.commitment_vector.clone();
                commitment_vector_tilde.push(rndmz_commitment_l);

                let mut opening_vector_tilde = orig_sig.opening_vector.clone();
                opening_vector_tilde.push(rndmz_opening_l);

                (
                    EQC_Signature {
                        sigma: sigma_tilde,
                        update_key: orig_sig.update_key.clone(),
                        commitment_vector: commitment_vector_tilde,
                        opening_vector: opening_vector_tilde,
                    },
                    opening_l,
                )
            } else {
                panic!("index_l is the out of scope");
            }
        } else {
            // no update key, cannot update, panic
            panic!("No update key, cannot update");
        }
    }

    /// Convert Signature
    /// Creates a temporary (orphan) signature for use in the convert signature algorithm.
    ///
    /// # Arguments
    /// vk: Verification Key
    /// sk_u: Secret Key
    /// sigma: Sigma {Z, Y, Y_hat, T} signature
    ///
    /// # Returns
    /// temporary orphan signature
    pub fn send_convert_sig(&self, vk: &[VK], sk_u: &FieldElement, sigma: &Sigma) -> Sigma {
        let Sigma { Z, Y, Y_hat, T } = sigma;

        // update component T of signature to remove the old key
        if let VK::G1(vk0) = &vk[0] {
            let t_new = T + (vk0 * sk_u).negation();
            Sigma {
                Z: Z.clone(),
                Y: Y.clone(),
                Y_hat: Y_hat.clone(),
                T: t_new,
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
    /// sigma_orphan: Sigma {Z, Y, Y_hat, T} signature
    ///
    /// # Returns
    /// new signature for the new public key
    pub fn receive_convert_sig(
        &self,
        vk: &[VK],
        sk_r: &FieldElement,
        sigma_orphan: &Sigma,
    ) -> Sigma {
        let Sigma { Z, Y, Y_hat, T } = sigma_orphan;

        // update component T of signature to remove the old key
        if let VK::G1(vk0) = &vk[0] {
            let t_new = T + (vk0 * sk_r);
            Sigma {
                Z: Z.clone(),
                Y: Y.clone(),
                Y_hat: Y_hat.clone(),
                T: t_new,
            }
        } else {
            panic!("Invalid verification key");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    struct TestMessages {
        message1_str: Vec<String>,
        message2_str: Vec<String>,
        message3_str: Vec<String>,
        attributes: Attributes,
    }

    struct Attributes {
        age: String,
        name: String,
        drivers: String,
        gender: String,
        company: String,
        drivers_type_b: String,
        insurance: String,
        car_type: String,
    }

    // make a setup fn that generates message_strs
    fn setup_tests() -> TestMessages {
        let age = "age = 30";
        let name = "name = Alice ";
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

        let attributes = Attributes {
            age: age.to_owned(),
            name: name.to_owned(),
            drivers: drivers.to_owned(),
            gender: gender.to_owned(),
            company: company.to_owned(),
            drivers_type_b: drivers_type_b.to_owned(),
            insurance: insurance.to_owned(),
            car_type: car_type.to_owned(),
        };

        TestMessages {
            message1_str,
            message2_str,
            message3_str,
            attributes,
        }
    }

    #[test]
    fn test_sign() {
        // Generate a signature and verify it
        // create a signing keys for 10 messagses
        let max_cardinal = 5;
        let sign_scheme = EQC_Sign::new(max_cardinal);

        let l_message = 10;
        let (sk, vk) = sign_scheme.sign_keygen(l_message);

        // create a user key pair
        let (sk_u, pk_u) = sign_scheme.user_keygen();

        let messages_vectors = setup_tests();

        // create a signature sigma for user pk_u, without update_key
        let signature = sign_scheme.sign(
            &pk_u,
            &sk,
            &vec![
                InputType::VecString(messages_vectors.message1_str),
                InputType::VecString(messages_vectors.message2_str),
            ],
            None,
        );

        assert!(sign_scheme.verify(&vk, &pk_u, &signature.commitment_vector, &signature.sigma));
    }

    // Generate a signature, run changrep function and verify it
    #[test]
    fn test_changerep() {
        //create a signing keys for 10 messagses
        let max_cardinal = 5;
        let sign_scheme = EQC_Sign::new(max_cardinal);

        let l_message = 10;
        let (sk, vk) = sign_scheme.sign_keygen(l_message);

        // create a user key pair
        let (sk_u, pk_u) = sign_scheme.user_keygen();

        let messages_vectors = setup_tests();

        // create a signature for pk_u, (C1, C2) related to (message1_str, message2_str) with k = 2, and
        // also output update_key for k_prime = 4,
        // allow adding 2 more commitments for range k = 2 to k' = 4
        let k_prime = Some(4);
        let signature_original = sign_scheme.sign(
            &pk_u,
            &sk,
            &vec![
                InputType::VecString(messages_vectors.message1_str),
                InputType::VecString(messages_vectors.message2_str),
            ],
            k_prime,
        );

        // run changerep function (without randomizing update_key) to
        // randomize the sign, pk_u and commitment vector
        let b = false;
        let mu = FieldElement::random();
        let psi = FieldElement::random();

        let (rndmz_pk_u, signature) =
            sign_scheme.change_rep(&vk, &pk_u, &signature_original, &mu, &psi, b);

        assert!(sign_scheme.verify(
            &vk,
            &rndmz_pk_u,
            &signature.commitment_vector,
            &signature.sigma
        ));
    }

    /// Generate a signature, run changrep function using update_key, randomize update_key (uk) and verify it
    /// This test is similar to test_changerep, but it randomizes the update_key
    /// and verifies the signature using the randomized update_key
    #[test]
    fn test_changerep_update_key() {
        //create a signing keys for 10 messagses
        let max_cardinal = 5;
        let sign_scheme = EQC_Sign::new(max_cardinal);

        let l_message = 10;
        let (sk, vk) = sign_scheme.sign_keygen(l_message);

        // create a user key pair
        let (sk_u, pk_u) = sign_scheme.user_keygen();

        let messages_vectors = setup_tests();

        // create a signature for pk_u, (C1, C2) related to (message1_str, message2_str) with k = 2, and
        // also output update_key for k_prime = 4,
        // allow adding 2 more commitments for range k = 2 to k' = 4
        let k_prime = Some(4);
        let signature_original = sign_scheme.sign(
            &pk_u,
            &sk,
            &vec![
                InputType::VecString(messages_vectors.message1_str),
                InputType::VecString(messages_vectors.message2_str),
            ],
            k_prime,
        );

        // run changerep function (without randomizing update_key) to
        // randomize the sign, pk_u and commitment vector
        let randomize_update_key = true;
        let mu = FieldElement::random();
        let psi = FieldElement::random();

        let (rndmz_pk_u, signature) = sign_scheme.change_rep(
            &vk,
            &pk_u,
            &signature_original,
            &mu,
            &psi,
            randomize_update_key,
        );

        assert!(sign_scheme.verify(
            &vk,
            &rndmz_pk_u,
            &signature.commitment_vector,
            &signature.sigma
        ));
    }

    /// Generate a signature, run changrel function one the signature, add one additional commitment using update_key (uk) and verify it
    /// This test is similar to test_changerep_uk, but it adds one additional commitment to the signature
    #[test]
    fn test_changerel_from_sign() {
        // Generate a signature, run changrel function one the signature, add one additional commitment using update_key (uk) and verify it

        //create a signing keys for 10 messages
        let max_cardinal = 5;
        let sign_scheme = EQC_Sign::new(max_cardinal);

        let l_message = 3;
        let (sk, vk) = sign_scheme.sign_keygen(l_message);

        // create a user key pair
        let (sk_u, pk_u) = sign_scheme.user_keygen();

        let messages_vectors = setup_tests();

        // create a signature for pk_u on (C1, C2) related to (message1_str, message2_str)) and aslo output update_key for k_prime = 4, allow adding 2 more commitments like C3 and C4
        let k_prime = Some(3);
        let messages_vector = &vec![
            InputType::VecString(messages_vectors.message1_str),
            InputType::VecString(messages_vectors.message2_str),
        ];
        let signature_original = sign_scheme.sign(&pk_u, &sk, messages_vector, k_prime);

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
        let message_l = InputType::VecString(messages_vectors.message3_str);
        // µ ∈ Zp means that µ is a random element in Zp. Zp is the set of integers modulo p.
        let mu = FieldElement::one();

        let (signature_chged, _opening_l) =
            sign_scheme.change_rel(&message_l, 3, &signature_original, &mu);

        let res = sign_scheme.verify(
            &vk,
            &pk_u,
            &signature_chged.commitment_vector,
            &signature_chged.sigma,
        );

        assert!(sign_scheme.verify(
            &vk,
            &pk_u,
            &signature_chged.commitment_vector,
            &signature_chged.sigma
        ));
    }

    /// run changrel on the signature that is coming from changerep (that is already randomized) and verify it
    #[test]
    fn test_changerel_from_rep() {
        //create a signing keys for 10 messages
        let max_cardinal = 5;
        let sign_scheme = EQC_Sign::new(max_cardinal);

        let l_message = 10;
        let (sk, vk) = sign_scheme.sign_keygen(l_message);

        // create a user key pair
        let (sk_u, pk_u) = sign_scheme.user_keygen();

        let messages_vectors = setup_tests();

        // create a signature for pk_u on (C1, C2) related to (message1_str, message2_str)) and aslo output update_key for k_prime = 4, allow adding 2 more commitments like C3 and C4
        let k_prime = Some(4);
        let messages_vector = &vec![
            InputType::VecString(messages_vectors.message1_str),
            InputType::VecString(messages_vectors.message2_str),
        ];
        let signature_original = sign_scheme.sign(&pk_u, &sk, messages_vector, k_prime);

        // run changerep function (without randomizing update_key) to
        // randomize the sign, pk_u and commitment vector
        let b = true;
        let mu = FieldElement::random();
        let psi = FieldElement::random();

        let (rndmz_pk_u, signature_prime) =
            sign_scheme.change_rep(&vk, &pk_u, &signature_original, &mu, &psi, b);

        // verify the signature_prime
        assert!(sign_scheme.verify(
            &vk,
            &rndmz_pk_u,
            &signature_prime.commitment_vector,
            &signature_prime.sigma
        ));

        // change_rel
        let message_l = InputType::VecString(messages_vectors.message3_str);
        // µ ∈ Zp means that µ is a random element in Zp. Zp is the set of integers modulo p.
        let (signature_tilde, _opening_l) =
            sign_scheme.change_rel(&message_l, 3, &signature_prime, &mu);

        // verify the signature
        assert!(sign_scheme.verify(
            &vk,
            &rndmz_pk_u,
            &signature_tilde.commitment_vector,
            &signature_tilde.sigma
        ));
    }

    /// run convert protocol (send_convert_sig, receive_convert_sig) to switch a pk_u to new pk_u and verify it
    #[test]
    fn test_convert() {
        // 1. sign_keygen
        let max_cardinal = 5;
        let sign_scheme = EQC_Sign::new(max_cardinal);

        let l_message = 10;
        let (sk, vk) = sign_scheme.sign_keygen(l_message);

        // 2. user_keygen
        let (sk_u, pk_u) = sign_scheme.user_keygen();

        // 3. sign
        let messages_vectors = setup_tests();
        let k_prime = Some(4);
        let messages_vector = &vec![
            InputType::VecString(messages_vectors.message1_str),
            InputType::VecString(messages_vectors.message2_str),
        ];

        let signature_original = sign_scheme.sign(&pk_u, &sk, messages_vector, k_prime);

        // 4. create second user_keygen pk_u_new, sk_new
        let (sk_new, pk_u_new) = sign_scheme.user_keygen();

        // 5. send_convert_sig to create sigma_orphan
        let sigma_orphan = sign_scheme.send_convert_sig(&vk, &sk_u, &signature_original.sigma);

        // 6. receive_convert_sig takes sigma_orphan to create sk_new and sigma_orphan
        let sigma_new = sign_scheme.receive_convert_sig(&vk, &sk_new, &sigma_orphan);

        // 7. verify the signature using sigma_new
        assert!(sign_scheme.verify(
            &vk,
            &pk_u_new,
            &signature_original.commitment_vector,
            &sigma_new
        ));
    }
}
