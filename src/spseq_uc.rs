use crate::set_commits::Commitment;
use crate::set_commits::CrossSetCommitment;
use crate::set_commits::InputType;
use crate::set_commits::ParamSetCommitment;
use amcl_wrapper::extension_field_gt::GT;
use amcl_wrapper::field_elem::FieldElement;
use amcl_wrapper::group_elem::GroupElement;
use amcl_wrapper::group_elem_g1::G1;
use amcl_wrapper::group_elem_g2::G2;
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

pub type UpdateKey = Option<Vec<G1>>;

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
        for i in 0..l_message {
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
    fn encode(&self, mess_set: Vec<String>) -> (G1, FieldElement) {
        CrossSetCommitment::commit_set(&self.csc_scheme.param_sc, &InputType::VecString(mess_set))
    }

    /// Generates a signature for the commitment and related opening information along with update key.
    /// # Arguments
    /// pk_u: user public key
    /// sk: signing key
    /// messages_vector: vector of messages
    /// k_prime: index defining number of delegatable attributes  in update key update_key
    ///
    /// # Returns
    /// signature, opening information, update key
    fn sign(
        &self,
        pk_u: &G1,
        sk: &Vec<FieldElement>,
        messages_vector: &Vec<Vec<String>>,
        k_prime: Option<usize>,
    ) -> EQC_Signature {
        // encode all messagse sets of the messages vector as set commitments
        let mut commitment_vector = Vec::new();
        let mut opening_vector = Vec::new();
        for mess in messages_vector {
            let (commitment, opening) = self.encode(mess.to_vec());
            commitment_vector.push(commitment);
            opening_vector.push(opening);
        }

        // pick randomness y
        let y = FieldElement::random();

        // compute sign -> sigma = (Z, Y, hat Ym T)
        let mut list_Z = Vec::new();
        for i in 0..commitment_vector.len() {
            let Z_i = sk[i + 2].clone() * commitment_vector[i].clone();
            list_Z.push(Z_i);
        }

        // temp_point = sum of all ec points in list_Z
        let mut temp_point = G1::identity();
        for Z_i in list_Z {
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
        if k_prime.is_some() {
            // compute update key
            let k_prime = k_prime.unwrap();
            let mut uk = Vec::new();
            for i in 0..k_prime {
                let uk_i = sk[i].clone() * &self.csc_scheme.param_sc.g_1;
                uk.push(uk_i);
            }
            update_key = Some(uk);
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
    /// a randomization of message-signature pair
    pub fn change_rep(
        &self,
        vk: &Vec<VK>,
        pk_u: &G1,
        orig_sig: &EQC_Signature,
        mu: &FieldElement,
        psi: &FieldElement,
        randomize_update_key: bool,
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
            if randomize_update_key {
                if let Some(update_key) = &orig_sig.update_key {
                    let mut rndmz_update_key_vec = Vec::new();
                    for key in update_key.iter() {
                        let rndmz_update_key_vec_i = mu * key;
                        rndmz_update_key_vec.push(rndmz_update_key_vec_i);
                    }
                    rndmz_update_key = Some(rndmz_update_key_vec);
                }
            }

            // return public key and Signature
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
            &vec![messages_vectors.message1_str, messages_vectors.message2_str],
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
            &vec![messages_vectors.message1_str, messages_vectors.message2_str],
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
}
