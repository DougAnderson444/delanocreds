use super::spseq_uc;
use crate::set_commits;
use crate::spseq_uc::EqcSign;
use crate::spseq_uc::VK;
use crate::utils::{InputType, PedersenOpen};
use crate::zkp::{ChallengeState, DamgardTransform, Generator, Schnorr};
/// This is implementation of delegatable anonymous credential using SPSQE-UC signatures and set commitment.
// See  the following for the details:
// - Practical Delegatable Anonymous Credentials From Equivalence Class Signatures, PETS 2023.
//    https://eprint.iacr.org/2022/680
use amcl_wrapper::extension_field_gt::GT;
use amcl_wrapper::field_elem::FieldElement;
use amcl_wrapper::group_elem::GroupElement;
use amcl_wrapper::group_elem_g1::G1;
use amcl_wrapper::group_elem_g2::G2;
use sha2::{Digest, Sha256};

struct DAC {
    l_message: usize,
    max_cardinal: usize,
    spseq_uc: EqcSign,
    zkp: DamgardTransform,
}

struct User {
    vk: Vec<VK>,
    sk: Vec<FieldElement>,
    pk_u: G1,
    sk_u: FieldElement,
    // zkp: DamgardTransform,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct Nym {
    nym: G1,
    secret_wit: FieldElement,
    proof_nym_u: NymProof,
}

/// (FieldElement, PedersenOpen, G1, G1, FieldElement)
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct NymProof {
    pub challenge: FieldElement,
    pub pedersen_open: PedersenOpen,
    pub pedersen_commit: G1,
    pub nym: G1,
    pub response: FieldElement,
}

// impl AsRef from Nym
impl Nym {
    pub fn as_ref(&self) -> &Self {
        self
    }
}

impl User {}

impl DAC {
    /// New constructor
    /// # Arguments
    /// t: max cardinality of the set. Cardinality of the set is in [1, t]. t is a public parameter.
    /// l_message: the max number of the messagses. The number of the messages is in [1, l_message]. l_message is a public parameter.
    ///
    /// # Returns
    /// DAC
    pub fn new(t: usize, l_message: usize) -> DAC {
        DAC {
            l_message,
            max_cardinal: t,
            spseq_uc: EqcSign::new(t),
            zkp: DamgardTransform::new(),
        }
    }

    pub fn user_keygen(&self) -> User {
        let sign_scheme = spseq_uc::EqcSign::new(self.max_cardinal);
        let (sk, vk) = sign_scheme.sign_keygen(self.l_message);
        let (usk, upk) = sign_scheme.user_keygen();

        User {
            vk,
            sk,
            pk_u: upk,
            sk_u: usk,
            // zkp: self.zkp,
        }
    }

    /// Generate a new pseudonym and auxiliary information.
    pub fn nym_gen(&self, user: User) -> Nym {
        // pick randomness
        let psi = FieldElement::random();
        let chi = FieldElement::random();
        let g_1 = G1::generator();

        // pk_u: &G1, chi: &FieldElement, psi: &FieldElement, g_1: &G1
        let nym = spseq_uc::rndmz_pk(&user.pk_u, &chi, &psi, &g_1);
        let secret_wit = psi * (user.sk_u + chi);

        // create a proof for nym
        let (pedersen_commit, pedersen_open) = self.zkp.announce();

        let state = ChallengeState {
            name: "schnorr".to_owned(),
            g: Generator::G1(self.zkp.pedersen.g.clone()),
            hash: Sha256::digest(pedersen_commit.to_bytes(false)).into(),
            statement: vec![Generator::G1(self.zkp.pedersen.h.clone())],
        };

        let challenge = DamgardTransform::challenge(&state);

        // (challenge: &Challenge, announce_randomness: &FieldElement, stm: &G2, secret_wit: &FieldElement)
        let response = DamgardTransform::response(
            &challenge,
            &pedersen_open.announce_randomness,
            &nym,
            &secret_wit,
        );

        let proof_nym_u = NymProof {
            challenge,
            pedersen_open,
            pedersen_commit,
            nym: nym.clone(),
            response,
        };

        Nym {
            nym,
            secret_wit,
            proof_nym_u,
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
        sk: &Vec<FieldElement>,
        nym: &Nym,
        k_prime: Option<usize>,
        proof_nym_u: NymProof,
    ) -> spseq_uc::EqcSignature {
        // check if proof of nym is correct
        if self.zkp.verify(&proof_nym_u) {
            // check if delegate keys is provided
            let cred = self.spseq_uc.sign(&nym.nym, sk, attr_vector, k_prime);
            assert!(self
                .spseq_uc
                .verify(vk, &nym.nym, &cred.commitment_vector, &cred.sigma)); //, "signature/credential is not correct";
            return cred;
        } else {
            panic!("proof of nym is not valid");
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::utils::InputType;

    use super::*;

    fn setup() {
        // let nizkp
    }

    #[test]
    fn test_root_cred() {
        // Test the creation of a root credential.
        let message1_str = vec!["age = 30", "name = Alice ", "driver license = 12"];
        let message2_str = vec![
            "genther = male",
            "componey = XX ",
            "driver license type = B",
        ];

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

        let dac = DAC::new(5, 10);

        // create user key pair
        let user = dac.user_keygen();
        let (sk_ca, vk_ca) = dac.spseq_uc.sign_keygen(dac.l_message);

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
            &nym.clone(),
            Some(3),
            nym.proof_nym_u,
        );

        // check the correctness of root credential
        // assert (spseq_uc.verify(pp_sign, vk_ca, nym_u, commitment_vector, sigma))
        assert!(dac
            .spseq_uc
            .verify(&vk_ca, &nym.nym, &cred.commitment_vector, &cred.sigma));
    }
}
