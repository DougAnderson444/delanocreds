use std::fmt::{Display, Formatter};

use amcl_wrapper::field_elem::FieldElement;
use amcl_wrapper::group_elem::GroupElement;
use amcl_wrapper::group_elem_g2::G2;
use amcl_wrapper::types::BigNum;
use amcl_wrapper::{constants::CurveOrder, group_elem_g1::G1};
use anyhow::Result;
use sha2::{Digest, Sha256};

use crate::dac::NymProof;
use crate::utils::{self, Pedersen, PedersenCommit, PedersenOpen};

#[derive(Clone, Debug)]
pub enum Generator {
    G1(G1),
    G2(G2),
}

impl Display for Generator {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Generator::G1(g) => write!(f, "{}", g),
            Generator::G2(g) => write!(f, "{}", g),
        }
    }
}

pub struct ChallengeState {
    pub name: String,
    pub g: Generator,
    pub statement: Vec<Generator>,
    pub hash: [u8; 32],
}

pub type Challenge = FieldElement;
pub type Response = Vec<FieldElement>; // Vec<BigNum>;
/// Schnorr proof (non-interactive using Fiat Shamir heuristic) of the statement
/// ZK(x, m_1....m_n; h = g^x and h_1^m_1...h_n^m_n) and generilized version
pub struct ZkpSchnorrFiatShamir {}

impl ZkpSchnorrFiatShamir {
    fn new() -> Self {
        ZkpSchnorrFiatShamir {}
    }
    pub fn setup() -> G2 {
        G2::generator()
    }

    /// The code below is from the original implementation of the Schnorr proof (non-interactive using FS heuristic) of the statement ZK(x ; h = g^x)
    fn challenge(state: &ChallengeState) -> FieldElement {
        // transform the state into a byte array
        let mut state_bytes = Vec::new();
        state_bytes.extend_from_slice(state.name.as_bytes());
        state_bytes.extend_from_slice(state.g.to_string().as_bytes());

        for stmt in &state.statement {
            state_bytes.extend_from_slice(stmt.to_string().as_bytes());
        }

        state_bytes.extend_from_slice(&state.hash);

        FieldElement::from_msg_hash(&state_bytes)
    }

    /// Schnorr proof (non-interactive using FS heuristic)
    pub fn non_interact_prove(
        g_2: &G2,
        stms: &Vec<G2>,
        secret_wit: &Vec<FieldElement>,
    ) -> Result<(Response, Challenge)> {
        // match on the statement

        // FieldElement::random() for each statement item
        let w_list = (0..stms.len())
            .map(|_| FieldElement::random())
            .collect::<Vec<FieldElement>>();

        // wit_list = [w_list[i] * g for i in range(len(w_list))]
        let witness_list = w_list.iter().map(|li| li * g_2).collect::<Vec<G2>>();

        // sum all w_list items into announcement
        let announcement = witness_list.iter().fold(G2::identity(), |acc, x| acc + x);

        // SHAKE3 hash the &announcement.to_bytes(false)
        let hash: [u8; 32] = Sha256::digest(announcement.to_bytes(false)).into();
        // cast stms to Generator::G2
        let stms = stms
            .iter()
            .map(|x| Generator::G2(x.clone()))
            .collect::<Vec<Generator>>();

        let state = ChallengeState {
            name: "schnorr".to_string(),
            g: Generator::G2(g_2.clone()),
            statement: stms,
            hash,
        };

        // generate challenge. How do you take the modulo of the Group order using amcl_wrapper? I don't see a method for it. I'm using the modulo of the field order. Is that correct? I'm not sure how to do it with the group order. I'm using the modulo of the field order. Is that correct?
        // let mut c = BigNum::frombytes(&Self::challenge(&state).to_bytes());
        let mut c = Self::challenge(&state).to_bignum();
        c.rmod(&CurveOrder);

        // r = [(w_list[i] - c * secret_wit[i]) % o for i in range(len(secret_wit))], use rmod(&CurveOrder) instead of  `% o`
        let r = (0..secret_wit.len())
            .map(|i| {
                let a = w_list[i].clone();
                let b = FieldElement::try_from(c).unwrap() * secret_wit[i].clone();
                let mut r = BigNum::frombytes(&(a - b).to_bytes());
                r.rmod(&CurveOrder);
                r
            })
            .collect::<Vec<BigNum>>();

        let c: Challenge = FieldElement::from_hex(c.tostring()).unwrap();
        let r: Response = r
            .iter()
            .map(|x| FieldElement::from_hex(x.tostring()).unwrap())
            .collect::<Vec<FieldElement>>();

        Ok((r, c))
    }

    /// Verify the statement ZK(x ; h = g^x)
    pub fn non_interact_verify(g_2: &G2, stms: &[G2], proof_list: &(Response, Challenge)) -> bool {
        let (r, c) = proof_list;

        // W_list = [r[i] * g + c * stm[i] for i in range(len(r))]
        let w_list = (0..r.len())
            .map(|i| r[i].clone() * g_2 + c * stms[i].clone())
            .collect::<Vec<G2>>();
        // sum all w_list items into announcement
        let announcement = w_list.iter().fold(G2::identity(), |acc, x| acc + x);

        // cast stms to Generator::G2
        let stms = stms
            .iter()
            .map(|x| Generator::G2(x.clone()))
            .collect::<Vec<Generator>>();

        let state = ChallengeState {
            name: "schnorr".to_string(),
            g: Generator::G2(g_2.clone()),
            statement: stms,
            hash: Sha256::digest(announcement.to_bytes(false)).into(),
        };
        let mut hash = Self::challenge(&state).to_bignum();
        hash.rmod(&CurveOrder);

        FieldElement::from_hex(hash.tostring()).unwrap() == *c
    }
}

/// Schnorr (interactive) proof of the statement ZK(x ; h = g^x)
pub trait Schnorr {
    fn new() -> Self;

    // In rust, the implemented default traits are:
    fn setup() -> G2 {
        G2::generator()
    }
    fn challenge(state: &ChallengeState) -> Challenge {
        let mut elem_str = vec![state.statement.len().to_string()];
        elem_str.extend(state.statement.iter().map(|x| x.to_string()));

        // The length of each element in the list is added to the element
        let elem_len = elem_str.iter().map(|x| format!("{}||{}", x.len(), x));
        let state = elem_len.collect::<Vec<String>>().join("|");

        let hash = Sha256::digest(state.as_bytes());

        FieldElement::from_hex(format!("{:X}", hash)).unwrap()
    }

    fn response(
        challenge: &Challenge,
        announce_randomness: &FieldElement,
        stm: &G1,
        secret_wit: &FieldElement,
    ) -> FieldElement {
        assert!(secret_wit * G1::generator() == *stm);
        let mut res = BigNum::frombytes(&(announce_randomness + challenge * secret_wit).to_bytes());
        res.rmod(&CurveOrder);
        res.into()
    }
}

pub struct ZKPSchnorr {}

// use defaults
impl Schnorr for ZKPSchnorr {
    fn new() -> Self {
        Self {}
    }
}

impl ZKPSchnorr {
    /// Verify the statement ZK(x ; h = g^x)
    pub fn verify(
        &self,
        challenge: &Challenge,
        announce_element: &G1,
        stm: &G1,
        response: &FieldElement,
    ) -> bool {
        let left_side = response * G1::generator();
        let right_side = (announce_element + challenge * stm);
        left_side == right_side
    }
}

pub struct DamgardTransform {
    pub pedersen: Pedersen,
}

impl DamgardTransform {
    pub fn announce(&self) -> (PedersenCommit, PedersenOpen) {
        let w_random = FieldElement::random();
        let w_element = &w_random * &self.pedersen.g;
        let (pedersen_commit, mut pedersen_open) = self.pedersen.commit(w_random);
        pedersen_open.element(w_element);
        (pedersen_commit, pedersen_open)
    }
    pub fn verify(&self, proof_nym_u: &NymProof) -> bool {
        let left_side = proof_nym_u.response.clone() * &self.pedersen.g;
        let right_side = (proof_nym_u.pedersen_open.announce_element.as_ref().unwrap()
            + proof_nym_u.challenge.clone() * proof_nym_u.nym.clone());
        left_side == right_side
            && self
                .pedersen
                .decommit(&proof_nym_u.pedersen_open, &proof_nym_u.pedersen_commit)
    }
}

// implement a trait for Damgard_Transform that has the same functions as ZKP_Schnorr and then you would implement the functions for Damgard_Transform

impl Schnorr for DamgardTransform {
    fn new() -> Self {
        let pedersen = Pedersen::new();
        Self { pedersen }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_non_interact_prove() {
        // 0. ZkpSchnorrFiatShamir::new()
        // 1. Setup
        // 2. Prove
        // 3. Verify
        let g_2 = ZkpSchnorrFiatShamir::setup();
        let x = FieldElement::random();
        let h = x.clone() * g_2.clone();

        // create a vec of secrets for iter 0 to 5
        let secrets = (0..5)
            .map(|_| FieldElement::random())
            .collect::<Vec<FieldElement>>();

        // create stm for len of secrets, sec[i * g_2]
        let stm = secrets.iter().map(|s| s * g_2.clone()).collect::<Vec<G2>>();

        let proof_list /* (r, c) */ = ZkpSchnorrFiatShamir::non_interact_prove(&g_2, &stm, &secrets).unwrap();
        // let proof = (r, c);
        let result = ZkpSchnorrFiatShamir::non_interact_verify(&g_2, &stm, &proof_list);
        assert!(result);

        // create a proof for statement
        let proof_single =
            ZkpSchnorrFiatShamir::non_interact_prove(&g_2, &vec![h.clone()], &vec![x]).unwrap();
        let result_single =
            ZkpSchnorrFiatShamir::non_interact_verify(&g_2, &vec![h], &proof_single);
        assert!(result_single);
    }
}
