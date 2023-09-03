use crate::ec::curve::{CurveOrder, FieldElement, GroupElement, G1, G2};
use amcl_wrapper::types::BigNum;
use anyhow::Result;
use secrecy::{ExposeSecret, Secret};
use sha2::{Digest, Sha256};
use std::fmt::{Display, Formatter};

use crate::keypair::spseq_uc::RandomizedPubKey;
use crate::keypair::NymProof;
use crate::types::{Generator, GeneratorG1, GeneratorG2, Group};

impl Display for Generator {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Generator::G1(g) => write!(f, "{g}"),
            Generator::G2(g) => write!(f, "{g}"),
        }
    }
}

impl Display for Group {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Group::G1(g) => write!(f, "{g}"),
            Group::G2(g) => write!(f, "{g}"),
        }
    }
}

pub struct ChallengeState {
    pub name: String,
    pub g: Generator,
    pub statement: Vec<Group>,
    pub hash: [u8; 32],
}

impl ChallengeState {
    pub fn new(generator: Generator, statement: Vec<Group>, announcement: &[u8]) -> Self {
        Self {
            name: crate::config::CHALLENGE_STATE_NAME.to_string(),
            g: generator,
            statement,
            hash: Sha256::digest(announcement).into(),
        }
    }
}

pub type Challenge = FieldElement;
pub type Response = Vec<FieldElement>;

/// Schnorr proof (non-interactive using Fiat Shamir heuristic) of the statement
/// ZK(x, m_1....m_n; h = g^x and h_1^m_1...h_n^m_n) and generalized version
pub struct ZkpSchnorrFiatShamir {}

impl Default for ZkpSchnorrFiatShamir {
    fn default() -> Self {
        Self::new()
    }
}

impl ZkpSchnorrFiatShamir {
    pub fn new() -> Self {
        ZkpSchnorrFiatShamir {}
    }
    pub fn setup() -> G2 {
        G2::generator()
    }

    /// The code below is from the original implementation of the Schnorr proof (non-interactive using FS heuristic) of the statement ZK(x ; h = g^x)
    pub fn challenge(state: &ChallengeState) -> FieldElement {
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
        secret_wit: &Vec<Secret<FieldElement>>,
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
        // cast stms to Group::G2
        let stms = stms
            .iter()
            .map(|x| Group::G2(x.clone()))
            .collect::<Vec<Group>>();

        let state = ChallengeState {
            name: "schnorr".to_string(),
            g: Generator::G2(GeneratorG2(g_2.clone())),
            statement: stms,
            hash,
        };

        // Generate challenge.
        let mut c = Self::challenge(&state).to_bignum();
        c.rmod(&CurveOrder);

        // r = [(w_list[i] - c * secret_wit[i]) % o for i in range(len(secret_wit))]
        let r = (0..secret_wit.len())
            .map(|i| {
                let a = w_list[i].clone();
                let b = FieldElement::try_from(c).unwrap() * secret_wit[i].expose_secret();
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
            .map(|x| Group::G2(x.clone()))
            .collect::<Vec<Group>>();

        let state = ChallengeState {
            name: "schnorr".to_string(),
            g: Generator::G2(GeneratorG2(g_2.clone())),
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
    fn setup() -> G1 {
        G1::generator()
    }

    fn challenge(state: &ChallengeState) -> Challenge {
        let mut elem_str = vec![state.statement.len().to_string()];
        elem_str.extend(state.statement.iter().map(|x| x.to_string()));

        // The length of each element in the list is added to the element
        let elem_len = elem_str.iter().map(|x| format!("{}||{}", x.len(), x));
        let state = elem_len.collect::<Vec<String>>().join("|");

        let hash = Sha256::digest(state.as_bytes());

        FieldElement::from_hex(format!("{hash:X}")).unwrap()
    }

    fn response(
        challenge: &Challenge,
        announce_randomness: &FieldElement,
        stm: &RandomizedPubKey,
        secret_wit: &Secret<FieldElement>,
    ) -> FieldElement {
        assert!(G1::generator() * secret_wit.expose_secret() == *stm.as_ref());
        let mut res = BigNum::frombytes(
            &(announce_randomness + challenge * secret_wit.expose_secret()).to_bytes(),
        );
        res.rmod(&CurveOrder);
        res.into()
    }
}

pub struct ZKPSchnorr {
    g_1: G1,
}

// use defaults
impl Schnorr for ZKPSchnorr {
    fn new() -> Self {
        Self {
            g_1: G1::generator(),
        }
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
        let right_side = announce_element + challenge * stm;
        left_side == right_side
    }

    pub fn announce(&self) -> (G1, FieldElement) {
        let w_random = FieldElement::random();
        let w_element = w_random.clone() * &self.g_1;
        (w_element, w_random)
    }
}
#[derive(Clone)]

pub struct DamgardTransform {
    pub pedersen: Pedersen,
}

impl DamgardTransform {
    pub fn announce(&self) -> (PedersenCommit, PedersenOpen) {
        let w_random = FieldElement::random();
        let w_element = &self.pedersen.g.scalar_mul_const_time(&w_random);
        let (pedersen_commit, mut pedersen_open) = self.pedersen.commit(w_random);
        pedersen_open.element(w_element.clone());
        (pedersen_commit, pedersen_open)
    }
    pub fn verify(nym_proof: &NymProof, nym_damgard: &DamgardTransform) -> bool {
        let left_side = nym_proof.response.clone() * &G1::generator();
        let right_side = nym_proof.pedersen_open.announce_element.as_ref().unwrap()
            + nym_proof.challenge.clone() * nym_proof.public_key.as_ref();
        left_side == right_side
            && nym_damgard
                .pedersen
                .decommit(&nym_proof.pedersen_open, &nym_proof.pedersen_commit)
    }
}

// implement a trait for Damgard_Transform that has the same functions as ZKP_Schnorr and then you would implement the functions for Damgard_Transform

impl Schnorr for DamgardTransform {
    fn new() -> Self {
        let pedersen = Pedersen::new();
        Self { pedersen }
    }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct Pedersen {
    pub g: GeneratorG1,
    pub h: G1,
    // trapdoor: FieldElement,
}
pub type PedersenCommit = G1;

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct PedersenOpen {
    pub open_randomness: FieldElement,
    pub announce_randomness: FieldElement,
    pub announce_element: Option<G1>,
}

impl PedersenOpen {
    pub fn element(&mut self, elem: G1) {
        self.announce_element = Some(elem);
    }
}
impl Default for Pedersen {
    fn default() -> Self {
        Self::new()
    }
}
impl Pedersen {
    pub fn new() -> Self {
        // h is the statement. d is the trapdoor. g is the generator. h = d*g
        let g: GeneratorG1 = G1::generator().into();
        let d = Secret::new(FieldElement::random()); // trapdoor
        let h = &g.scalar_mul_const_time(d.expose_secret());
        Pedersen { g, h: h.clone() }
    }
    pub fn commit(&self, msg: FieldElement) -> (PedersenCommit, PedersenOpen) {
        let r = FieldElement::random();
        let pedersen_commit = &r * &self.h + &self.g.scalar_mul_const_time(&msg);
        let pedersen_open = PedersenOpen {
            open_randomness: r,
            announce_randomness: msg,
            announce_element: None,
        };

        (pedersen_commit, pedersen_open)
    }

    /// Decrypts/Decommits the message
    pub fn decommit(&self, pedersen_open: &PedersenOpen, pedersen_commit: &PedersenCommit) -> bool {
        let c2 = &self.h.scalar_mul_const_time(&pedersen_open.open_randomness)
            + &self
                .g
                .scalar_mul_const_time(&pedersen_open.announce_randomness);
        &c2 == pedersen_commit
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
        let secret_x = Secret::new(FieldElement::random());
        let public_h = g_2.scalar_mul_const_time(secret_x.expose_secret());

        // create a vec of secrets for iter 0 to 5
        let secrets = (0..5)
            .map(|_| Secret::new(FieldElement::random()))
            .collect::<Vec<Secret<FieldElement>>>();

        // create stm for len of secrets, sec[i * g_2]
        let stm = secrets
            .iter()
            .map(|s| g_2.scalar_mul_const_time(s.expose_secret()))
            .collect::<Vec<G2>>();

        let proof_list /* (r, c) */ = ZkpSchnorrFiatShamir::non_interact_prove(&g_2, &stm, &secrets).unwrap();
        // let proof = (r, c);
        let result = ZkpSchnorrFiatShamir::non_interact_verify(&g_2, &stm, &proof_list);
        assert!(result);

        // create a proof for statement
        let proof_single = ZkpSchnorrFiatShamir::non_interact_prove(
            &g_2,
            &vec![public_h.clone()],
            &vec![secret_x],
        )
        .unwrap();
        let result_single =
            ZkpSchnorrFiatShamir::non_interact_verify(&g_2, &vec![public_h], &proof_single);
        assert!(result_single);
    }

    #[test]
    fn test_interact_prove() {
        // Create a random statement for testing
        let secret_x = Secret::new(FieldElement::random());
        let zkpsch = ZKPSchnorr::new();
        let stm = RandomizedPubKey(zkpsch.g_1.scalar_mul_const_time(secret_x.expose_secret()));

        let announce = zkpsch.announce();

        // verifier creates a challenge
        let state = ChallengeState {
            name: "schnorr".to_string(),
            g: Generator::G1(zkpsch.g_1.clone().into()),
            statement: vec![Group::G1(stm.as_ref().clone())],
            hash: Sha256::digest(announce.0.to_bytes(false)).into(),
        };

        let challenge = ZKPSchnorr::challenge(&state);

        // prover creates a respoonse (or proof)
        let response = ZKPSchnorr::response(&challenge, &announce.1, &stm, &secret_x);

        //     assert(Schnorr.verify(challenge, W_element, stm, response))
        assert!(zkpsch.verify(&challenge, &announce.0, &stm, &response));
    }

    #[test]
    fn test_damgard_transform() {
        let damgard = DamgardTransform::new();

        // create a statement. A statement is a secret and a commitment to that secret.
        // A commitment is a generator raised to the power of the secret.
        let secret = Secret::new(FieldElement::random()); // x
        let statement = RandomizedPubKey(
            damgard
                .pedersen
                .g
                .scalar_mul_const_time(secret.expose_secret()),
        ); // h

        let (pedersen_commit, pedersen_open) = damgard.announce();

        let state = ChallengeState::new(
            Generator::G1(damgard.pedersen.g.clone()),
            vec![Group::G1(statement.as_ref().clone())],
            &pedersen_commit.to_bytes(false),
        );

        let challenge = DamgardTransform::challenge(&state);

        // (challenge: &Challenge, announce_randomness: &FieldElement, stm: &G2, secret_wit: &FieldElement)
        let response = DamgardTransform::response(
            &challenge,
            &pedersen_open.announce_randomness,
            &statement,
            &secret,
        );

        let proof_nym = NymProof {
            challenge,
            pedersen_open,
            pedersen_commit,
            public_key: statement,
            response,
        };

        assert!(DamgardTransform::verify(&proof_nym, &damgard));
    }
}
