use std::fmt::Display;

use anyhow::Result;
use bls12_381_plus::elliptic_curve::bigint;
use bls12_381_plus::elliptic_curve::bigint::Encoding;
use bls12_381_plus::elliptic_curve::ops::MulByGenerator;
use bls12_381_plus::ff::Field;
use bls12_381_plus::group::prime::PrimeCurveAffine;
use bls12_381_plus::group::Curve;
use bls12_381_plus::group::GroupEncoding;
use bls12_381_plus::G1Affine;
use bls12_381_plus::G2Affine;
use bls12_381_plus::{G1Projective, G2Projective, Scalar};
use rand::rngs::ThreadRng;
use secrecy::{ExposeSecret, Secret};
use sha2::{Digest, Sha256};

use crate::keypair::NymProof;

/// The Challenge State is a struct that contains the name of the challenge,
/// the generator, the statement, and the hash of the announcement
///
/// # Arguments
///
/// * `name` - The name of the challenge
/// * `g` - The generator
/// * `statement` - The statement
/// * `hash` - The hash of the announcement
#[derive(Clone, Debug)]
pub struct ChallengeState<T: PrimeCurveAffine> {
    pub name: String,
    pub g: T,
    pub statement: Vec<T>,
    pub hash: [u8; 32],
}

impl<T: PrimeCurveAffine + GroupEncoding> ChallengeState<T> {
    /// Creates a new [ChallengeState]
    pub fn new(statement: Vec<T>, announcement: impl AsRef<[u8]>) -> Self {
        Self {
            name: crate::config::CHALLENGE_STATE_NAME.to_string(),
            g: <T as PrimeCurveAffine>::generator(),
            statement,
            hash: Sha256::digest(announcement).into(),
        }
    }
}

pub type Challenge = Scalar;
// pub type Response = Vec<Scalar>;

/// Schnorr proof (non-interactive using Fiat Shamir heuristic) of the statement
/// ZK(x, m_1....m_n; h = g^x and h_1^m_1...h_n^m_n) and generalized version
pub mod zkp_schnorr_fiat_shamir {
    use super::*;

    /// The code below is from the original implementation of the Schnorr proof (non-interactive using FS heuristic) of the statement ZK(x ; h = g^x)
    pub fn challenge<T: PrimeCurveAffine + GroupEncoding<Repr = impl AsRef<[u8]>>>(
        state: &ChallengeState<T>,
    ) -> Scalar {
        // transform the state into a byte array
        let mut state_bytes = Vec::new();
        state_bytes.extend_from_slice(state.name.as_bytes());
        state_bytes.extend_from_slice(state.g.to_bytes().as_ref());

        for stmt in &state.statement {
            state_bytes.extend_from_slice(stmt.to_bytes().as_ref());
        }

        state_bytes.extend_from_slice(&state.hash);

        let digest = Sha256::digest(&state_bytes);

        let big_digest = bigint::U256::from_be_bytes(digest.into());

        Scalar::from_raw(big_digest.into())
    }

    /// Schnorr proof (non-interactive using FS heuristic)
    pub fn non_interact_prove(
        stms: &Vec<G2Affine>,
        secret_wit: &Vec<Secret<Scalar>>,
    ) -> Result<(Vec<Scalar>, Challenge)> {
        // match on the statement

        let w_list = (0..stms.len())
            .map(|_| Scalar::random(ThreadRng::default()))
            .collect::<Vec<Scalar>>();

        // wit_list = [w_list[i] * g for i in range(len(w_list))]
        let witness_list = w_list
            .iter()
            .map(G2Projective::mul_by_generator)
            .collect::<Vec<G2Projective>>();

        // sum all w_list items into announcement
        let announcement = witness_list
            .iter()
            .fold(G2Projective::IDENTITY, |acc, x| acc + x);

        let state = ChallengeState::new(stms.to_vec(), &announcement.to_bytes());

        // Generate challenge.
        // let c = Scalar::reduce(bigint::U384::from(Self::challenge(&state)));
        let c = self::challenge(&state);

        // r = [(w_list[i] - c * secret_wit[i]) % o for i in range(len(secret_wit))]
        let r = (0..secret_wit.len())
            .map(|i| {
                let a = w_list[i];
                let b = c * secret_wit[i].expose_secret();
                // let mut r = BigNum::frombytes(&(a - b).to_bytes());
                a - b
                // Scalar::reduce(r)
            })
            .collect::<Vec<Scalar>>();

        Ok((r, c))
    }

    /// Verify the statement ZK(x ; h = g^x)
    pub fn non_interact_verify(stms: &[G2Affine], proof_list: &(Vec<Scalar>, Challenge)) -> bool {
        let (r, c) = proof_list;

        // W_list = [r[i] * g + c * stm[i] for i in range(len(r))]
        let w_list = (0..r.len())
            .map(|i| G2Projective::mul_by_generator(&r[i]) + c * stms[i])
            .collect::<Vec<G2Projective>>();
        // sum all w_list items into announcement
        let announcement = w_list.iter().fold(G2Projective::IDENTITY, |acc, x| acc + x);

        // let state = ChallengeState {
        //     name: "schnorr".to_string(),
        //     g: G2Projective::GENERATOR,
        //     statement: stms.to_vec(),
        //     hash: Sha256::digest(announcement.to_bytes()).into(),
        // };
        let state = ChallengeState::new(stms.to_vec(), &announcement.to_bytes());
        let hash = self::challenge(&state);
        // let hash = Scalar::reduce(bigint::U256::from(hash));
        hash == *c
    }
}

/// Schnorr (interactive) proof of the statement ZK(x ; h = g^x)
pub trait Schnorr {
    fn new() -> Self;

    /// Create a Schnorr challenge
    fn challenge<T: PrimeCurveAffine + GroupEncoding<Repr = impl AsRef<[u8]>> + Display>(
        state: &ChallengeState<T>,
    ) -> Challenge {
        let mut state_bytes = Vec::new();
        state_bytes.extend_from_slice(state.name.as_bytes());
        state_bytes.extend_from_slice(state.g.to_bytes().as_ref());

        for stmt in &state.statement {
            state_bytes.extend_from_slice(stmt.to_bytes().as_ref());
        }

        state_bytes.extend_from_slice(&state.hash);

        let digest = Sha256::digest(&state_bytes);

        let big_digest = bigint::U256::from_be_bytes(digest.into());

        Scalar::from_raw(big_digest.into())
    }

    /// Create a Schnorr response to our own challenge
    fn response(
        challenge: &Scalar,
        announce_randomness: &Scalar,
        stm: &G1Affine,
        secret_wit: &Secret<Scalar>,
    ) -> Scalar {
        assert!(G1Projective::mul_by_generator(secret_wit.expose_secret()).to_affine() == *stm);
        *announce_randomness + challenge * secret_wit.expose_secret()
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
        challenge: &Challenge,
        announce_element: &G1Projective,
        stm: &G1Projective,
        response: &Scalar,
    ) -> bool {
        let left_side = G1Projective::mul_by_generator(response);
        let right_side = announce_element + challenge * stm;
        left_side == right_side
    }

    /// Create a Schnorr announcement
    pub fn announce() -> (G1Projective, Scalar) {
        let w_random = Scalar::random(ThreadRng::default());
        let w_element = G1Projective::mul_by_generator(&w_random);
        (w_element, w_random)
    }
}

/// Damgard Transform containing a [Pedersen] commitment
#[derive(Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct DamgardTransform {
    pub pedersen: Pedersen,
}

impl DamgardTransform {
    /// Create a Damgard Transform challenge announcement
    pub fn announce(&self) -> (PedersenCommit, PedersenOpen) {
        let w_random = Scalar::random(ThreadRng::default());
        let w_element = G1Projective::mul_by_generator(&w_random).to_affine();
        let (pedersen_commit, mut pedersen_open) = self.pedersen.commit(w_random);
        pedersen_open.element(w_element);
        (pedersen_commit, pedersen_open)
    }

    /// Verify the given [NymProof] against the [DamgardTransform]
    pub fn verify(nym_proof: &NymProof, nym_damgard: &DamgardTransform) -> bool {
        let left_side = G1Projective::mul_by_generator(&nym_proof.response);
        let right_side = nym_proof.pedersen_open.announce_element.as_ref().unwrap()
            + nym_proof.challenge * nym_proof.public_key;
        let decommit = nym_damgard
            .pedersen
            .decommit(&nym_proof.pedersen_open, &nym_proof.pedersen_commit);

        (left_side == right_side) && decommit
    }
}

/// Implementation of Schnorr trait for DamgardTransform that has the same functions as ZKP_Schnorr
impl Schnorr for DamgardTransform {
    fn new() -> Self {
        let pedersen = Pedersen::new();
        Self { pedersen }
    }
}

/// Pedersen commitment containing [G1Projective] public key of the random secret trapdoor `d`
#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Pedersen {
    pub h: G1Projective,
    // trapdoor: Scalar,
}
pub type PedersenCommit = G1Projective;

#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct PedersenOpen {
    pub open_randomness: Scalar,
    pub announce_randomness: Scalar,
    pub announce_element: Option<G1Affine>,
}

impl PedersenOpen {
    /// Sets the announce element for the PedersenOpen
    pub fn element(&mut self, elem: G1Affine) {
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
        let d = Secret::new(Scalar::random(ThreadRng::default())); // trapdoor
        let h = G1Projective::mul_by_generator(d.expose_secret());
        Pedersen { h }
    }

    pub fn from_bytes(bytes: &[u8; 32]) -> Self {
        let d = Scalar::from_be_bytes(bytes).expect("32 bytes");
        let h = G1Projective::mul_by_generator(&d);
        Pedersen { h }
    }

    pub fn commit(&self, msg: Scalar) -> (PedersenCommit, PedersenOpen) {
        let r = Scalar::random(ThreadRng::default());
        let pedersen_commit = r * self.h + G1Projective::mul_by_generator(&msg);
        let pedersen_open = PedersenOpen {
            open_randomness: r,
            announce_randomness: msg,
            announce_element: None,
        };

        (pedersen_commit, pedersen_open)
    }

    /// Decrypts/Decommits the message
    pub fn decommit(&self, pedersen_open: &PedersenOpen, pedersen_commit: &PedersenCommit) -> bool {
        let c2 = self.h * pedersen_open.open_randomness
            + G1Projective::mul_by_generator(&pedersen_open.announce_randomness);
        &c2 == pedersen_commit
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bls12_381_plus::group::Curve;

    #[test]
    fn test_non_interact_prove() {
        // 1. Setup
        // 2. Prove
        // 3. Verify
        eprintln!("Testing non-interactive");
        let secret_x = Secret::new(Scalar::random(ThreadRng::default()));
        let public_h = G2Projective::mul_by_generator(secret_x.expose_secret());

        // create a vec of secrets for iter 0 to 5
        let secrets = (0..5)
            .map(|_| Secret::new(Scalar::random(ThreadRng::default())))
            .collect::<Vec<Secret<Scalar>>>();

        // create stm for len of secrets, sec[i * g_2]
        let stm = secrets
            .iter()
            .map(|s| G2Projective::mul_by_generator(s.expose_secret()).to_affine())
            .collect();

        let proof_list /* (r, c) */ = zkp_schnorr_fiat_shamir::non_interact_prove(&stm, &secrets).unwrap();
        // let proof = (r, c);
        let result = zkp_schnorr_fiat_shamir::non_interact_verify(&stm, &proof_list);
        assert!(result);

        // create a proof for statement
        let proof_single =
            zkp_schnorr_fiat_shamir::non_interact_prove(&vec![public_h.into()], &vec![secret_x])
                .unwrap();
        let result_single =
            zkp_schnorr_fiat_shamir::non_interact_verify(&[public_h.into()], &proof_single);
        assert!(result_single);
    }

    #[test]
    fn test_interact_prove() {
        // Create a random statement for testing
        let secret_x = Secret::new(Scalar::random(ThreadRng::default()));
        let stm = G1Projective::mul_by_generator(secret_x.expose_secret()).to_affine();

        let announce = ZKPSchnorr::announce();

        let state = ChallengeState::new(vec![stm], &announce.0.to_bytes());

        let challenge = ZKPSchnorr::challenge(&state);

        // prover creates a respoonse (or proof)
        let response = ZKPSchnorr::response(&challenge, &announce.1, &stm, &secret_x);

        assert!(ZKPSchnorr::verify(
            &challenge,
            &announce.0,
            &stm.into(),
            &response
        ));
    }

    #[test]
    fn test_damgard_transform() {
        let damgard = DamgardTransform::new();

        // create a statement. A statement is a secret and a commitment to that secret.
        // A commitment is a generator raised to the power of the secret.
        let secret = Secret::new(Scalar::random(ThreadRng::default())); // x
                                                                        // h
        let statement = G1Projective::mul_by_generator(secret.expose_secret()).to_affine();

        let (pedersen_commit, pedersen_open) = damgard.announce();

        let state = ChallengeState::new(vec![statement], &pedersen_commit.to_bytes());

        let challenge = DamgardTransform::challenge(&state); // uses triat default

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
            public_key: statement.into(),
            response,
        };

        assert!(DamgardTransform::verify(&proof_nym, &damgard));
    }
}
