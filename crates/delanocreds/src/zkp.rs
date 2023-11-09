use std::fmt::Display;
use std::ops::Deref;

use bls12_381_plus::elliptic_curve::bigint;
use bls12_381_plus::elliptic_curve::ops::MulByGenerator;
use bls12_381_plus::ff::Field;
use bls12_381_plus::group::prime::PrimeCurveAffine;
use bls12_381_plus::group::Curve;
use bls12_381_plus::group::GroupEncoding;
use bls12_381_plus::G1Affine;
use bls12_381_plus::{G1Projective, Scalar};
use rand::rngs::ThreadRng;
use secrecy::{ExposeSecret, Secret};
use sha2::{Digest, Sha256};

use crate::keypair::NymProof;

#[derive(PartialEq, Eq, Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Nonce(pub(crate) Scalar);

/// Create a new [Nonce] with any arbitrary length type that implements AsRef<[u8]> by hashing it
/// into a 32 byte digest and converting it into a Scalar
impl Nonce {
    /// Hash the given bytes into a [Nonce]
    pub fn new(bytes: impl AsRef<[u8]>) -> Self {
        let chash = Sha256::digest(bytes);
        Self(Scalar::from(bigint::U256::from_be_slice(&chash)))
    }
}

impl Default for Nonce {
    fn default() -> Self {
        Self(Scalar::random(ThreadRng::default()))
    }
}

impl From<Scalar> for Nonce {
    fn from(scalar: Scalar) -> Self {
        Self(scalar)
    }
}

/// Converts from [u8; 32] directly into a Nonce
impl From<[u8; 32]> for Nonce {
    fn from(bytes: [u8; 32]) -> Self {
        Self(Scalar::from(bigint::U256::from_be_slice(&bytes)).into())
    }
}

/// Converts from a &[u8, 32] directly into a Nonce
impl From<&[u8; 32]> for Nonce {
    fn from(bytes: &[u8; 32]) -> Self {
        Self(Scalar::from(bigint::U256::from_be_slice(bytes)).into())
    }
}

/// Creates a new [Nonce] from a hash of the given Vec<u8>
impl From<Vec<u8>> for Nonce {
    fn from(bytes: Vec<u8>) -> Self {
        Self::new(bytes.as_slice())
    }
}

/// Creates a new [Nonce] from a hash of the given &[u8]
impl From<&Vec<u8>> for Nonce {
    fn from(bytes: &Vec<u8>) -> Self {
        Self::new(bytes.as_slice())
    }
}

impl Deref for Nonce {
    type Target = Scalar;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl PartialEq<bls12_381_plus::Scalar> for &Nonce {
    fn eq(&self, other: &bls12_381_plus::Scalar) -> bool {
        self.0 == Scalar::from(*other)
    }
}

impl From<Nonce> for Scalar {
    fn from(nonce: Nonce) -> Self {
        nonce.0.into()
    }
}

// convert From Option<impl AsRef<[u8]>> to Nonce
impl From<Option<&[u8]>> for Nonce {
    fn from(bytes: Option<&[u8]>) -> Self {
        match bytes {
            Some(bytes) => Self::new(bytes),
            None => Self::default(),
        }
    }
}

// These functions were in the original implementation but are unused in this Implementation
// Keeping them here unused under a 'zkp' flag for potential future use as needed
#[cfg(feature = "zkp")]
use anyhow::Result;
#[cfg(feature = "zkp")]
use bls12_381_plus::G2Affine;
#[cfg(feature = "zkp")]
use bls12_381_plus::G2Projective;

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

// pub type Response = Vec<Scalar>;

/// Schnorr proof (non-interactive using Fiat Shamir heuristic) of the statement
/// ZK(x, m_1....m_n; h = g^x and h_1^m_1...h_n^m_n) and generalized version
pub mod zkp_schnorr_fiat_shamir {

    #[cfg(feature = "zkp")]
    use super::*;

    /// The code below is from the original implementation of the Schnorr proof (non-interactive using FS heuristic) of the statement ZK(x ; h = g^x)
    /// Enbles only with feature zkp
    #[cfg(feature = "zkp")]
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

        bigint::U256::from_be_slice(&digest).into()
    }

    /// Schnorr proof (non-interactive using FS heuristic)
    #[cfg(feature = "zkp")]
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
    #[cfg(feature = "zkp")]
    pub fn non_interact_verify(stms: &[G2Affine], proof_list: &(Vec<Scalar>, Challenge)) -> bool {
        let (r, c) = proof_list;

        // W_list = [r[i] * g + c * stm[i] for i in range(len(r))]
        let w_list = (0..r.len())
            .map(|i| G2Projective::mul_by_generator(&r[i]) + c * stms[i])
            .collect::<Vec<G2Projective>>();
        // sum all w_list items into announcement
        let announcement = w_list.iter().fold(G2Projective::IDENTITY, |acc, x| acc + x);

        let state = ChallengeState::new(stms.to_vec(), &announcement.to_bytes());
        let hash = self::challenge(&state);
        hash == *c
    }
}

/// Schnorr (interactive) proof of the statement ZK(x ; h = g^x)
pub trait Schnorr {
    fn new() -> Self;

    /// Create a Schnorr challenge
    fn challenge<T: PrimeCurveAffine + GroupEncoding<Repr = impl AsRef<[u8]>> + Display>(
        state: &ChallengeState<T>,
    ) -> Scalar {
        let mut state_bytes = Vec::new();
        state_bytes.extend_from_slice(state.name.as_bytes());
        state_bytes.extend_from_slice(state.g.to_bytes().as_ref());

        for stmt in &state.statement {
            state_bytes.extend_from_slice(stmt.to_bytes().as_ref());
        }

        state_bytes.extend_from_slice(&state.hash);

        let digest = Sha256::digest(&state_bytes);

        Scalar::from(bigint::U256::from_be_slice(&digest))
    }

    /// Create a Schnorr response to our own challenge
    fn response(
        challenge: &Scalar,
        announce_randomness: &Scalar,
        stm: &G1Affine,
        secret_wit: &Secret<Scalar>,
    ) -> Scalar {
        assert!(G1Projective::mul_by_generator(secret_wit.expose_secret()).to_affine() == *stm);
        Scalar::from(*announce_randomness + Scalar::from(*challenge) * secret_wit.expose_secret())
    }
}

pub struct ZKPSchnorr {}

// use defaults
impl Schnorr for ZKPSchnorr {
    fn new() -> Self {
        Self {}
    }
}

#[cfg(feature = "zkp")]
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
#[derive(Clone, PartialEq, Eq, Debug, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct DamgardTransform {
    pub pedersen: Pedersen,
}

impl DamgardTransform {
    /// Create a Damgard Transform challenge announcement
    /// Takes an optional randomness (nonce) to use for the announcement
    pub fn announce(&self, nonce: &Nonce) -> (PedersenCommit, PedersenOpen) {
        let w_random = Scalar::random(ThreadRng::default());
        let w_element = G1Projective::mul_by_generator(&w_random).to_affine();
        let (pedersen_commit, mut pedersen_open) = self.pedersen.commit(nonce, w_random);
        pedersen_open.element(w_element);
        (pedersen_commit, pedersen_open)
    }

    /// Verify the given [NymProof] is valid
    ///
    /// # Example:
    ///
    /// assert!(DamgardTransform::verify(their_proof)
    pub fn verify(nym_proof: &NymProof, nonce: Option<&Nonce>) -> bool {
        if let Some(nonce) = nonce {
            if nym_proof.pedersen_open.open_randomness != *nonce {
                return false;
            }
        }
        let left_side = G1Projective::mul_by_generator(&nym_proof.response);
        let right_side = nym_proof.pedersen_open.announce_element.as_ref().unwrap()
            + nym_proof.challenge * nym_proof.public_key;
        let decommit = nym_proof
            .damgard
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

/// Pedersen Open information: Randomness used to open the commitment, randomness used to announce the secret, and the announcement element
#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct PedersenOpen {
    /// Randomness used to open the commitment
    pub open_randomness: Nonce,
    /// Randomness used to announce the secret
    pub announce_randomness: Scalar,
    /// Announcement element
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

    /// Create a Pedersen commit
    /// Takes an optional randomness (nonce) to use for the announcement which can be used by the
    /// verifier to prevent replay attacks
    ///
    /// The nonce can be compared against the Pedersen open randomness to verify that a replay
    /// attach isn't reusing a previously generated proof
    pub fn commit(&self, nonce: &Nonce, msg: Scalar) -> (PedersenCommit, PedersenOpen) {
        let r: Scalar = **nonce;
        let pedersen_commit = r * self.h + G1Projective::mul_by_generator(&msg);
        let pedersen_open = PedersenOpen {
            open_randomness: nonce.clone(),
            announce_randomness: msg,
            announce_element: None,
        };

        (pedersen_commit, pedersen_open)
    }

    /// Decrypts/Decommits the message
    pub fn decommit(&self, pedersen_open: &PedersenOpen, pedersen_commit: &PedersenCommit) -> bool {
        let c2 = self.h * (*pedersen_open.open_randomness)
            + G1Projective::mul_by_generator(&pedersen_open.announce_randomness);
        &c2 == pedersen_commit
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bls12_381_plus::group::Curve;

    #[test]
    #[cfg(feature = "zkp")]
    fn test_non_interact_prove() {
        let nonce: Nonce = Nonce::default();
        // 1. Setup
        // 2. Prove
        // 3. Verify
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
    #[cfg(feature = "zkp")]
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
        let nonce: Nonce = Nonce::default();
        let damgard = DamgardTransform::new();

        // create a statement. A statement is a secret and a commitment to that secret.
        // A commitment is a generator raised to the power of the secret.
        let secret = Secret::new(Scalar::random(ThreadRng::default())); // x
                                                                        // h
        let statement = G1Projective::mul_by_generator(secret.expose_secret()).to_affine();

        let (pedersen_commit, pedersen_open) = damgard.announce(&nonce);

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
            damgard,
        };

        assert!(DamgardTransform::verify(&proof_nym, Some(&nonce)));
    }
}
