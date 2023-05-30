use super::*;
use crate::keypair::Signature;
use amcl_wrapper::errors::SerzDeserzError;
use amcl_wrapper::field_elem::FieldElement;
use amcl_wrapper::group_elem::GroupElement;
use amcl_wrapper::group_elem_g1::G1;
use std::ops::Deref;

/// Update Key alias
pub type UpdateKey = Option<Vec<Vec<G1>>>;
pub type OpeningInformation = FieldElement;

#[derive(Debug)]
pub enum UpdateError {
    SerzDeserzError(SerzDeserzError),
    Error,
}

impl From<SerzDeserzError> for UpdateError {
    fn from(err: SerzDeserzError) -> Self {
        UpdateError::SerzDeserzError(err)
    }
}

/// A [`DelegatableKey`] Credential is an EqcSignature signature returned by the sign function
/// It contains the sigma, update key, commitment vector
/// - `sigma` [`Signature`] is the sigma value used in the signature
/// - `commitment_vector` is the commitment vector used in the signature
/// - `opening_vector` enables holder to generate proofs, if available
/// - `update_key` [`UpdateKey`] enables holder to extend the attributes in credential, up to the update_key limit. `initial Entry len < current Entry len < update_key.len()`
/// for the next level in the delegation hierarchy. If no further delegations are allowed, then no
/// update key is provided.
///
#[derive(Clone)]
pub struct Credential {
    pub sigma: Signature,
    pub update_key: UpdateKey, // Called DelegatableKey (dk for k prime) in the paper
    pub commitment_vector: Vec<G1>,
    pub opening_vector: Vec<FieldElement>,
}

/// Change representation of the signature message pair to a new commitment vector and user public key.
/// This is used to update the signature message pair to a new user public key.
/// The new commitment vector is computed using the old commitment vector and the new user public key.
/// The new user public key is computed using the old user public key and the update key.
/// The update key is computed during the signing process.
///
/// # Arguments
/// - `vk`: the verification key
/// - `pk_u`: the user public key
/// - `commitment_vector`: the commitment vector
/// - `opening_vector`: opening information vector related to commitment vector
/// - `sigma`: the signature
/// - `mu`: randomness is used to randomize commitment vector and signature accordingly
/// - `psi`: randomness is used to randomize commitment vector and signature accordingly
/// - `extendable`: a flag to determine if it needs to refresh (randomize) the `update_key` as well or not. Only takes
/// effect if there is both `b` and an `orig_sig.update_key`
///
/// # Returns
/// returns an updated signature σ for a new commitment vector and corresponding openings
pub fn change_rep(
    vk: &[VK],
    pk_u: &G1,
    orig_sig: &Credential,
    mu: &FieldElement,
    psi: &FieldElement,
    extendable: bool,
) -> (RandomizedPubKey, Credential, FieldElement) {
    // pick randomness, chi
    let chi = FieldElement::random();

    // randomize Commitment and opening vectors and user public key with randomness mu, chi
    let rndmz_commit_vector: Vec<G1> = orig_sig.commitment_vector.iter().map(|c| mu * c).collect();

    let rndmz_opening_vector: Vec<FieldElement> =
        orig_sig.opening_vector.iter().map(|o| mu * o).collect();

    // Randomize public key with two given randomness psi and chi.
    let rndmz_pk_u = psi * &(pk_u + &chi * &G1::generator());

    // adapt the signature for the randomized commitment vector and PK_u_prime
    let Signature { z, y_g1, y_hat, t } = &orig_sig.sigma;

    if let VK::G1(vk0) = &vk[0] {
        let sigma_prime = Signature {
            z: mu * &psi.inverse() * z,
            y_g1: psi * y_g1,
            y_hat: psi * y_hat,
            t: psi * &(t + &chi * vk0),
        };

        // randomize update key with randomness mu
        let mut fresh_update_key = None;
        if extendable {
            if let Some(update_key) = &orig_sig.update_key {
                let mut usign_prime = Vec::new();
                usign_prime.resize(update_key.len(), Vec::new());
                for k in orig_sig.commitment_vector.len() + 1..update_key.len() {
                    usign_prime[k - 1] = update_key[k - 1]
                        .iter()
                        .map(|item| mu * &psi.inverse() * item)
                        .collect();
                }
                fresh_update_key = Some(usign_prime);
            }
        }

        (
            RandomizedPubKey(rndmz_pk_u),
            Credential {
                sigma: sigma_prime,
                update_key: fresh_update_key,
                commitment_vector: rndmz_commit_vector,
                opening_vector: rndmz_opening_vector,
            },
            chi,
        )
    } else {
        panic!("Invalid verification key");
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct RandomizedPubKey(pub G1);

/// Impl As_Ref
impl AsRef<G1> for RandomizedPubKey {
    fn as_ref(&self) -> &G1 {
        &self.0
    }
}

impl Deref for RandomizedPubKey {
    type Target = G1;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<RandomizedPubKey> for G1 {
    fn from(val: RandomizedPubKey) -> Self {
        val.0
    }
}

pub fn rndmz_pk(pk_u: &G1, chi: &FieldElement, psi: &FieldElement, g_1: &G1) -> RandomizedPubKey {
    RandomizedPubKey(psi * (pk_u + chi * g_1))
}
