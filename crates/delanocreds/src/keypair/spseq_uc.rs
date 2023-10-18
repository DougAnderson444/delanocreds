use super::*;
use crate::ec::curve::polynomial_from_roots;
use crate::ec::{G1Projective, Scalar};
use crate::keypair::Signature;
use bls12_381_plus::group::GroupEncoding;
use bls12_381_plus::G1Compressed;
use serde_with::base64::{Base64, UrlSafe};
use serde_with::formats::Unpadded;
use serde_with::serde_as;

/// Update Key alias
pub type UpdateKey = Option<Vec<Vec<G1Projective>>>;

/// Error that is thrown when the update key is not available for the credential
#[derive(Debug)]
pub enum UpdateError {
    Error(String),
}

impl std::error::Error for UpdateError {}

impl std::fmt::Display for UpdateError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            UpdateError::Error(e) => write!(f, "UpdateError: {}", e),
        }
    }
}

/// A [Credential] is an EqcSignature signature returned by the sign function
/// It contains the sigma, update key, commitment vector
/// - `sigma` [`Signature`] is the sigma value used in the signature
/// - `commitment_vector` is the commitment vector used in the signature
/// - `opening_vector` enables holder to generate proofs, if available
/// - `update_key` [`UpdateKey`] enables holder to extend the attributes in credential, up to the update_key limit. `initial Entry len < current Entry len < update_key.len()`
/// for the next level in the delegation hierarchy. If no further delegations are allowed, then no
/// update key is provided.
/// - `vk` [`VK`] is the verification key used in the signature
///
#[derive(Clone, Debug, PartialEq)]
pub struct Credential {
    pub sigma: Signature,
    pub update_key: UpdateKey, // Called DelegatableKey (dk for k prime) in the paper
    pub commitment_vector: Vec<G1Projective>,
    pub opening_vector: Vec<Scalar>,
    pub vk: Vec<VK>,
}

/// [CredentialCompressed] is a compressed version of [Credential]. Each element is compressed into their smallest byte equivalents and serializable as base64URL safe encoding.
#[serde_as]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct CredentialCompressed {
    sigma: SignatureCompressed,
    #[serde_as(as = "Option<Vec<Vec<Base64<UrlSafe, Unpadded>>>>")]
    update_key: Option<Vec<Vec<G1Compressed>>>,
    #[serde_as(as = "Vec<Base64<UrlSafe, Unpadded>>")]
    commitment_vector: Vec<G1Compressed>,
    #[serde_as(as = "Vec<Base64<UrlSafe, Unpadded>>")]
    opening_vector: Vec<OpeningInfo>,
    #[serde_as(as = "Vec<Base64<UrlSafe, Unpadded>>")]
    vk: Vec<VKCompressed>,
}

/// Try to convert from [CredentialCompressed] to [Credential]
impl TryFrom<CredentialCompressed> for Credential {
    type Error = String;
    fn try_from(value: CredentialCompressed) -> std::result::Result<Self, Self::Error> {
        let sigma = Signature::try_from(value.sigma)?;
        let update_key = match value.update_key {
            Some(usign) => {
                let mut usign_decompressed = Vec::new();
                usign_decompressed.resize(usign.len(), Vec::new());
                for k in 0..usign.len() {
                    usign_decompressed[k] = usign[k]
                        .iter()
                        .map(|item| {
                            let g1_maybe = G1Projective::from_bytes(item);
                            if g1_maybe.is_none().into() {
                                return Err("Invalid G1 point".to_string());
                            }
                            Ok(g1_maybe.expect("it'll be fine, it passed the check"))
                        })
                        .map(|item| item.unwrap())
                        .collect();
                }
                Some(usign_decompressed)
            }
            None => None,
        };
        let commitment_vector = value
            .commitment_vector
            .iter()
            .map(|item| {
                let g1_maybe = G1Projective::from_bytes(item);
                if g1_maybe.is_none().into() {
                    return Err("Invalid G1 point".to_string());
                }
                Ok(g1_maybe.expect("it'll be fine, it passed the check"))
            })
            // unwrap the Ok into inner for each
            .map(|item| item.unwrap())
            .collect::<Vec<G1Projective>>();
        let opening_vector = value
            .opening_vector
            .into_iter()
            .map(|item| item.into_scalar())
            .collect::<Vec<Scalar>>();
        let vk = value
            .vk
            .iter()
            .map(|item| match item {
                VKCompressed::G1(g1) => {
                    let g1_maybe = G1Projective::from_bytes(g1);
                    if g1_maybe.is_none().into() {
                        return Err("Invalid G1 point".to_string());
                    }
                    Ok(VK::G1(
                        g1_maybe.expect("it'll be fine, it passed the check"),
                    ))
                }
                VKCompressed::G2(g2) => {
                    let g2_maybe = G2Projective::from_bytes(g2);
                    if g2_maybe.is_none().into() {
                        return Err("Invalid G2 point".to_string());
                    }
                    Ok(VK::G2(
                        g2_maybe.expect("it'll be fine, it passed the check"),
                    ))
                }
            })
            .map(|item| item.unwrap())
            .collect::<Vec<VK>>();

        Ok(Credential {
            sigma,
            update_key,
            commitment_vector,
            opening_vector,
            vk,
        })
    }
}

/// Convert from [Credential] to [CredentialCompressed]
impl From<Credential> for CredentialCompressed {
    fn from(cred: Credential) -> Self {
        let sigma = SignatureCompressed::from(cred.sigma);
        let update_key = match cred.update_key {
            Some(usign) => {
                let mut usign_compressed = Vec::new();
                usign_compressed.resize(usign.len(), Vec::new());
                for k in 0..usign.len() {
                    usign_compressed[k] = usign[k].iter().map(|item| item.to_bytes()).collect();
                }
                Some(usign_compressed)
            }
            None => None,
        };
        let commitment_vector = cred
            .commitment_vector
            .iter()
            .map(|item| item.to_bytes())
            .collect();
        let opening_vector = cred
            .opening_vector
            .into_iter()
            .map(OpeningInfo::new)
            .collect::<Vec<OpeningInfo>>();

        let vk = cred
            .vk
            .iter()
            .map(|item| match item {
                VK::G1(g1) => VKCompressed::G1(g1.to_bytes()),
                VK::G2(g2) => VKCompressed::G2(g2.to_bytes()),
            })
            .collect();

        CredentialCompressed {
            sigma,
            update_key,
            commitment_vector,
            opening_vector,
            vk,
        }
    }
}

/// Newtype for Opening Vector of [Scalar].
/// This exists so it can easily be converted to base64
pub struct OpeningInfo {
    inner: [u8; 32],
}

impl OpeningInfo {
    pub fn new(inner: Scalar) -> Self {
        OpeningInfo {
            inner: inner.to_be_bytes(),
        }
    }

    pub fn into_scalar(self) -> Scalar {
        Scalar::from_be_bytes(&self.inner).unwrap()
    }
}

/// Implements AsRef<[u8]> for OpeningVector, so it can be serde compatible
impl AsRef<[u8]> for OpeningInfo {
    fn as_ref(&self) -> &[u8] {
        self.inner.as_ref()
    }
}

/// From<Vec<u8>> for OpeningVector
impl From<Vec<u8>> for OpeningInfo {
    fn from(v: Vec<u8>) -> Self {
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&v[..]);
        OpeningInfo { inner: bytes }
    }
}

/// [Display] for [Credential] is converting its compressed elements, then to json string
#[cfg(feature = "serde")]
impl Display for Credential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let comp = CredentialCompressed::from(self.clone());
        let comp_json = serde_json::to_string_pretty(&comp).unwrap();
        write!(f, "{}", comp_json)
    }
}

/// Takes compressed elements and deserializes json string to [Credential]
#[cfg(feature = "serde")]
impl FromStr for Credential {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let cred_compressed: CredentialCompressed = serde_json::from_str(s).unwrap();
        cred_compressed.try_into()
    }
}
/// Change the Representative of the signature message pair to a new commitment vector and user public key.
/// This is used to update the signature message pair to a new user public key.
/// The new commitment vector is computed using the old commitment vector and the new user public key.
/// The new user public key is computed using the old user public key and the update key.
/// The update key is computed during the signing process.
///
/// # Arguments
/// - `pk_u`: Current public key associated to the Credential's Sigma Signature
/// - `cred`: [Credential] to be updated
/// - `mu`: randomness is used to randomize commitment vector and signature accordingly. Should be set to one (1) unless it's the final use, as it cannot be re-randomized again.
/// - `psi`: randomness is used to randomize commitment vector and signature accordingly
/// - `extendable`: a flag to determine if it needs to refresh (randomize) the `update_key` as well or not. Only takes
/// effect if there is both `b` and an `orig_sig.update_key`
///
/// # Returns
/// returns an updated signature σ for a new commitment vector and corresponding openings
pub fn change_rep(
    pk_u: &G1Projective,
    cred: &Credential,
    mu: &Scalar,
    psi: &Scalar,
    extendable: bool,
) -> (G1Projective, Credential, Scalar) {
    // pick randomness, chi
    let chi = Scalar::random(ThreadRng::default());
    // randomize Commitment and opening vectors and user public key with randomness mu, chi
    let rndmz_commit_vector = cred.commitment_vector.iter().map(|c| mu * c).collect();
    let rndmz_opening_vector = cred.opening_vector.iter().map(|o| mu * o).collect();

    // Randomize public key with two given randomness psi and chi.
    let rndmz_pk_u = psi * (pk_u + G1Projective::mul_by_generator(&chi));

    // adapt the signature for the randomized commitment vector and PK_u_prime
    let Signature { z, y_g1, y_hat, t } = &cred.sigma;

    if let VK::G1(vk0) = &cred.vk[0] {
        let sigma_prime = Signature {
            z: mu * psi.invert().unwrap() * z,
            y_g1: psi * y_g1,
            y_hat: psi * y_hat,
            t: psi * (t + chi * vk0),
        };

        // randomize update key with randomness mu, psi
        let fresh_update_key = match &cred.update_key {
            Some(usign) if extendable => {
                let mut usign_prime = Vec::new();
                usign_prime.resize(usign.len(), Vec::new());
                for k in cred.commitment_vector.len()..usign.len() {
                    usign_prime[k] = usign[k]
                        .iter()
                        .map(|item| mu * psi.invert().unwrap() * item)
                        .collect();
                }
                Some(usign_prime)
            }
            _ => None,
        };

        (
            rndmz_pk_u,
            Credential {
                sigma: sigma_prime,
                update_key: fresh_update_key,
                commitment_vector: rndmz_commit_vector,
                opening_vector: rndmz_opening_vector,
                vk: cred.vk.to_vec(),
            },
            chi,
        )
    } else {
        panic!("Invalid verification key");
    }
}

/// Change Relations of a [Credential]. Push additional [Entry] onto the end of Message Commitment Stack.
///
/// Appends new randomized commitment and opening for the new entry.
///
/// Updates the signature for a new commitment vector including 𝐶_L for message_l using update_key
///
/// Referred to as `change_rel` or "Change Relations" in the paper.
///
/// # Arguments
/// - `message_l`: message set at index `index_l` that will be added in message vector
/// - `index_l`: index of `update_key` to be used for the added element,
///             `[1..n]` (starts at 1)
/// - `signature`: EqcSignature {sigma, update_key, commitment_vector, opening_vector}
/// - `mu`: optional randomness, default to 1. Only applies when same randomness is used previosuly in [`change_rep`] function
///
/// # Returns
/// new signature including the message set at index l
pub fn change_rel(
    parameters: &ParamSetCommitment,
    addl_attrs: &Entry,
    orig_sig: Credential,
    mu: &Scalar,
) -> Result<Credential, UpdateError> {
    // Validate the input. There must be room between the length of the current commitment vector
    // and the length of the update key to append a new entry.
    // valid input if: index_l = orig_sig.commitment_vector.len() + 1 && orig_sig.commitment_vector.len() + 1 <= orig_sig.update_key.as_ref().unwrap().len()
    let index_l = orig_sig.commitment_vector.len();

    match &orig_sig.update_key {
        // can only change attributes if we have the messages and an update_key
        Some(usign) if index_l < usign.len() => {
            let Signature { z, y_g1, y_hat, t } = orig_sig.sigma;
            let (commitment_l, opening_l) = CrossSetCommitment::commit_set(parameters, addl_attrs);

            let rndmz_commitment_l = mu * commitment_l;
            let rndmz_opening_l = mu * opening_l;

            let set_l = entry_to_scalar(addl_attrs);
            let monypolcoefficient = polynomial_from_roots(&set_l[..]);

            let list = usign.get(index_l).unwrap();
            let sum_points_uk_i = list
                .iter()
                .zip(monypolcoefficient.coefficients().iter())
                .fold(
                    G1Projective::identity(),
                    |acc, (list_i, monypolcoefficient_i)| acc + list_i * monypolcoefficient_i,
                );

            let gama_l = sum_points_uk_i * opening_l;

            let z_tilde = z + gama_l;

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
                commitment_vector: commitment_vector_tilde,
                opening_vector: opening_vector_tilde,
                ..orig_sig
            })
        }
        _ => Err(UpdateError::Error(
            "No update key, cannot change relations".to_string(),
        )),
    }
}
