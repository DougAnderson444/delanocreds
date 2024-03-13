use self::error::Error;

use super::*;
use crate::ec::curve::polynomial_from_roots;
use crate::ec::G1Projective;
use crate::keypair::Signature;

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

/// A [Credential] is an SP-SEQ sigma [Signature] returned by the sign function
/// It contains the sigma, update key, commitment vector, and issuer public data
/// - `sigma` [`Signature`] is the sigma value used in the signature
/// - `commitment_vector` is the commitment vector used in the signature
/// - `opening_vector` enables holder to generate proofs, if available
/// - `update_key` [`UpdateKey`] enables holder to extend the attributes in credential, up to the update_key limit. `initial Entry len < current Entry len < update_key.len()`
/// for the next level in the delegation hierarchy. If no further delegations are allowed, then no
/// update key is provided.
/// - `vk` [`VK`] is the verification key used in the signature
#[derive(Clone, Debug, PartialEq, Default)]
pub struct Credential {
    pub sigma: Signature,
    pub update_key: UpdateKey, // Called DelegatableKey (dk for k prime) in the paper
    pub commitment_vector: Vec<G1Projective>,
    pub opening_vector: Vec<Scalar>,
    pub issuer_public: IssuerPublic,
}

/// [CredentialCompressed] is a compressed version of [Credential]. Each element is compressed into their smallest byte equivalents and serializable.
#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct CredentialCompressed {
    pub sigma: SignatureCompressed,
    pub update_key: Option<Vec<Vec<Vec<u8>>>>,
    pub commitment_vector: Vec<Vec<u8>>,
    pub opening_vector: Vec<Vec<u8>>,
    pub issuer_public: IssuerPublicCompressed,
}

impl CBORCodec for CredentialCompressed {}

/// Try to convert from [CredentialCompressed] to [Credential]
impl TryFrom<CredentialCompressed> for Credential {
    type Error = error::Error;
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
                            // into G1Projective
                            let mut bytes = [0u8; G1Affine::COMPRESSED_BYTES];
                            bytes.copy_from_slice(item);
                            let g1_maybe = G1Affine::from_compressed(&bytes);

                            if g1_maybe.is_none().into() {
                                return Err(Error::InvalidG1Point);
                            }
                            Ok(g1_maybe.expect("it'll be fine, it passed the check"))
                        })
                        .map(|item| item.unwrap().into())
                        .collect::<Vec<G1Projective>>();
                }
                Some(usign_decompressed)
            }
            None => None,
        };

        let commitment_vector = value
            .commitment_vector
            .iter()
            .map(|item| {
                let mut bytes = [0u8; G1Affine::COMPRESSED_BYTES];
                bytes.copy_from_slice(item);
                let g1_maybe = G1Affine::from_compressed(&bytes);

                if g1_maybe.is_none().into() {
                    // Error::InvalidG1
                    return Err(Error::InvalidG1Point);
                }
                Ok(g1_maybe.expect("it'll be fine, it passed the check"))
            })
            // unwrap the Ok into inner for each
            .map(|item| item.unwrap().into())
            .collect::<Vec<G1Projective>>();

        let opening_vector = value
            .opening_vector
            .into_iter()
            .map(|item| {
                // Convert to OpeningInfo then scalar
                let mut bytes = [0u8; 32];
                bytes.copy_from_slice(&item);
                let opening_info = OpeningInfo { inner: bytes };
                opening_info.into_scalar()
            })
            .collect::<Vec<Scalar>>();

        let issuer_public = IssuerPublic::try_from(value.issuer_public)?;

        Ok(Credential {
            sigma,
            update_key,
            commitment_vector,
            opening_vector,
            issuer_public,
        })
    }
}

/// Convert from [Credential] to [CredentialCompressed]
impl From<&Credential> for CredentialCompressed {
    fn from(cred: &Credential) -> Self {
        let sigma = SignatureCompressed::from(cred.sigma.clone());
        let issuer_public = IssuerPublicCompressed::from(cred.issuer_public.clone());

        let update_key = match &cred.update_key {
            Some(usign) => {
                let mut usign_compressed = Vec::new();
                usign_compressed.resize(usign.len(), Vec::new());
                for k in 0..usign.len() {
                    usign_compressed[k] = usign[k]
                        .iter()
                        .map(|item| item.to_compressed().to_vec())
                        .collect();
                }
                Some(usign_compressed)
            }
            None => None,
        };

        let commitment_vector = cred
            .commitment_vector
            .iter()
            .map(|item| item.to_compressed().to_vec())
            .collect();

        let opening_vector = cred
            .opening_vector
            .clone()
            .into_iter()
            .map(|item| OpeningInfo::new(item).inner.to_vec())
            .collect::<Vec<Vec<u8>>>();

        CredentialCompressed {
            sigma,
            update_key,
            commitment_vector,
            opening_vector,
            issuer_public,
        }
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
                    usign_compressed[k] = usign[k]
                        .iter()
                        .map(|item| item.to_compressed().to_vec())
                        .collect();
                }
                Some(usign_compressed)
            }
            None => None,
        };
        let commitment_vector = cred
            .commitment_vector
            .iter()
            .map(|item| item.to_compressed().to_vec())
            .collect();
        let opening_vector = cred
            .opening_vector
            .clone()
            .into_iter()
            .map(|item| OpeningInfo::new(item).inner.to_vec())
            .collect::<Vec<Vec<u8>>>();

        let issuer_public: IssuerPublicCompressed = cred.issuer_public.into();

        CredentialCompressed {
            sigma,
            update_key,
            commitment_vector,
            opening_vector,
            issuer_public,
        }
    }
}

/// Newtype for Opening Information which is [Scalar] bytes.
/// This exists so it can easily be converted to base64 and back.
pub struct OpeningInfo {
    inner: [u8; 32],
}

impl OpeningInfo {
    /// Create a new OpeningInfo from a [Scalar]
    pub fn new(inner: Scalar) -> Self {
        OpeningInfo {
            inner: inner.to_be_bytes(),
        }
    }

    /// Convert the inner bytes to a [Scalar]
    pub fn into_scalar(self) -> Scalar {
        Scalar::from_be_bytes(&self.inner).unwrap()
    }
}

/// Implements AsRef<[u8]> for [OpeningInfo], so it can be serde compatible
impl AsRef<[u8]> for OpeningInfo {
    fn as_ref(&self) -> &[u8] {
        self.inner.as_ref()
    }
}

/// From<Vec<u8>> for [OpeningInfo]
impl From<Vec<u8>> for OpeningInfo {
    fn from(v: Vec<u8>) -> Self {
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&v[..]);
        OpeningInfo { inner: bytes }
    }
}

/// [Display] for [Credential] is converting its compressed elements, then to json string
#[cfg(feature = "serde_json")]
impl Display for Credential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let comp = CredentialCompressed::from(self);
        let comp_json = serde_json::to_string_pretty(&comp).unwrap();
        write!(f, "{}", comp_json)
    }
}

/// Try to take compressed elements and deserializes json string to [Credential]
#[cfg(feature = "serde_json")]
impl TryFrom<String> for Credential {
    type Error = error::Error;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        let cred_compressed: CredentialCompressed = serde_json::from_str(&s)?;
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

    if let VK::G1(vk0) = &cred.issuer_public.vk[0] {
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
                issuer_public: cred.issuer_public.clone(),
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
                z: z_tilde.into(),
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

pub mod fixtures {
    use super::*;

    /// Make test credential
    pub fn make_test_credential() -> Credential {
        let sigma = Signature {
            z: G1Projective::random(&mut rand::thread_rng()).into(),
            y_g1: G1Projective::random(&mut rand::thread_rng()).into(),
            y_hat: G2Projective::random(&mut rand::thread_rng()).into(),
            t: G1Projective::random(&mut rand::thread_rng()).into(),
        };
        let update_key = Some(vec![vec![G1Projective::random(&mut rand::thread_rng())]]);
        let commitment_vector = vec![G1Projective::random(&mut rand::thread_rng())];
        let opening_vector = vec![Scalar::random(&mut rand::thread_rng())];
        let issuer_public = IssuerPublic {
            vk: vec![VK::G1(G1Projective::random(&mut rand::thread_rng()))],
            parameters: ParamSetCommitment {
                pp_commit_g1: vec![G1Projective::random(&mut rand::thread_rng())],
                pp_commit_g2: vec![G2Projective::random(&mut rand::thread_rng())],
            },
        };
        Credential {
            sigma,
            update_key,
            commitment_vector,
            opening_vector,
            issuer_public,
        }
    }
}

//TEsts
#[cfg(test)]
mod test {

    use super::*;
    use fixtures::make_test_credential;

    #[test]
    fn test_credential_compressed_uncompress_roundtrip() {
        let cred = make_test_credential();
        let cred_compressed = CredentialCompressed::from(&cred);
        let cred_uncompressed = Credential::try_from(cred_compressed).unwrap();
        assert_eq!(cred, cred_uncompressed);
    }
}
