//! This is implementation of delegatable anonymous credential using SPSQE-UC signatures and set commitment.
//! See  the following for the details:
//! - Practical Delegatable Anonymous Credentials From Equivalence Class Signatures, PETS 2023.
//!    [https://eprint.iacr.org/2022/680](https://eprint.iacr.org/2022/680)
use super::CredentialBuilder;
use crate::ec::curve::pairing;
use crate::ec::Scalar;
use crate::entry::entry_to_scalar;
use crate::entry::{Entry, MaxEntries};
use crate::set_commits::{Commitment, CrossSetCommitment};
use crate::set_commits::{ParamSetCommitment, ParamSetCommitmentCompressed};
use crate::zkp::Nonce;
use crate::{config, error};
use crate::{
    zkp::PedersenOpen,
    zkp::Schnorr,
    zkp::{ChallengeState, DamgardTransform},
};

use anyhow::Result;
use bls12_381_plus::elliptic_curve::ops::MulByGenerator;
use bls12_381_plus::ff::Field;
use bls12_381_plus::group::{Curve, Group, GroupEncoding};
use bls12_381_plus::{
    G1Affine, G1Compressed, G1Projective, G2Affine, G2Compressed, G2Projective, Gt,
};
pub use delano_keys::vk::{VKCompressed, VK};
use rand::rngs::ThreadRng;
pub use secrecy::{ExposeSecret, Secret};
use serde_with::base64::{Base64, UrlSafe};
use serde_with::formats::Unpadded;
use serde_with::serde_as;
use spseq_uc::Credential;
use spseq_uc::UpdateError;
use std::fmt::Display;
use std::ops::Mul;
use std::ops::{Deref, Neg};
use std::str::FromStr;

pub mod spseq_uc;

/// Maximum Cardinality of an [Entry] of Attributes of an [Issuer]
/// Default is [config::DEFAULT_MAX_CARDINALITY] (currently set to 8)
#[derive(Debug, Clone, PartialEq)]
pub struct MaxCardinality(pub usize);

impl From<&usize> for MaxCardinality {
    fn from(item: &usize) -> Self {
        MaxCardinality(*item)
    }
}

impl From<usize> for MaxCardinality {
    fn from(item: usize) -> Self {
        MaxCardinality(item)
    }
}

impl From<u8> for MaxCardinality {
    fn from(item: u8) -> Self {
        MaxCardinality(item as usize)
    }
}

impl From<MaxCardinality> for usize {
    fn from(item: MaxCardinality) -> Self {
        item.0
    }
}

impl Deref for MaxCardinality {
    type Target = usize;
    fn deref(&self) -> &usize {
        &self.0
    }
}

impl Default for MaxCardinality {
    fn default() -> Self {
        MaxCardinality(config::DEFAULT_MAX_CARDINALITY)
    }
}

impl MaxCardinality {
    pub fn new(item: usize) -> Self {
        MaxCardinality(item)
    }
}

// enum Error of SerzDeserzError and TooLargeCardinality
#[derive(Debug, Clone)]
pub enum IssuerError {
    TooLargeCardinality,
    TooLongEntries,
    InvalidNymProof,
    UpdateError(String),
}

// implement `std::error::Error` for IssuerError
impl std::error::Error for IssuerError {}

// impl fmt
impl std::fmt::Display for IssuerError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            IssuerError::TooLargeCardinality => write!(f, "TooLargeCardinality. You passed too many attributes per Entry. Hint: reduce the number of attributes to be less than the max cardinality of this Issuer."),
            IssuerError::TooLongEntries => write!(f, "TooLongEntries. You passed too many Entries. Hint: reduce the number of Entries to be less than the max entries of this Issuer."),
            IssuerError::InvalidNymProof => write!(f, "InvalidNymProof. The proof of the pseudonym is invalid."),
            IssuerError::UpdateError(e) => write!(f, "UpdateError: {}", e),        }
    }
}

impl From<UpdateError> for IssuerError {
    fn from(item: UpdateError) -> Self {
        IssuerError::UpdateError(item.to_string())
    }
}

/// Root Issuer aka Certificate Authority
pub struct Issuer {
    pub public: IssuerPublic,
    sk: Secret<Vec<Scalar>>,
}

#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IssuerPublic {
    pub parameters: ParamSetCommitment,
    pub vk: Vec<VK>,
}

#[serde_as]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct IssuerPublicCompressed {
    pub parameters: ParamSetCommitmentCompressed,
    #[serde_as(as = "Vec<Base64<UrlSafe, Unpadded>>")]
    pub vk: Vec<VKCompressed>,
}

#[cfg(feature = "serde_json")]
impl ToString for IssuerPublicCompressed {
    fn to_string(&self) -> String {
        serde_json::to_string(&self).unwrap()
    }
}

/// From [IssuerPublic] to [IssuerPublicCompressed]
impl From<IssuerPublic> for IssuerPublicCompressed {
    fn from(item: IssuerPublic) -> Self {
        Self {
            parameters: item.parameters.into(),
            vk: item.vk.iter().map(|vk| vk.into()).collect::<Vec<_>>(),
        }
    }
}

/// From &[IssuerPublic] to [IssuerPublicCompressed]
impl From<&IssuerPublic> for IssuerPublicCompressed {
    fn from(item: &IssuerPublic) -> Self {
        Self {
            parameters: item.parameters.clone().into(),
            vk: item.vk.iter().map(|vk| vk.into()).collect::<Vec<_>>(),
        }
    }
}

/// TryFrom [IssuerPublicCompressed] to [IssuerPublic]
impl TryFrom<IssuerPublicCompressed> for IssuerPublic {
    type Error = String;

    fn try_from(item: IssuerPublicCompressed) -> Result<Self, Self::Error> {
        let vk = item
            .vk
            .iter()
            .map(|vk| match vk {
                VKCompressed::G1(vk) => {
                    let g1_maybe = G1Affine::from_bytes(vk);

                    if g1_maybe.is_none().into() {
                        return Err("Invalid G1 point".to_string());
                    }

                    Ok(VK::G1(
                        g1_maybe.expect("it'll be fine, it passed the check").into(),
                    ))
                }
                VKCompressed::G2(vk) => {
                    let g2 = G2Affine::from_bytes(vk);

                    if g2.is_none().into() {
                        return Err("Invalid G2 point".to_string());
                    }

                    Ok(VK::G2(
                        g2.expect("it'll be fine, it passed the check").into(),
                    ))
                }
            })
            .collect::<Result<Vec<_>, _>>()?;

        Ok(Self {
            parameters: item.parameters.try_into()?,
            vk,
        })
    }
}

impl IssuerPublic {
    /// Compacts the [VK] to a single G1 and single G2, then serilizes them to [IssuerPublicCompressed]
    pub fn to_compact(&self) -> IssuerPublicCompressed {
        let vk_b64 = self
            .vk
            .clone()
            .iter()
            .take(2)
            .map(|vk| match vk {
                VK::G1(vk) => VKCompressed::G1(vk.to_bytes()),
                VK::G2(vk) => VKCompressed::G2(vk.to_bytes()),
            })
            .collect::<Vec<_>>();

        IssuerPublicCompressed {
            vk: vk_b64,
            parameters: self.parameters.clone().into(),
        }
    }
}

/// Default Issuer using MaxCardinality and
/// MaxEntries setting from [config]
impl Default for Issuer {
    fn default() -> Self {
        Self::new(MaxCardinality::default(), MaxEntries::default())
    }
}

impl Issuer {
    /// Generates a new [Issuer] given a [MaxCardinality] and a [MaxEntries]
    ///
    /// Use this function to generate a new Issuer when you have no secret key
    pub fn new(t: MaxCardinality, l_message: MaxEntries) -> Self {
        // compute secret keys for each item in l_message
        // sk has to be at least 2 longer than l_message, to compute `list_z` in `sign()` function which adds +2
        let sk = Secret::new(
            (0..l_message.0 + 2)
                .map(|_| Scalar::random(ThreadRng::default()))
                .collect::<Vec<_>>(),
        );

        Self::new_with_secret(sk, t)
    }

    /// Generates an [Issuer] given a Vector of [Scalar]s and a [MaxCardinality]
    ///
    /// Use this function to generate a new Issuer when you have secret keys
    /// but no public parameters yet
    pub fn new_with_secret(sk: Secret<Vec<Scalar>>, t: MaxCardinality) -> Self {
        let public_parameters = ParamSetCommitment::new(&t);

        Self::new_with_params(sk, public_parameters)
    }

    /// Generates a new [Issuer] given a [Secret] and a [ParamSetCommitment]
    ///
    /// Use this function to generate a new Issuer when you have both secret keys
    /// and previously generated public parameters
    pub fn new_with_params(sk: Secret<Vec<Scalar>>, params: ParamSetCommitment) -> Self {
        let mut vk: Vec<VK> = sk
            .expose_secret()
            .iter()
            .map(|sk_i| VK::G2(G2Projective::mul_by_generator(sk_i)))
            .collect::<Vec<_>>();

        // compute X_0 keys that is used for delegation
        let x_0 = G1Projective::mul_by_generator(&sk.expose_secret()[0]);
        vk.insert(0, VK::G1(x_0)); // vk is now of length l_message + 1 (or sk + 1)

        Self {
            sk,
            public: IssuerPublic {
                parameters: params,
                vk,
            },
        }
    }

    /// Build a [Credential] using this [Issuer]
    pub fn credential(&self) -> CredentialBuilder {
        CredentialBuilder::new(self)
    }

    /// Creates a root credential to a user's pseudonym ([NymPublic]).
    pub fn issue_cred(
        &self,
        attr_vector: &[Entry],
        k_prime: Option<usize>,
        nym_proof: &NymProof,
        nonce: Option<&Nonce>,
    ) -> Result<Credential, IssuerError> {
        // check if proof of nym is correct using Damgard’s technique for obtaining malicious verifier
        // interactive zero-knowledge proofs of knowledge
        if !DamgardTransform::verify(nym_proof, nonce) {
            return Err(IssuerError::InvalidNymProof);
        }
        // check if delegate keys is provided
        let cred = self.sign(&nym_proof.public_key, attr_vector, k_prime)?;
        assert!(verify(
            &self.public.vk,
            &nym_proof.public_key,
            &cred.commitment_vector,
            &cred.sigma
        ));
        Ok(cred)
    }

    /// Generates a signature for the commitment and related opening information along with update key.
    /// # Arguments
    /// pk_u: user public key
    /// messages_vector: vector of messages
    /// k_prime: index defining max number of Entry(s) up to which delegatees can add
    ///
    /// # Returns
    /// signature, opening information, update key
    fn sign(
        &self,
        pk_u: &G1Projective,
        messages_vector: &[Entry],
        k_prime: Option<usize>,
    ) -> Result<Credential, IssuerError> {
        // Validate that the Cardinality is within the bounds of the public parameters
        // if not, return a Too Large Cardinality Error
        // ensure each element in messages_vector is less than self.public.parameters.pp_commit_g1.len()
        if messages_vector
            .iter()
            .any(|mess| mess.len() > self.public.parameters.pp_commit_g1.len())
        {
            return Err(IssuerError::TooLargeCardinality);
        }

        // Too long entries if messages_vector.len() > Issuer vk - 2
        // because Issuer vk has 2 more elements than messages_vector
        if messages_vector.len() >= self.public.vk.len() - 2 {
            return Err(IssuerError::TooLongEntries);
        }

        // Generate commitments for all messagse sets of the messages vector as set commitments
        let (commitment_vector, opening_vector): (Vec<G1Projective>, Vec<Scalar>) = messages_vector
            .iter()
            .map(|mess| CrossSetCommitment::commit_set(&self.public.parameters, mess))
            .collect::<Vec<_>>()
            .into_iter()
            .unzip();

        // pick randomness for y_g1
        let y_rand = Scalar::random(ThreadRng::default());

        // compute sign -> sigma = (Z, Y, hat Ym t)
        let list_z = commitment_vector
            .iter()
            .enumerate()
            .map(|(i, c)| c * self.sk.expose_secret()[i + 2])
            .collect::<Vec<_>>();

        // temp_point = sum of all ec points in list_Z
        let temp_point = list_z
            .iter()
            .fold(G1Projective::identity(), |acc, x| acc + x);

        // Z is y_rand mod_inverse(order) times temp_point
        let z = y_rand.invert().unwrap() * temp_point;

        // Y = y_rand * g_1
        let y_g1 = G1Projective::mul_by_generator(&y_rand);

        // Y_hat = y_rand * g_2
        let y_hat = G2Projective::mul_by_generator(&y_rand);

        // t = sk[1] * Y + sk[0] * pk_u
        let t = y_g1 * self.sk.expose_secret()[1] + pk_u * self.sk.expose_secret()[0];

        let sigma = Signature { z, y_g1, y_hat, t };

        // check if the update key is requested
        // then compute update key using k_prime,
        // otherwise compute signature without it
        let mut update_key = None;
        if let Some(k_prime) = k_prime {
            if k_prime > messages_vector.len() {
                // k_prime upper bounds: ensure k_prime is at most sk.len() - 2, which is l_message length from sign_keygen()
                let k_prime = k_prime.min(self.sk.expose_secret().len() - 2);

                let mut usign = Vec::new();
                usign.resize(k_prime, Vec::new()); // update_key is k < k' < l, same length as l_message.length, which is same as sk

                // only valid keys are between commitment length (k) an length (l), k_prime.length = k < k' < l
                for k in (messages_vector.len() + 1)..=k_prime {
                    let mut uk = Vec::new();
                    for i in 0..self.public.parameters.pp_commit_g1.len() {
                        let uk_i = self.public.parameters.pp_commit_g1[i]
                            * y_rand.invert().unwrap()
                            * self.sk.expose_secret()[k + 1]; // this is `k + 1` because sk[0] and sk[1] are used for t
                        uk.push(uk_i);
                    }
                    usign[k - 1] = uk; // first element is index 0 (message m is index m-1)
                }
                update_key = Some(usign);

                return Ok(Credential {
                    sigma,
                    update_key,
                    commitment_vector,
                    opening_vector,
                    issuer_public: self.public.clone(),
                });
            }
            // k_prime of equal or lesser value than current message length has no effect
            // since the whole point of k_prime is to extend the message length!
        }

        Ok(Credential {
            sigma,
            update_key,
            commitment_vector,
            opening_vector,
            issuer_public: self.public.clone(),
        })
    }
}

/// Verifies a [Signature] for a given message set against a [VK] verification key
/// # Arguments
/// - `vk`: [VK] verification key
/// - `pk_u`: [G1] user public key
/// - `commitment_vector`: &[G1] vector of commitments
/// - `sigma`: &[Signature]
pub fn verify(
    vk: &[VK],
    pk_u: &G1Projective,
    commitment_vector: &[G1Projective],
    sigma: &Signature,
) -> bool {
    let g_1 = &G1Projective::GENERATOR;
    let g_2 = &G2Projective::GENERATOR;
    let Signature { z, y_g1, y_hat, t } = sigma;

    let pairing_op = commitment_vector
        .iter()
        .zip(vk.iter().skip(3))
        .map(|(c, vkj3)| {
            if let VK::G2(vkj3) = vkj3 {
                pairing(c, vkj3)
            } else {
                panic!("Invalid verification key");
            }
        })
        .collect::<Vec<_>>();

    if let VK::G2(vk2) = &vk[2] {
        if let VK::G2(vk1) = &vk[1] {
            let a = pairing(y_g1, g_2) == pairing(g_1, y_hat);
            let b = pairing(t, g_2) == pairing(y_g1, vk2) * pairing(pk_u, vk1);
            let c = pairing(z, y_hat) == pairing_op.iter().fold(Gt::IDENTITY, Gt::mul);
            a && b && c
        } else {
            panic!("Invalid verification key");
        }
    } else {
        panic!("Invalid verification key");
    }
}

/// This struct allows the [Initial] [Nym] to be deterministic, in order to easily manage keys. For
/// use of [Credential]s, [Nym]s are [Randomized] with the `randomize` function to ensure anonymity.
pub struct Initial;
/// This struct ensures that only (pseudo)[Nym]s which have been randomized can be used in `issue`
/// credential, `offer` and `prove` functions.
pub struct Randomized;

/// Nym which holds secret and public information about the user.
/// - `secret`: [`Secret`]<[`Scalar`]>, secret witness of the user
/// - pub `public`: [`NymPublic`], proof of the user
pub struct Nym<Stage> {
    secret: Secret<Scalar>,
    pub public: NymPublic,
    stage: std::marker::PhantomData<Stage>,
}

/// Pseudonym Public information
/// - `proof`: [`NymProof`], proof of the user
/// - `damgard`: [`DamgardTransform`], damgard transform of the user
/// - `public_parameters`: [`ParamSetCommitment`], public parameters of the user
#[derive(Clone)]
pub struct NymPublic {
    /// [DamgardTransform] is used to generate the [NymProof]
    pub damgard: DamgardTransform,
    /// [G1Projective] Public key for this [Nym]
    pub key: G1Projective,
}

/// NymProof
/// - `challenge`: Challenge, challenge of the user
/// - `pedersen_open`: PedersenOpen, opening information of the user
/// - `pedersen_commit`: G1, commitment of the user th
/// - `public_key`: RandomizedPubKey, public key of the Nym
/// - `response`: Scalar, response of the user
#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct NymProof {
    /// [Scalar] is used to generate the [NymProof]
    pub challenge: Scalar,
    /// [PedersenOpen] is used to open the [NymProof] Pedersen Commitment
    pub pedersen_open: PedersenOpen,
    /// The [G1Projective] Pedersen Commitment of the [NymProof]
    pub pedersen_commit: G1Projective,
    /// [G1Projective] Public key for this [Nym]
    pub public_key: G1Projective,
    /// [Scalar] response of the [NymProof]
    pub response: Scalar,
    /// [DamgardTransform] is used to annouce the [crate::zkp::PedersenCommit] and [PedersenOpen],
    /// all of which are needed to verify this proof
    pub damgard: DamgardTransform,
}

impl<Stage> Nym<Stage> {
    /// Derive a [Nym] from a given secret that references a big endien 32 byte array which [Zeroize]s it's
    /// memory after dropping
    fn new_from_secret(secret_bytes: Secret<Scalar>) -> Nym<Stage> {
        let key = G1Projective::mul_by_generator(secret_bytes.expose_secret());
        Nym::<Stage> {
            stage: std::marker::PhantomData,
            secret: secret_bytes,
            public: NymPublic {
                damgard: DamgardTransform::new(),
                key,
            },
        }
    }

    /// Generates a pseudonym for the user.
    /// RndmzPK(pku, ψ, χ) → pk_u from the paper.
    pub fn randomize(&self) -> Nym<Randomized> {
        // pick randomness, ψ
        let psi = Scalar::random(ThreadRng::default());
        // pick randomness, χ
        let chi = Scalar::random(ThreadRng::default());

        let secret_wit = Secret::new((self.secret.expose_secret() + chi) * psi);

        Nym::new_from_secret(secret_wit)
    }
    /// Creates an [super::OfferBuilder] for a [Credential] using this [Nym]
    ///
    /// # Arguments
    /// - `cred`: [Credential], credential being offered to the delegatee
    /// - `entries`: &[Entry], vector of all attribute [Entry]s corresponding to the `cred`
    ///
    /// # Returns
    /// [super::OfferBuilder]
    pub fn offer_builder<'a>(
        &'a self,
        cred: &'a Credential,
        entries: &[Entry],
    ) -> super::OfferBuilder<Stage> {
        super::OfferBuilder::new(self, cred, entries)
    }

    /// Create a [super::ProofBuilder] for a [Credential] and [Entry]s using this [Nym]
    ///
    /// # Arguments
    ///
    /// - `cred`: [Credential], credential being proven
    /// - `entries`: &[Entry], vector of all attribute [Entry]s corresponding to the `cred`
    pub fn proof_builder<'a>(
        &'a self,
        cred: &'a Credential,
        entries: &'a [Entry],
    ) -> super::ProofBuilder<Stage> {
        super::ProofBuilder::new(self, cred, entries)
    }

    /// Creates an orphan [Offer] for a [Credential]. This function will also validate the given
    /// [NymProof] is valid, but does not associate/link this offer with that [Nym] (see note below).
    ///
    /// Important Note: The orphan [Signature] created by this [Offer] can be used by
    /// any holder who also has possesion of the associated [crate::attributes::Attribute]s,
    /// so it is important to either keep [Offer]s confidential or disassociated
    /// with the [crate::attributes::Attribute]s. In other words, do not make both pubically available and associated;
    /// do not store them in the same place or object, unless it is with the intended Holder.
    pub fn offer(
        &self,
        cred: &Credential,
        addl_attrs: &Option<Entry>,
    ) -> Result<Offer, error::Error> {
        // Before we offer the Credential, change the Representative so we stay anonymous
        // This differs slightly from the reference Python implementation which
        // runs `change_rep` algorithm upon `accept()` protocol (they call it `delegatee()` function)
        // We make this change because we want to change the rep before we offer the credential to someone else
        // as opposed to changing it before we accept it for ourselves.

        // `mu` has to be `Scalar::ONE` here because it can only be randomized _once_,
        // which is during the prove() function
        // mu randomizes the commitment vector. Setting it to ONE means the commitment vector is not randomized
        let mu = Scalar::ONE;
        // pick randomness psi.
        let psi = Scalar::random(ThreadRng::default());

        let (nym_p_pk, cred_prime, chi) =
            spseq_uc::change_rep(&self.public.key, cred, &mu, &psi, true);

        // Since we changed the Nym Rep above, we need to use the new Nym (instead of self)
        // to send the convert signal.
        // So create new Nym with the new rep (`nym_p`) and the new nym_p secret_wit
        let nym = Nym::from_components(&self.secret, Chi(chi), Psi(psi));

        let mut cred_prime = cred_prime;
        if let Some(addl_attrs) = addl_attrs {
            // Note: change_rel does NOT change Signature { t, ..}
            cred_prime = match spseq_uc::change_rel(
                &cred.issuer_public.parameters,
                addl_attrs,
                cred_prime.clone(),
                &mu,
            ) {
                Ok(cred_pushed) => cred_pushed,
                Err(e) => {
                    return Err(error::Error::ChangeRelationsFailed(format!(
                        "Change Relations Failed: {}",
                        e
                    )))
                }
            };
        }

        // Credential Signature is now for the new Nym
        if !verify(
            &cred_prime.issuer_public.vk,
            &nym_p_pk,
            &cred_prime.commitment_vector,
            &cred_prime.sigma,
        ) {
            return Err(error::Error::InvalidSignature(
                "Credential Signature is not valid for the new Nym".into(),
            ));
        }

        // negate Signature { t, ..} with nym.secret
        let orphan = nym.send_convert_sig(&cred_prime.issuer_public.vk, cred_prime.sigma.clone());

        Ok(Offer(Credential {
            sigma: orphan,
            ..cred_prime
        }))
    }

    /// Accept the credential and adapt [Signature] back to Self.
    ///
    /// Delegated User (delegatee) uses this function to assign to their pseudonym.
    ///
    /// # Arguments
    /// - `offer`: [Offer], credential received from delegator
    ///
    /// # Returns
    /// [Credential] with the new [Signature] for the our [Nym]'s public key
    pub fn accept(
        &self,
        offer: &Offer, // credential got from delegator
    ) -> Result<Credential, crate::error::Error> {
        let sigma_new = self.receive_cred(&offer.issuer_public.vk, offer.sigma.clone())?;

        // verify the signature of the credential first
        if !verify(
            &offer.issuer_public.vk,
            &self.public.key,
            &offer.commitment_vector,
            &sigma_new,
        ) {
            return Err(error::Error::AcceptOfferFailed(String::from(
                "Invalid Signature",
            )));
        }

        Ok(Credential {
            sigma: sigma_new,
            ..offer.clone().into()
        })
    }

    /// Receive Converted Signature
    ///
    /// On input a temporary (orphan) sigma [Signature] and returns a new signature for the new public key.
    ///
    /// # Arguments
    ///
    /// - `vk`: [VK] Verification Key
    /// - `orphan`: [Signature] {Z, Y, Y_hat, t}
    ///
    /// # Returns
    /// New [Signature] for the new public key
    fn receive_cred(&self, vk: &[VK], mut orphan: Signature) -> Result<Signature, error::Error> {
        match &vk[0] {
            VK::G1(vk0) => {
                orphan.t += vk0 * self.secret.expose_secret();
                Ok(orphan)
            }
            _ => Err(error::Error::InvalidVerificationKey {
                expected: String::from("G1"),
                found: String::from("G2"),
            }),
        }
    }

    /// Prove selected [crate::attributes::Attribute]s for a [Credential], given all [Entry]s
    ///
    /// If a selected [Entry] is empty, it is skipped (not proven) and there is no need to provide any of the corresponding
    /// full/complete [Entry] as `prove()` filters out any selected [Entry]s which are empty and excludes them from the proof.
    ///
    /// ## Arguments
    /// - `cred`: &[Credential], credential of the user
    /// - `all_attributes`: &[Entry], vector of complete attribute [Entry]s of the user corresponding to the selected attributes
    /// - `selected_attrs`: &[Entry], vector of selected attribute [Entry]s to be disclosed
    pub fn prove(
        &self,
        cred: &Credential,
        all_attributes: &[Entry],
        selected_attrs: &[Entry],
        nonce: &Nonce,
    ) -> CredProof {
        // mu can be random here since `prove` is the last step in the Cred process.
        let mu = Scalar::random(ThreadRng::default());
        let psi = Scalar::random(ThreadRng::default());

        // run change rep to randomize credential and user pk (i.e., create a new nym)
        // vk: &[VK], pk_u: &G1, orig_sig: &EqcSignature, mu: &Scalar, psi: &Scalar, b: bool
        // No need to update or reveal the update_key for a proof (only needed for delegation)
        let (_nym_p, cred_p, chi) = spseq_uc::change_rep(&self.public.key, cred, &mu, &psi, false);

        // update aux_r with chi and psi
        // let secret_wit = Secret::new((self.secret.expose_secret() + chi) * psi);
        let nym: Nym<Randomized> = Nym::from_components(&self.secret, Chi(chi), Psi(psi));

        let (witness_vector, commit_vector) = selected_attrs
            .iter()
            .enumerate()
            .filter(|(_, selected_attr)| !selected_attr.is_empty()) // filter out selected_attrs which is_empty()
            .fold(
                (Vec::new(), Vec::new()),
                |(mut witness, mut commitment_vectors), (i, selected_attr)| {
                    if let Some(opened) = CrossSetCommitment::open_subset(
                        &cred.issuer_public.parameters,
                        &all_attributes[i],
                        &cred_p.opening_vector[i],
                        selected_attr,
                    ) {
                        witness.push(opened); //can only have as many witnesses as there are openable selected attributes
                        commitment_vectors.push(cred_p.commitment_vector[i]);
                        // needs to be the same length as the witness vector
                    }
                    (witness, commitment_vectors)
                },
            );

        let witness_pi = CrossSetCommitment::aggregate_cross(&witness_vector, &commit_vector);

        CredProof {
            sigma: cred_p.sigma,
            commitment_vector: cred_p.commitment_vector,
            witness_pi,
            nym_proof: nym.nym_proof(nonce),
        }
    }
}

impl Default for Nym<Randomized> {
    fn default() -> Self {
        Self::new()
    }
}

/// Chi Scalar newtype wrapper to disambiguate between scalars
struct Chi(Scalar);

impl Deref for Chi {
    type Target = Scalar;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// Psi Scalar newtype wrapper to disambiguate between scalars
struct Psi(Scalar);

impl Deref for Psi {
    type Target = Scalar;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// Deterministic [Nym]s are only [Initial] nyms that can `accept` a [Credential] but are [Randomized] before `offer` or `prove` a Credential Claim
impl Nym<Initial> {
    /// New from secret can be public for [Initial] Nym
    pub fn from_secret(secret_bytes: Secret<Scalar>) -> Self {
        Nym::new_from_secret(secret_bytes)
    }
}

/// Convert signals and proofs should only ever be generated by a [Randomized] [Nym] to keep identity anonymous.
impl Nym<Randomized> {
    /// Create a new [Nym] with a random secret key and a public key
    pub fn new() -> Self {
        let secret = Secret::new(Scalar::random(ThreadRng::default()));
        Nym::new_from_secret(secret)
    }

    /// Internal function used to build a Randomized Nym from a Initial Nym
    fn from_components(secret: &Secret<Scalar>, chi: Chi, psi: Psi) -> Self {
        let secret_wit = Secret::new((secret.expose_secret() + (*chi)) * (*psi));
        Nym::new_from_secret(secret_wit)
    }

    /// Delegate by Converting a Signature.
    /// It is an algorithm run by a user who wants to delegate a
    /// signature σ. It takes as input the public verification key vk, a secret key sku and the signature.
    /// It outputs an orphan signature σ. Creates a temporary (orphan) signature
    /// used by the delegatee to finish converting the signature.
    ///
    /// # Arguments
    /// - `vk`: [VK] Verification Key
    /// - `sigma`:  [Signature] Sigma {Z, Y, Y_hat, t}
    ///
    /// # Returns
    /// Temporary orphan signature
    fn send_convert_sig(&self, vk: &[VK], mut sigma: Signature) -> Signature {
        // let Signature { z, y_g1, y_hat, t } = sigma;

        // update component t of signature to remove the old key
        if let VK::G1(vk0) = &vk[0] {
            sigma.t += (vk0 * self.secret.expose_secret()).neg();
            sigma
        } else {
            panic!("Invalid verification key"); // TODO: Remove panics, switch to Result
        }
    }

    /// Create a proof using Damgard's technique for obtaining malicious verifier interactive zero-knowledge proofs of knowledge
    ///
    /// This enables us to obtain malicious verifier interactive zero-knowledge proofs of
    /// knowledge. Verifiers can optionally provide a nonce to the proof, which will be
    /// used to generate the challenge. If no nonce is provided, a random nonce will be
    /// generated. This nonce can be checked against the Pedersen open randomness to
    /// ensure the proof is valid.
    pub fn nym_proof(&self, nonce: &Nonce) -> NymProof {
        let (pedersen_commit, pedersen_open) = self.public.damgard.announce(nonce);

        let state = ChallengeState::new(
            vec![self.public.damgard.pedersen.h.to_affine()],
            &pedersen_commit.to_bytes(),
        );

        let challenge = DamgardTransform::challenge(&state);

        // (challenge: &Challenge, announce_randomness: &Scalar, stm: &G2, secret_wit: &Scalar)
        let response = DamgardTransform::response(
            &challenge,
            &pedersen_open.announce_randomness,
            &self.public.key.into(),
            &self.secret,
        );

        NymProof {
            challenge,
            pedersen_open,
            pedersen_commit,
            public_key: self.public.key,
            response,
            damgard: self.public.damgard.clone(),
        }
    }
}

/// SPSEQ-UC sigma [Signature] of a [Credential]
/// - `z`: The inverse of the sum of all the commitments in the commitment vector
/// - `y_g1`: The public key of the user
/// - `y_hat`: The public key of the user
/// - `t`: The signature of the user
#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Signature {
    z: G1Projective,
    y_g1: G1Projective,
    y_hat: G2Projective,
    t: G1Projective,
}

/// [Display] for [Signature] is converting it to [SignatureCompressed] then to json string
impl Display for Signature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let sig_compressed = SignatureCompressed::from(self.clone());
        let sig_json = serde_json::to_string(&sig_compressed).unwrap();
        write!(f, "{}", sig_json)
    }
}

/// Uses [SignatureCompressed] to deserialize json string to [Signature]
impl FromStr for Signature {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let sig_compressed: SignatureCompressed = serde_json::from_str(s).unwrap();
        Signature::try_from(sig_compressed)
    }
}

/// [SignatureCompressed] is a compressed version of [Signature]
#[serde_as]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct SignatureCompressed {
    #[serde_as(as = "Base64<UrlSafe, Unpadded>")]
    z: G1Compressed,
    #[serde_as(as = "Base64<UrlSafe, Unpadded>")]
    y_g1: G1Compressed,
    #[serde_as(as = "Base64<UrlSafe, Unpadded>")]
    y_hat: G2Compressed,
    #[serde_as(as = "Base64<UrlSafe, Unpadded>")]
    t: G1Compressed,
}

/// To convert a [Signature] to a [SignatureCompressed]
impl From<Signature> for SignatureCompressed {
    fn from(sig: Signature) -> Self {
        SignatureCompressed {
            z: sig.z.to_bytes(),
            y_g1: sig.y_g1.to_bytes(),
            y_hat: sig.y_hat.to_bytes(),
            t: sig.t.to_bytes(),
        }
    }
}

/// Impl TryFrom for SignatureCompressed to Signature
impl TryFrom<SignatureCompressed> for Signature {
    type Error = String;

    fn try_from(sig: SignatureCompressed) -> Result<Self, Self::Error> {
        let z = G1Projective::from_bytes(&sig.z);
        let y_g1 = G1Projective::from_bytes(&sig.y_g1);
        let y_hat = G2Projective::from_bytes(&sig.y_hat);
        let t = G1Projective::from_bytes(&sig.t);

        if z.is_none().into()
            || y_g1.is_none().into()
            || y_hat.is_none().into()
            || t.is_none().into()
        {
            return Err("Invalid serialization bytes".into());
        }

        Ok(Signature {
            z: z.unwrap(),
            y_g1: y_g1.unwrap(),
            y_hat: y_hat.unwrap(),
            t: t.unwrap(),
        })
    }
}

/// Newtype wrapper for a [Credential] which has an orphan [Signature]
#[derive(Clone, Debug)]
pub struct Offer(Credential);

impl Deref for Offer {
    type Target = Credential;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// Implement [From]<[Credential]> for [Offer]
impl From<Credential> for Offer {
    fn from(cred: Credential) -> Self {
        Offer(cred)
    }
}

impl From<Offer> for Credential {
    fn from(offer: Offer) -> Self {
        offer.0
    }
}

/// Credentials Proof, struct which holds all the information needed to verify a [Credential]
///
/// # Arguments
/// - `sigma`: [`Signature`], signature of the user
/// - `commitment_vector`: Vec<[`G1`]>, commitment vector of the user
/// - `witness_pi`: [`G1`], witness of the user
/// - `nym_public`: [`NymPublic`], proof of the pseudonym
pub struct CredProof {
    sigma: Signature,
    commitment_vector: Vec<G1Projective>,
    witness_pi: G1Projective,
    nym_proof: NymProof,
}

/// Verify a proof of a [CredProof] against [IssuerPublic] and selected [Entry]s
pub fn verify_proof(
    issuer_public: &IssuerPublic,
    proof: &CredProof,
    selected_attrs: &[Entry],
    nonce: Option<&Nonce>,
) -> Result<bool, IssuerError> {
    // Get the selected_attr indexes which are not `is_enpty()`,
    // use those indexes to select corresponding `commitment_vectors`
    // zip together `commitment_vector` where `selected_attr` is not empty
    let commitment_vectors = proof
        .commitment_vector
        .iter()
        .zip(selected_attrs.iter())
        .filter(|(_, selected_attr)| !selected_attr.is_empty())
        .map(|(commitment_vector, _)| *commitment_vector)
        .collect::<Vec<_>>();

    // check the proof is valid for each
    let check_verify_cross = CrossSetCommitment::verify_cross(
        &issuer_public.parameters,
        &commitment_vectors,
        selected_attrs,
        &proof.witness_pi,
    );

    let check_zkp_verify = DamgardTransform::verify(&proof.nym_proof, nonce);

    // signature is based on the original commitment vector. Unless we adapt it when the restriction is applied
    let verify_sig = verify(
        &issuer_public.vk,
        &proof.nym_proof.public_key,
        &proof.commitment_vector,
        &proof.sigma,
    );

    // assert both check_verify_cross and check_zkp_verify are true && spseq_uc.verify
    Ok(check_verify_cross && check_zkp_verify && verify_sig)
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::attributes::{attribute, Attribute};

    lazy_static::lazy_static! {
        static ref NONCE: Nonce = Nonce::default();
    }

    fn init() {
        let _ = env_logger::builder().is_test(true).try_init();

        if log::log_enabled!(log::Level::Debug) {
            log::error!("Debug logging enabled");
        }
    }

    struct TestMessages {
        message1_str: Vec<Attribute>,
        message2_str: Vec<Attribute>,
        message3_str: Vec<Attribute>,
    }

    // make a setup fn that generates message_strs
    fn setup_tests() -> TestMessages {
        let age = attribute("age = 30");
        let name = attribute("name = Alice ");
        let drivers = attribute("driver license = 12");
        let gender = attribute("gender = male");
        let company = attribute("company = ACME");
        let insurance = attribute("Insurance = 2");
        let car_type = attribute("Car type = BMW");

        let message1_str = vec![age, name];

        let message2_str = vec![gender, company, drivers];
        let message3_str = vec![insurance, car_type];

        TestMessages {
            message1_str,
            message2_str,
            message3_str,
        }
    }

    #[test]
    fn test_sign() -> Result<(), IssuerError> {
        let issuer = Issuer::new(MaxCardinality::new(5), MaxEntries::new(10));

        // create a user key
        let user = Nym::new();

        // get some test entries
        let messages_vectors = setup_tests();

        // create a signature
        let cred = issuer.sign(
            &user.public.key,
            &[
                Entry(messages_vectors.message1_str),
                Entry(messages_vectors.message2_str),
            ],
            None,
        )?;

        assert!(verify(
            &issuer.public.vk,
            &user.public.key,
            &cred.commitment_vector,
            &cred.sigma
        ));
        Ok(())
    }

    #[test]
    fn test_signature_roundtrip_convert_compressed() {
        let issuer = Issuer::new(MaxCardinality::new(5), MaxEntries::new(10));

        // create a user key
        let user = Nym::new();

        // get some test entries
        let messages_vectors = setup_tests();

        // create a signature
        let cred = issuer
            .sign(
                &user.public.key,
                &[
                    Entry(messages_vectors.message1_str),
                    Entry(messages_vectors.message2_str),
                ],
                None,
            )
            .unwrap();

        let sig_compressed = SignatureCompressed::from(cred.sigma.clone());
        let sig_json = serde_json::to_string(&sig_compressed).unwrap();
        let sig_compressed2: SignatureCompressed = serde_json::from_str(&sig_json).unwrap();
        let sig2 = Signature::try_from(sig_compressed2).unwrap();

        assert_eq!(cred.sigma, sig2);
    }

    #[test]
    fn test_sign_too_large_cardinality_error() {
        let issuer = Issuer::new(MaxCardinality::new(1), MaxEntries::new(10));

        // create a user key
        let user = Nym::new();

        // get some test entries
        let messages_vectors = setup_tests();

        // create a signature
        let cred = issuer.sign(
            &user.public.key,
            &[
                Entry(messages_vectors.message1_str),
                Entry(messages_vectors.message2_str),
                Entry(messages_vectors.message3_str),
            ],
            None,
        );

        assert!(cred.is_err());
    }

    #[test]
    fn test_sign_too_large_entries_error() {
        let issuer = Issuer::new(MaxCardinality::new(5), MaxEntries::new(2));

        // create a user key
        let user = Nym::new();

        // get some test entries
        let messages_vectors = setup_tests();

        // create a Entry vector 1 larger than allowed
        let cred = issuer.sign(
            &user.public.key,
            &[
                Entry(messages_vectors.message1_str),
                Entry(messages_vectors.message2_str),
                Entry(messages_vectors.message3_str),
            ],
            None,
        );

        assert!(cred.is_err());
    }

    // test signing an empty message vector
    #[test]
    fn test_sign_empty_message_vector() {
        let issuer = Issuer::default();

        // create a user key
        let user = Nym::new();

        // create a signature
        let cred = issuer.sign(&user.public.key, &[], None);

        assert!(cred.is_ok());
    }

    // Generate a signature, run changrep function and verify it
    #[test]
    fn test_changerep() -> Result<(), IssuerError> {
        // Issuer with 5 and 10
        let issuer = Issuer::new(MaxCardinality::new(5), MaxEntries::new(10));

        // create a user key
        let user = Nym::new();

        // get some test entries
        let messages_vectors = setup_tests();

        // create a signature
        let k_prime = Some(4);
        let signature_original = issuer.sign(
            &user.public.key,
            &[
                Entry(messages_vectors.message1_str),
                Entry(messages_vectors.message2_str),
            ],
            k_prime,
        )?;

        // run changerep function (without randomizing update_key) to
        // randomize the sign, pk_u and commitment vector
        let updatable = false;
        let mu = Scalar::random(ThreadRng::default());
        let psi = Scalar::random(ThreadRng::default());

        let (rndmz_pk_u, signature, _chi) =
            spseq_uc::change_rep(&user.public.key, &signature_original, &mu, &psi, updatable);

        assert!(verify(
            &issuer.public.vk,
            &rndmz_pk_u,
            &signature.commitment_vector,
            &signature.sigma
        ));

        Ok(())
    }

    /// Generate a signature, run changrep function using update_key, randomize update_key (uk) and verify it
    /// This test is similar to test_changerep, but it randomizes the update_key
    /// and verifies the signature using the randomized update_key
    #[test]
    fn test_changerep_update_key() -> Result<(), IssuerError> {
        // Issuer with 5 and 10
        let issuer = Issuer::new(MaxCardinality::new(5), MaxEntries::new(10));

        // create a user key
        let user = Nym::new();

        // get some test entries
        let messages_vectors = setup_tests();

        // create a signature
        let k_prime = Some(4);
        let signature_original = issuer.sign(
            &user.public.key,
            &[
                Entry(messages_vectors.message1_str),
                Entry(messages_vectors.message2_str),
            ],
            k_prime,
        )?;

        // run changerep function (with randomizing update_key) to
        // randomize the sign, pk_u and commitment vector
        let updatable = true;
        let mu = Scalar::random(ThreadRng::default());
        let psi = Scalar::random(ThreadRng::default());

        let (rndmz_pk_u, signature, _chi) =
            spseq_uc::change_rep(&user.public.key, &signature_original, &mu, &psi, updatable);

        assert!(verify(
            &issuer.public.vk,
            &rndmz_pk_u,
            &signature.commitment_vector,
            &signature.sigma
        ));

        Ok(())
    }

    /// Generate a signature, run changrel function one the signature, add one additional commitment using update_key (uk) and verify it
    /// This test is similar to test_changerep_uk, but it adds one additional commitment to the signature
    #[test]
    fn test_change_rel_from_sign() -> Result<(), IssuerError> {
        // Generate a signature, run changrel function one the signature, add one additional commitment using update_key (uk) and verify it

        // Issuer with 5 and 10
        let issuer = Issuer::new(MaxCardinality::new(5), MaxEntries::new(10));

        // create a user key
        let nym = Nym::new();

        // get some test entries
        let messages_vectors = setup_tests();

        // create a signature
        let k_prime = 3;
        let messages_vector = &vec![
            Entry(messages_vectors.message1_str),
            Entry(messages_vectors.message2_str),
        ];
        let signature_original = issuer.sign(&nym.public.key, messages_vector, Some(k_prime))?;

        // assrt that signature has update_key of length k_prime
        // how to convert a usize to integer:
        // convert an integer to usize using as_usize() method
        assert_eq!(
            signature_original
                .update_key
                .as_ref()
                .expect("There to be an update key")
                .len(),
            k_prime
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

        for k in messages_vector.len()..k_prime {
            assert_ne!(
                signature_original
                    .update_key
                    .as_ref()
                    .expect("There to be an update key")[k],
                Vec::new()
            );
        }

        // run changerel function (with update_key) to add commitment C3 (for message3_str) to the sign where index L = 3
        let message_l = Entry(messages_vectors.message3_str);
        // µ ∈ Zp means that µ is a random element in Zp. Zp is the set of integers modulo p.
        // mu is only not a one() when chage_rep has been immediately called before using the same mu
        let mu = Scalar::ONE;

        let signature_changed = spseq_uc::change_rel(
            &issuer.public.parameters,
            &message_l,
            signature_original,
            &mu,
        )?;

        // assert!(sign_scheme.verify(&vk, &pk_u, &cred_chged.commitment_vector, &cred_chged.sigma));
        assert!(verify(
            &issuer.public.vk,
            &nym.public.key,
            &signature_changed.commitment_vector,
            &signature_changed.sigma
        ));

        Ok(())
    }

    /// run changrel on the signature that is coming from changerep (that is already randomized) and verify it
    #[test]
    fn test_change_rel_from_rep() -> Result<()> {
        // Issuer with 5 and 10
        let issuer = Issuer::new(MaxCardinality::new(5), MaxEntries::new(10));

        // create a user key
        let nym = Nym::new();

        // get some test entries
        let messages_vectors = setup_tests();

        // create a signature
        let k_prime = Some(4);
        let messages_vector = &vec![
            Entry(messages_vectors.message1_str),
            Entry(messages_vectors.message2_str),
        ];
        let signature_original = issuer.sign(&nym.public.key, messages_vector, k_prime)?;

        // run changerep function (with randomizing update_key) to
        // randomize the sign, pk_u and commitment vector
        let updatable = true;
        let mu = Scalar::random(ThreadRng::default());
        let psi = Scalar::random(ThreadRng::default());

        let (rndmz_pk_u, signature_prime, _chi) =
            spseq_uc::change_rep(&nym.public.key, &signature_original, &mu, &psi, updatable);

        // verify the signature_prime
        assert!(verify(
            &issuer.public.vk,
            &rndmz_pk_u,
            &signature_prime.commitment_vector,
            &signature_prime.sigma
        ));

        // change_rel
        let message_l = Entry(messages_vectors.message3_str);
        let cred_tilde =
            spseq_uc::change_rel(&issuer.public.parameters, &message_l, signature_prime, &mu)?;

        // verify the signature
        assert!(verify(
            &issuer.public.vk,
            &rndmz_pk_u,
            &cred_tilde.commitment_vector,
            &cred_tilde.sigma
        ));

        Ok(())
    }

    /// run changrel on the signature that is coming from changerep (that is already randomized) and verify it
    #[test]
    fn test_change_rel_from_rep_rep() -> Result<()> {
        // Issuer with 5 and 10
        let issuer = Issuer::new(MaxCardinality::new(5), MaxEntries::new(10));

        // create a user key
        let nym = Nym::new();

        // get some test entries
        let messages_vectors = setup_tests();
        let message_l = Entry(messages_vectors.message3_str);

        // create a signature
        let k_prime = Some(8);
        let messages_vector = &vec![
            Entry(messages_vectors.message1_str),
            Entry(messages_vectors.message2_str),
        ];
        let cred = issuer.sign(&nym.public.key, messages_vector, k_prime)?;

        // run changerep function (with randomizing update_key) to
        // randomize the sign, pk_u and commitment vector
        let mu = Scalar::ONE;
        let psi = Scalar::random(ThreadRng::default());
        let (rndmz_pk_u, cred_r, _chi) =
            spseq_uc::change_rep(&nym.public.key, &cred, &mu, &psi, true);

        // verify the signature_prime
        assert!(verify(
            &cred_r.issuer_public.vk,
            &rndmz_pk_u,
            &cred_r.commitment_vector,
            &cred_r.sigma
        ));

        let mu = Scalar::random(ThreadRng::default()); // only works the second time if the first is mu = one()
        let psi = Scalar::random(ThreadRng::default());
        let (rndmz_pk_u, cred_r, _chi) =
            spseq_uc::change_rep(&rndmz_pk_u, &cred_r, &mu, &psi, true);

        // verify the signature_prime
        assert!(verify(
            &cred_r.issuer_public.vk,
            &rndmz_pk_u,
            &cred_r.commitment_vector,
            &cred_r.sigma
        ));

        // change_rel
        let cred_rel =
            spseq_uc::change_rel(&issuer.public.parameters, &message_l, cred_r, &mu).unwrap();

        // verify the signature
        assert!(verify(
            &cred_rel.issuer_public.vk,
            &rndmz_pk_u,
            &cred_rel.commitment_vector,
            &cred_rel.sigma
        ));

        Ok(())
    }

    /// run convert protocol (send_convert_sig, receive_convert_sig) to switch a pk_u to new pk_u and verify it
    #[test]
    fn test_convert() -> Result<(), error::Error> {
        // 1. sign_keygen
        let issuer = Issuer::new(MaxCardinality::new(5), MaxEntries::new(10));

        // 2. user_keygen and nym
        let nym = Nym::new().randomize();

        // 3. sign
        let messages_vectors = setup_tests();
        let k_prime = Some(4);
        let messages_vector = &vec![
            Entry(messages_vectors.message1_str),
            Entry(messages_vectors.message2_str),
        ];

        let signature_original = issuer
            .sign(&nym.public.key, messages_vector, k_prime)
            .expect("valid tests");

        // 4. create second user_keygen pk_u_new, sk_new
        let nym_new = Nym::new();

        // 5. send_convert_sig to create sig orphan
        let orphan = nym.send_convert_sig(&issuer.public.vk, signature_original.sigma);

        // 6. receive_convert_sig takes sig orphan to create sk_new and sig orphan
        let sigma_new = nym_new.receive_cred(&issuer.public.vk, orphan)?;

        // 7. verify the signature using sigma_new
        assert!(verify(
            &issuer.public.vk,
            &nym_new.public.key,
            &signature_original.commitment_vector,
            &sigma_new
        ));

        Ok(())
    }

    #[test]
    fn test_issue_root_cred() -> Result<(), IssuerError> {
        // 1. sign_keygen
        let issuer = Issuer::new(MaxCardinality::new(5), MaxEntries::new(10));

        // 2. user_keygen and nym
        let nym = Nym::new().randomize();

        // 3. sign
        let messages_vectors = setup_tests();
        let k_prime = Some(4);
        let messages_vector = &vec![
            Entry(messages_vectors.message1_str),
            Entry(messages_vectors.message2_str),
        ];

        // Use `issue_cred` to issue a Credential to a Use's Nym
        let cred = issuer.issue_cred(
            messages_vector,
            k_prime,
            &nym.nym_proof(&NONCE),
            Some(&NONCE),
        )?;

        // check the correctness of root credential
        // assert (spseq_uc.verify(pp_sign, vk_ca, nym_u, commitment_vector, sigma))
        assert!(verify(
            &issuer.public.vk,
            &nym.public.key,
            &cred.commitment_vector,
            &cred.sigma
        ));
        Ok(())
    }

    #[test]
    fn test_delegate_only() -> Result<()> {
        // 1. offer
        // 2. accept
        // 3. prove
        // 4. verify proof

        let issuer = Issuer::default();
        let nym = Nym::new().randomize();

        let messages_vectors = setup_tests();
        let k_prime = Some(5);
        let messages_vector = &mut vec![
            Entry(messages_vectors.message1_str),
            Entry(messages_vectors.message2_str),
        ];

        let cred = issuer.issue_cred(
            messages_vector,
            k_prime,
            &nym.nym_proof(&NONCE),
            Some(&NONCE),
        )?;

        // User to whose Nym we will offer the credential
        let nym_r = Nym::new();

        let addl_entry = Entry::new(&[attribute("age > 21")]);
        messages_vector.push(addl_entry.clone());

        // Create the Offer
        let offer = nym.offer(&cred, &Some(addl_entry))?;

        // verify change_rel
        assert!(verify(
            &issuer.public.vk,
            &nym.public.key,
            &cred.commitment_vector,
            &cred.sigma
        ));

        // nym_r accepts
        let cred_r = nym_r.accept(&offer)?;

        // verify the signature
        assert!(verify(
            &cred_r.issuer_public.vk,
            &nym_r.public.key,
            &cred_r.commitment_vector,
            &cred_r.sigma
        ));

        // prepare a proof for all entrys, including the additional entry
        let proof = nym_r.prove(&cred_r, messages_vector, messages_vector, &NONCE);

        // verify_proof
        assert!(verify_proof(
            &issuer.public,
            &proof,
            messages_vector,
            Some(&NONCE)
        )?);

        Ok(())
    }

    #[test]
    fn test_prove_subset_creds() -> Result<(), IssuerError> {
        let age = attribute("age = 30");
        let name = attribute("name = Alice");
        let drivers = attribute("driver license = 12");
        let gender = attribute("gender = male");
        let company = attribute("company = ACME");
        let drivers_type_b = attribute("driver license type = B");
        let insurance = attribute("Insurance = 2");
        let car_type = attribute("Car type = BMW");

        let message1_str = vec![age.clone(), name.clone(), drivers];
        let message2_str = vec![gender.clone(), company.clone(), drivers_type_b];
        let message3_str = vec![insurance, car_type];

        // Test proving a credential to verifiers
        let all_attributes = vec![
            Entry::new(&message1_str),
            Entry::new(&message2_str),
            Entry::new(&message3_str),
        ];

        let issuer = Issuer::new(MaxCardinality::new(5), MaxEntries::new(10));
        let nym_p = Nym::new().randomize();

        let k_prime = Some(4);
        let cred = issuer.issue_cred(
            &all_attributes,
            k_prime,
            &nym_p.nym_proof(&NONCE),
            Some(&NONCE),
        )?;

        // subset of each message set
        // iteratre through message1_str and return vector if element is either `age` or `name` Attribute
        let search_for = [age, name];
        let sub_list1_str = message1_str
            .iter()
            .filter(|&x| search_for.contains(x))
            .cloned()
            .collect::<Vec<Attribute>>();
        let sub_list2_str = vec![gender, company];

        let selected_attrs = vec![Entry(sub_list1_str), Entry(sub_list2_str)];

        // prepare a proof
        let proof = nym_p.prove(&cred, &all_attributes, &selected_attrs, &NONCE);

        // verify_proof
        assert!(verify_proof(
            &issuer.public,
            &proof,
            &selected_attrs,
            Some(&NONCE)
        )?);

        Ok(())
    }

    #[test]
    fn test_delegate_subset() -> Result<()> {
        // Delegate a subset of attributes
        let age = attribute("age = 30");
        let name = attribute("name = Alice");
        let drivers = attribute("driver license = 12");
        let gender = attribute("gender = male");
        let company = attribute("company = ACME");
        let drivers_type_b = attribute("driver license type = B");
        let insurance = attribute("Insurance = 2");
        let car_type = attribute("Car type = BMW");

        let message1_str = vec![age.clone(), name, drivers];
        let message2_str = vec![gender, company, drivers_type_b];
        let message3_str = vec![insurance.clone(), car_type];

        // Test proving a credential to verifiers
        let mut all_attributes = vec![
            Entry::new(&message1_str),
            Entry::new(&message2_str),
            Entry::new(&message3_str),
        ];

        let l_message = MaxEntries::new(10);
        let issuer = Issuer::new(MaxCardinality::new(8), l_message);
        let alice_nym = Nym::new().randomize();

        let position = 5; // index of the update key to be used for the added element
        let index_l = all_attributes.len() + position;
        let k_prime = Some(std::cmp::min(index_l, l_message.into())); // k_prime must be: MIN(messages_vector.len()) < k_prime < MAX(l_message)

        let cred = issuer.issue_cred(
            &all_attributes,
            k_prime,
            &alice_nym.nym_proof(&NONCE),
            Some(&NONCE),
        )?;

        let bobby_nym = Nym::new();

        // We can retrict proving a credential by zerioizing the opening vector of the Entry
        let mut opening_vector_restricted = cred.opening_vector.clone();
        opening_vector_restricted[0] = Scalar::ZERO; // means the selected attributes cannot include the first commit in the vector
        opening_vector_restricted[1] = Scalar::ZERO; // selected attributes exclude the second commit in the vector

        let cred_restricted = Credential {
            opening_vector: opening_vector_restricted, // restrict opening to read only
            ..cred
        };

        // Add an additional Entry to the all_attributes and add the Entry to the Offer
        let legal_age = Attribute::new("age > 21");
        let addl_entry = Entry::new(&[legal_age.clone()]);

        all_attributes.push(addl_entry.clone());

        // offer to bobby_nym
        let alice_del_to_bobby = alice_nym.offer(&cred_restricted, &Some(addl_entry))?;

        // bobby_nym accepts
        let bobby_cred = bobby_nym.accept(&alice_del_to_bobby)?;

        // verify signature
        assert!(verify(
            &issuer.public.vk,
            &bobby_nym.public.key,
            &bobby_cred.commitment_vector,
            &bobby_cred.sigma
        ));

        // verify that opening_info is of length 4
        assert_eq!(bobby_cred.opening_vector.len(), 4);

        // select subset of each message set Entry
        let selected_attrs = vec![
            Entry(vec![]), // Root Issuer is the only one who could write to this entry
            Entry(vec![]),
            Entry(vec![insurance.clone()]),
            Entry(vec![legal_age.clone()]),
        ];

        // prepare a proof
        let proof = bobby_nym.prove(&bobby_cred, &all_attributes, &selected_attrs, &NONCE);

        // verify_proof
        assert!(verify_proof(
            &issuer.public,
            &proof,
            &selected_attrs,
            Some(&NONCE)
        )?);

        // if we try to prove Entry[0] or Entry[1] it should fail
        // age is from Entry[0]
        let selected_attrs = vec![
            Entry(vec![age]),
            Entry(vec![]),
            Entry(vec![insurance]),
            Entry(vec![legal_age]),
        ];

        // prepare a proof
        let proof = bobby_nym.prove(&bobby_cred, &all_attributes, &selected_attrs, &NONCE);

        // verify_proof should fail
        assert!(!verify_proof(
            &issuer.public,
            &proof,
            &selected_attrs,
            Some(&NONCE)
        )?);

        Ok(())
    }

    #[test]
    // second offer chain
    fn test_second_offer() -> Result<()> {
        init();

        // Delegate a subset of attributes
        let age = attribute("age = 30");
        let name = attribute("name = Alice");
        let drivers = attribute("driver license = 12");
        let gender = attribute("gender = male");
        let company = attribute("company = ACME");
        let drivers_type_b = attribute("driver license type = B");
        let insurance = attribute("Insurance = 2");
        let car_type = attribute("Car type = BMW");

        let message1_str = vec![age, name, drivers];
        let message2_str = vec![gender, company, drivers_type_b];
        let message3_str = vec![insurance.clone(), car_type];

        // Test proving a credential to verifiers
        let mut all_attributes = vec![
            Entry::new(&message1_str),
            Entry::new(&message2_str),
            Entry::new(&message3_str),
        ];

        let l_message = MaxEntries::new(10);
        let issuer = Issuer::new(MaxCardinality::new(8), l_message);
        let alice_nym = Nym::new().randomize();

        let position = 5; // index of the update key to be used for the added element
        let index_l = all_attributes.len() + position;
        let k_prime = Some(std::cmp::min(index_l, l_message.into())); // k_prime must be: MIN(messages_vector.len()) < k_prime < MAX(l_message)

        let alice_cred = issuer.issue_cred(
            &all_attributes,
            k_prime,
            &alice_nym.nym_proof(&NONCE),
            Some(&NONCE),
        )?;

        let bobby_nym = Nym::new();

        // offer to bobby_nym
        let alice_offer = alice_nym.offer(&alice_cred, &None)?;

        // bobby_nym accepts
        let bobby_cred = bobby_nym.accept(&alice_offer)?;

        // bobby offers to Charlie
        let charlie_nym = Nym::new();

        let handsome_attribute = Attribute::new("also handsome");
        let additional_entry = Entry::new(&[handsome_attribute.clone()]);
        all_attributes.push(additional_entry.clone());

        let bobby_offer = bobby_nym.offer(&bobby_cred, &Some(additional_entry))?;

        // bobby_offer commitment_vector should be 1 longer than bobby_cred
        assert_eq!(
            bobby_offer.commitment_vector.len(),
            bobby_cred.commitment_vector.len() + 1
        );

        // charlie accepts (FAILING HERE)
        let charlie_cred = charlie_nym.accept(&bobby_offer)?;

        // charlie makes a proof of insurance
        let selected_attrs = vec![
            Entry(vec![]), // Root Issuer is the only one who could write to this entry
            Entry(vec![]),
            Entry(vec![insurance]),
            Entry(vec![handsome_attribute]),
        ];

        // prepare a proof
        let proof = charlie_nym.prove(&charlie_cred, &all_attributes, &selected_attrs, &NONCE);

        // verify_proof
        assert!(verify_proof(
            &issuer.public,
            &proof,
            &selected_attrs,
            Some(&NONCE)
        )?);

        Ok(())
    }
    // Test the nonce matches nym_proof.pederson_open.open_randomness
    #[test]
    fn test_nonce_matches() {
        // Make a NONCENONCE
        let nonce = Nonce::new(vec![1, 2, 3, 4, 5, 6, 7, 8]);

        let issuer = Issuer::default();
        let nym = Nym::new();

        let messages_vectors = setup_tests();

        let k_prime = None;

        // issue the cred
        let cred = issuer
            .issue_cred(
                &[Entry(messages_vectors.message1_str.clone())],
                k_prime,
                &nym.nym_proof(&nonce),
                Some(&nonce),
            )
            .unwrap();

        // generate a proof using prove
        let proof = nym.prove(
            &cred,
            &[Entry(messages_vectors.message1_str.clone())],
            &[Entry(messages_vectors.message1_str.clone())],
            &nonce,
        );

        // the proof.pedersen_open.open_randomness should match the nonce
        assert_eq!(proof.nym_proof.pedersen_open.open_randomness, nonce);

        // verify the proof
        assert!(verify_proof(
            &issuer.public,
            &proof,
            &[Entry(messages_vectors.message1_str)],
            Some(&nonce)
        )
        .unwrap());
    }
}
