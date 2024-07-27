//! If `derive` is feature is enabled, this crate provides a key derivation mechanism for BLS12-381.
use crate::error::Error;
use crate::vk;
use blastkids::kdf;

use bls12_381_plus::elliptic_curve::hash2curve::ExpandMsgXmd;
// re-exports
pub use bls12_381_plus::group::Curve;
pub use bls12_381_plus::group::{Group, GroupEncoding};
use bls12_381_plus::G1Affine;
pub use bls12_381_plus::G1Projective;
use bls12_381_plus::G2Affine;
pub use bls12_381_plus::G2Projective;
pub use bls12_381_plus::Scalar;
pub use secrecy::zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};
pub use secrecy::{ExposeSecret, Secret};

use bls12_381_plus::elliptic_curve::ops::MulByGenerator;

/// Domain Separation Tag for Proof of Possession, as our Signatures are in G2 (and public keys are in G1).
/// See <https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bls-signature-04#section-4.2.3> for more details.
const DST: &'static [u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";

/// Seed and master key Manager.
///
/// Generic over the type of curve used, [either G1 or G2](https://hackmd.io/@benjaminion/bls12-381#Swapping-G1-and-G2)
///
/// ```rust
/// use blastkids::{Manager, Zeroizing};
/// use bls12_381_plus::G1Projective as G1;
/// use bls12_381_plus::G2Projective as G2;
/// // use blastkids::{G1, G2}; <== re-exported for convenience
///
/// // a G1 public key
/// let seed = Zeroizing::new([69u8; 32]);
/// let manager: Manager<G1> = Manager::from_seed(seed);
///
/// // or if you like, make a new manager for a G2 public key
/// let seed = Zeroizing::new([42u8; 32]);
/// let manager: Manager<G2> = Manager::from_seed(seed);
/// ```
///
pub struct Manager {
    master_sk: Secret<Scalar>,
}

impl Clone for Manager {
    fn clone(&self) -> Self {
        Self {
            master_sk: (*self.master_sk.expose_secret()).into(),
        }
    }
}

impl PartialEq for Manager {
    fn eq(&self, other: &Self) -> bool {
        self.master_sk.expose_secret() == other.master_sk.expose_secret()
    }
}

impl Default for Manager {
    fn default() -> Self {
        Self {
            master_sk: Secret::new(Scalar::ZERO),
        }
    }
}

impl Manager {
    /// Create a new Manager from a master secret key
    /// and derive the master public key from it.
    fn new(master_sk: Secret<Scalar>) -> Self {
        Self { master_sk }
    }

    /// Create a new Manager from a seed.
    ///
    /// The seed is used to derive the master secret key. The seed passed
    /// must covert to bytes and [Zeroize] and [ZeroizeOnDrop] for your memory safety.
    pub fn from_seed(seed: impl AsRef<[u8]> + Zeroize + ZeroizeOnDrop) -> Self {
        let master_sk: Scalar =
            kdf::derive_master_sk(seed.as_ref()).expect("Seed has length of 32 bytes");
        Self::new(Secret::new(master_sk))
    }

    /// Returns the Account at the index.
    ///
    /// Uses the master secret key to create a hardened account key,
    /// then [Account] uses this hardened account key to create a derived
    /// non-hardened sub-account (child) keys.
    ///
    /// This way the user can create new accounts for the same seed
    /// and also rotate them in the event of compromise without
    /// compromising the master secret key.
    pub fn account(&self, index: u32) -> Account {
        // first derive a hardened key for the account
        let sk: Secret<Scalar> =
            Secret::new(kdf::ckd_sk_hardened(self.master_sk.expose_secret(), index));
        // since the account secret key is hardened and cannot expose the master seed/secret
        // Derive the first normal secret key in advance
        // so we can get our Deterministic Public Keys for this account
        // for any length / size
        let sk_hardened_0 =
            Zeroizing::new(kdf::ckd_sk_normal::<G2Projective>(sk.expose_secret(), 0));
        let pk_g1 = G1Projective::mul_by_generator(&sk_hardened_0);
        let pk_g2 = G2Projective::mul_by_generator(sk.expose_secret());

        Account {
            index,
            sk,
            pk_g1,
            pk_g2,
        }
    }
}

/// An Account is a hardened key derived from the master secret key.
///
/// It is generic over the type of curve used, either G1 or G2.
pub struct Account {
    pub index: u32,
    sk: Secret<Scalar>,
    pub pk_g1: G1Projective,
    pub pk_g2: G2Projective,
}

impl Account {
    /// Create a new account from a secret key and public key
    pub fn new(index: u32, sk: Scalar, pk_g1: G1Projective, pk_g2: G2Projective) -> Self {
        Self {
            index,
            sk: Secret::new(sk),
            pk_g1,
            pk_g2,
        }
    }

    /// Getter for [bls12_381_plus::g1::G1Affine] public key.
    ///
    /// This is typically the key used for signing and verification as it is shorter.
    pub fn pk_g1(&self) -> G1Affine {
        self.pk_g1.to_affine()
    }

    /// Getter for [G2Affine] public key
    pub fn pk_g2(&self) -> G2Affine {
        self.pk_g2.to_affine()
    }

    /// Expand an Account given a length, using the Account's secret key to derive the additional keys.
    ///
    /// Function is deterministic, and always exapands to the same keys at each index.
    ///
    /// Maximum length is 255 as there is no practical use case for keys longer than this (yet)
    pub fn expand_to(&self, length: u8) -> Secret<Vec<Scalar>> {
        Secret::new(
            (0..length)
                .map(|i| kdf::ckd_sk_normal::<G2Projective>(self.sk.expose_secret(), i as u32))
                .collect::<Vec<Scalar>>(),
        )
    }

    /// Generates a signature for this account's [G1Projective] public key.
    ///
    /// # Example
    ///
    /// ```rust
    /// use delano_keys::kdf::{Manager, Zeroizing, verify};
    ///
    /// let seed = Zeroizing::new([69u8; 32]);
    /// let manager: Manager = Manager::from_seed(seed);
    /// let account = manager.account(1);
    /// let message = b"hello world";
    /// let signature = account.sign(message);
    /// // verify the signature
    /// let verified = verify(&account.pk_g1(), message, &signature).unwrap();
    /// assert!(verified);
    /// ```
    pub fn sign(&self, message: &[u8]) -> [u8; G2Affine::COMPRESSED_BYTES] {
        let sk_normal_0 = Zeroizing::new(kdf::ckd_sk_normal::<G2Projective>(
            self.sk.expose_secret(),
            0,
        ));

        // Hash the msg to G2
        let g2_point = G2Projective::hash::<ExpandMsgXmd<sha2::Sha256>>(message, DST);

        let signature = g2_point * *sk_normal_0;

        signature.to_compressed()
    }
}

/// Verify a signed message ([G2Compressed]) against a [G1] public key.
pub fn verify(pk: &G1Affine, message: &[u8], signature: &[u8]) -> Result<bool, Error> {
    // let err msg say that signature was not a valid G2 point
    let sig_g2 = try_decompress_g2(signature.to_vec())?;

    // Hash the msg to G2Affine
    let hashed_msg_g2 = G2Projective::hash::<ExpandMsgXmd<sha2::Sha256>>(message, DST).to_affine();
    let g1_generator = G1Projective::generator().to_affine();

    // Verify the signature by checking the pairing(G1_pubkey, G2_hashed_msg) == pairing(G1_generator, G2_signature)
    let result = bls12_381_plus::pairing(&pk, &hashed_msg_g2)
        == bls12_381_plus::pairing(&g1_generator, &sig_g2);

    Ok(result)
}

/// Given an Account's root Public Keys and a desired [VK] length,
/// derive the expanded Verification Key [VK] for the Account size.
///
/// The length is the target length of the entire Verification Key [VK]
pub fn derive(pk_g1: &G1Projective, pk_g2: &G2Projective, length: u8) -> Vec<vk::VK> {
    let vk_g2_expanded: Vec<vk::VK> = (0..(length - 1))
        .map(|i| {
            vk::VK::G2(blastkids::kdf::ckd_pk_normal::<G2Projective>(
                pk_g2, i as u32,
            ))
        })
        .collect();

    // concat pk_g1, vk_g2_expanded
    let mut vk = Vec::with_capacity(length as usize);
    vk.push(vk::VK::G1(*pk_g1));
    vk.extend(vk_g2_expanded);
    vk
}

/// Try Decompress G1 from byte Vector
pub fn try_decompress_g1(value: Vec<u8>) -> Result<G1Affine, Error> {
    let mut bytes = [0u8; G1Affine::COMPRESSED_BYTES];
    bytes.copy_from_slice(&value);
    let maybe_g1 = G1Affine::from_compressed(&bytes);

    if maybe_g1.is_none().into() {
        return Err(Error::InvalidG1Point);
    } else {
        Ok(maybe_g1.unwrap())
    }
}

/// Try Decompress G2
pub(crate) fn try_decompress_g2(value: Vec<u8>) -> Result<G2Affine, Error> {
    let mut bytes = [0u8; G2Affine::COMPRESSED_BYTES];
    bytes.copy_from_slice(&value);
    let maybe_g2 = G2Affine::from_compressed(&bytes);

    if maybe_g2.is_none().into() {
        return Err(Error::InvalidG2Point);
    } else {
        Ok(maybe_g2.unwrap())
    }
}

#[cfg(test)]
mod basic_test {

    use super::*;

    #[test]
    fn smoke() {
        let seed = Zeroizing::new([69u8; 32]);
        let manager: Manager = Manager::from_seed(seed);

        // Check to ensure the VK generated by the sk expanded matches those derived from pk_g1 and
        // pk_2
        let account = manager.account(1);

        let expanded = account.expand_to(2);

        // get the pk from each of the expanded keys
        // remember, the first VK is sk[0] * G1 and 2nd VK is sk[0] * G2Projective
        // so we need len - 1 secret keys
        let pk_g1 = G1Projective::mul_by_generator(&expanded.expose_secret()[0]);
        let pk_g2_0 = G2Projective::mul_by_generator(&expanded.expose_secret()[0]);
        let pk_g2_1 = G2Projective::mul_by_generator(&expanded.expose_secret()[1]);

        let vk = derive(&account.pk_g1, &account.pk_g2, 3);

        // vk should match the expanded Keys
        assert_eq!(
            vk,
            vec![vk::VK::G1(pk_g1), vk::VK::G2(pk_g2_0), vk::VK::G2(pk_g2_1)]
        );

        assert_eq!(
            vk,
            vec![
                vk::VK::G1(account.pk_g1),
                vk::VK::G2(blastkids::kdf::ckd_pk_normal::<G2Projective>(
                    &account.pk_g2,
                    0
                )),
                vk::VK::G2(blastkids::kdf::ckd_pk_normal::<G2Projective>(
                    &account.pk_g2,
                    1
                ))
            ]
        );
    }

    // Tests signature and verify
    #[test]
    fn test_sign_roundtrip() {
        let seed = Zeroizing::new([69u8; 32]);
        let manager: Manager = Manager::from_seed(seed);

        // For each account indices: 0, 1, 2, 3
        let indices = vec![0, 1, 2, 3];

        for index in indices {
            let account = manager.account(index);

            let message = b"hello world";
            let signature = account.sign(message);

            let verified = verify(&account.pk_g1.to_affine(), message, &signature).unwrap();
            assert!(verified);
        }
    }

    // Failing signature verification
    #[test]
    fn test_sign_roundtrip_fail() {
        let seed = Zeroizing::new([69u8; 32]);
        let manager: Manager = Manager::from_seed(seed);

        let account = manager.account(1);

        let message = b"hello world";
        let signature = account.sign(message);

        let verified = verify(&account.pk_g1.to_affine(), b"hello world!", &signature).unwrap();
        assert!(!verified);
    }
}
