//! If `derive` is feature is enabled, this crate provides a key derivation mechanism for BLS12-381.
use crate::vk;
use blastkids::kdf;

// re-exports
pub use bls12_381_plus::group::{Group, GroupEncoding};
pub use bls12_381_plus::G1Projective as G1;
pub use bls12_381_plus::G2Projective as G2;
pub use bls12_381_plus::Scalar;
pub use secrecy::zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};
pub use secrecy::{ExposeSecret, Secret};

use bls12_381_plus::elliptic_curve::ops::MulByGenerator;

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
        // since the account public key is hardened and cannot expose the master seed/secret
        // Derive the first normal secret key in advance
        // so we can get our Deterministic Public Keys for this account
        // for any length / size
        let sk_normal_0 = Zeroizing::new(kdf::ckd_sk_normal::<G2>(sk.expose_secret(), 0));
        let pk_normal_g1 = G1::mul_by_generator(&sk_normal_0);
        let pk_hardened_g2 = G2::mul_by_generator(sk.expose_secret());

        Account {
            index,
            sk,
            pk_g1: pk_normal_g1,
            pk_g2: pk_hardened_g2,
        }
    }
}

/// An Account is a hardened key derived from the master secret key.
///
/// It is generic over the type of curve used, either G1 or G2.
pub struct Account {
    pub index: u32,
    sk: Secret<Scalar>,
    pub pk_g1: G1,
    pub pk_g2: G2,
}

impl Account {
    /// Create a new account from a secret key and public key
    pub fn new(index: u32, sk: Scalar, pk_g1: G1, pk_g2: G2) -> Self {
        Self {
            index,
            sk: Secret::new(sk),
            pk_g1,
            pk_g2,
        }
    }

    /// Expand an Account given a length, using the Account's secret key to derive the additional keys.
    ///
    /// Function is deterministic, and always exapands to the same keys at each index.
    ///
    /// Maximum length is 255 as there is no practical use case for keys longer than this (yet)
    pub fn expand_to(&self, length: u8) -> Secret<Vec<Scalar>> {
        Secret::new(
            (0..length)
                .map(|i| kdf::ckd_sk_normal::<G2>(self.sk.expose_secret(), i as u32))
                .collect::<Vec<Scalar>>(),
        )
    }
}

/// Given an Account's root Public Keys and a desired [VK] length,
/// derive the expanded Verification Key [VK] for the Account size.
///
/// The length is the target length of the entire Verification Key [VK]
pub fn derive(pk_g1: &G1, pk_g2: &G2, length: u8) -> Vec<vk::VK> {
    let vk_g2_expanded: Vec<vk::VK> = (0..(length - 1))
        .map(|i| vk::VK::G2(blastkids::kdf::ckd_pk_normal::<G2>(pk_g2, i as u32)))
        .collect();

    // concat pk_g1, vk_g2_expanded
    let mut vk = Vec::with_capacity(length as usize);
    vk.push(vk::VK::G1(*pk_g1));
    vk.extend(vk_g2_expanded);
    vk
}

#[cfg(test)]
mod basic_test {

    use secrecy::zeroize::Zeroizing;

    use super::*;

    #[test]
    fn smoke() {
        let seed = Zeroizing::new([69u8; 32]);
        let manager: Manager = Manager::from_seed(seed);

        // Check to ensure the VK generated by the sk expanded matches those derived from pk_g1 and
        // pk_2
        let account = manager.account(1);
        let vk = derive(&account.pk_g1, &account.pk_g2, 3);

        assert_eq!(
            vk,
            vec![
                vk::VK::G1(account.pk_g1),
                vk::VK::G2(blastkids::kdf::ckd_pk_normal::<G2>(&account.pk_g2, 0)),
                vk::VK::G2(blastkids::kdf::ckd_pk_normal::<G2>(&account.pk_g2, 1)),
            ]
        );
    }
}
