//! Reference implementation of [DelanocredsSecrets] that does not require any approvals
//! Useful for testing, examples, and demos where approvals are not required
//!
//! Secrets and Public keys are created in a hierarchical deterministic way
//! usign [bls_ckd] crate. This way, an Issuer only needs to reference their master
//! public key and the user can generate their commitment length keys deterministically.
use super::*;
use crate::types::{BigInteger, FieldElem};
use curv::elliptic::curves::DeserializationError;
use curv::{
    arithmetic::traits::*,
    elliptic::curves::{
        bls12_381::{
            // g1::GE1,
            g2::GE2,
            scalar::{FieldScalar, FE},
        },
        ECPoint, ECScalar,
    },
    BigInt,
};
use secrecy::Secret;

pub struct BasicSecretsManager {
    master_sk: FE,
    pub master_pk: GE2,
}

impl BasicSecretsManager {
    fn new(master_sk: FE) -> Result<Self, DeserializationError> {
        let master_pk: GE2 = ECPoint::generator_mul(&master_sk);
        Ok(Self {
            master_sk,
            master_pk,
        })
    }

    pub fn from_seed(seed: Seed) -> Result<Self, DelanocredsSecretsError> {
        let master_sk: FE = bls_ckd::derive_master_sk(&seed.into_inner())?;
        Ok(Self::new(master_sk)?)
    }

    /// Returns the Acount at the index.
    ///
    /// Uses the master secret key to create a hardened account key,
    /// then [Account] uses this hardened account key to create a derived
    /// non-hardened sub-account keys.
    ///
    /// This way the user can create new accounts for the same seed
    /// and also rotate them in the event of compromise without
    /// compromising the master secret key.
    pub fn account(&self, account_index: u32) -> Account {
        // first derive a hardened key for the account
        let derived_sk: FE = bls_ckd::ckd_sk_hardened(&self.master_sk, account_index);
        // since the account public key is hardened and cannot expose the master seed/secret
        let derived_pk: GE2 = ECPoint::generator_mul(&derived_sk);

        Account {
            index: account_index,
            sk: derived_sk,
            pk: derived_pk,
        }
    }
}

/// Wrapper type for [BigInt] so we can do conversions to [amcl_wrapper::types::BigNum] aka [amcl_wrapper::field_elem::FieldElement]
pub struct Big {
    pub inner: BigInt,
}

impl TryFrom<Big> for amcl_wrapper::field_elem::FieldElement {
    type Error = amcl_wrapper::errors::SerzDeserzError;

    fn try_from(big: Big) -> Result<Self, Self::Error> {
        let mut sized = [0u8; 48];
        let bytes = big.inner.to_bytes();
        let offset = 48 - bytes.len();
        sized[offset..].copy_from_slice(&bytes);

        Self::from_bytes(&sized)
    }
}

pub struct Account {
    pub index: u32,
    sk: FE,
    pub pk: GE2,
}

impl Account {
    /// Create a new account
    pub fn new(index: u32, sk: FE, pk: GE2) -> Self {
        Self { index, sk, pk }
    }

    /// Returns a Vector of [Secret] keys from index 0 to length -1
    /// Extracts the inner [BigInt] value of [FE] as the vector elements
    pub fn derive(&self, length: u32) -> Secret<Vec<FieldElem>> {
        Secret::new(
            (0..length)
                // FieldScalar::to_bigint(&bls_ckd::ckd_sk_normal::<GE2>(&self.sk, i))
                .map(|i| {
                    FieldElem::try_from(BigInteger::from(FieldScalar::to_bigint(
                        &bls_ckd::ckd_sk_normal::<GE2>(&self.sk, i),
                    )))
                    .expect("should be able to convert 32 byte into 48 bytes FE")
                })
                .collect::<Vec<FieldElem>>(),
        )
    }
}

/// Get child account at index.
pub fn derive(pk: &GE2, child_index: u32) -> GE2 {
    bls_ckd::ckd_pk_normal(pk, child_index)
}

#[derive(Debug)]
pub enum DelanocredsSecretsError {
    /// The user did not approve the request
    UserDenied,
    /// The user did not approve the request in time
    Timeout,
    /// The user did not approve the request in time
    Cancelled,
    /// The user did not approve the request in time
    Unknown(String),
    /// Seed is too small
    SeedTooSmall,
    /// DeserializationError
    DeserializationError(DeserializationError),
}

// Convert String to DelanocredsSecretsError
impl From<String> for DelanocredsSecretsError {
    fn from(s: String) -> Self {
        match s.as_str() {
            "UserDenied" => DelanocredsSecretsError::UserDenied,
            "Timeout" => DelanocredsSecretsError::Timeout,
            "Cancelled" => DelanocredsSecretsError::Cancelled,
            _ => DelanocredsSecretsError::Unknown(s),
        }
    }
}

// Convert DeserializationError to DelanocredsSecretsError
impl From<DeserializationError> for DelanocredsSecretsError {
    fn from(e: DeserializationError) -> Self {
        DelanocredsSecretsError::DeserializationError(e)
    }
}

/// To be compliant with [eip-2334](https://eips.ethereum.org/EIPS/eip-2334),
/// we need to set a path in the form of
///
/// ```text
/// m / purpose / coin_type /  account / use
/// ```
///
/// `m/12381/60/0/0` where `12381` is the BIP32 curve code for BLS12-381
/// This wallet is not for a "coin" but coin wallets may one day use this,
/// so lets set the `purpose` for forward compatability.
///
/// Value is set to Hex 0xCAFED00D (Decimal 3405697037) because we are
/// one bad duude, man.
pub const BIP44_PATH_PREFIX: [&str; 3] = ["m", "12381", "3405697037"];

#[cfg(test)]
mod basic_test {

    use super::*;
    use crate::types::Scalar;
    use secrecy::ExposeSecret;

    #[test]
    fn smoke() {
        let seed = Seed::new([69u8; 32]);
        let manager = BasicSecretsManager::from_seed(seed).expect("test seed to work");
        let pk2 = ECPoint::generator_mul(&manager.master_sk);
        assert_eq!(manager.master_pk, pk2);

        println!(
            "master_pk [{}]: compressed: [{:?}]",
            manager.master_pk.serialize_uncompressed().len(),
            manager.master_pk.serialize_compressed().len()
        );

        println!(
            "master_sk [{}]",
            manager.master_sk.to_bigint().to_bytes().len(),
        );

        let account_index = 1;
        // a user derived account #2 matches the issuer derived account #2
        let account = manager.account(account_index);
        // derived second floor from floor_account_pk
        let derived_sk = account.derive(1);

        // should match the issuer derived account #2 from secret keys
        let hardened_child_sk = bls_ckd::ckd_sk_hardened(&manager.master_sk, account_index);

        // account sk should match hardened_child_sk
        assert_eq!(
            account.sk.serialize().as_slice(),
            hardened_child_sk.to_bigint().to_bytes()
        );

        let normal_sk: FE = bls_ckd::ckd_sk_normal::<GE2>(&hardened_child_sk, 0u32);

        // derived_sk should match [leading 0s ..normal_sk]
        assert_eq!(
            Scalar(derived_sk.expose_secret()[0].clone().into()),
            Scalar(normal_sk) // normal_sk.serialize().as_slice()
        );
    }

    #[test]
    fn try_convert() {
        let seed = Seed::new([69u8; 32]);
        let manager = BasicSecretsManager::from_seed(seed).expect("test seed to work");

        let big = Big {
            inner: manager.master_sk.to_bigint(),
        };
        let _fe = amcl_wrapper::field_elem::FieldElement::try_from(big).unwrap();
    }
}
