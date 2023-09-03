//! Module wraps Field Scalar Elements and Big Integer library types so that they automatically convert
use curv::arithmetic::traits::*;
use curv::elliptic::curves::bls12_381::scalar::FieldScalar;
use curv::elliptic::curves::ECScalar;
use curv::BigInt;
use secrecy::zeroize::Zeroize;
use std::ops::Deref;
use std::ops::DerefMut;

pub use amcl_wrapper::field_elem::FieldElement;

type FE = amcl_wrapper::field_elem::FieldElement;
pub type G1 = amcl_wrapper::group_elem_g1::G1;
pub type G2 = amcl_wrapper::group_elem_g2::G2;

/// A newtype wrapper around [FE]
#[derive(Clone, Debug)]
pub struct FieldElem(pub FieldElement);

impl FieldElem {
    pub fn random() -> Self {
        Self(FE::random())
    }
}

impl From<FE> for FieldElem {
    fn from(fe: FE) -> Self {
        Self(fe)
    }
}

/// Wrapper around FieldScalar
#[derive(Clone, Debug, PartialEq)]
pub struct Scalar(pub FieldScalar);

/// From Scalar to FieldScalar
impl From<Scalar> for FieldScalar {
    fn from(s: Scalar) -> Self {
        s.0
    }
}

/// From Vec<FieldElem> into Vec<Scalar>
pub fn field_elems_into_scalars(field_elems: Vec<FieldElem>) -> Vec<Scalar> {
    field_elems
        .into_iter()
        .map(|fe| {
            Scalar(FieldScalar::from_bigint(&BigInt::from_bytes(
                &fe.0.to_bytes(),
            )))
        })
        .collect()
}

impl From<FieldScalar> for Scalar {
    fn from(fs: FieldScalar) -> Self {
        Self(fs)
    }
}

/// Scalar into FieldScalar
impl From<&Scalar> for FieldScalar {
    fn from(s: &Scalar) -> Self {
        s.0.clone()
    }
}

impl From<&FieldElem> for Scalar {
    fn from(fe: &FieldElem) -> Self {
        Self(FieldScalar::from_bigint(&BigInt::from_bytes(
            &fe.0.to_bytes(),
        )))
    }
}

impl From<&FieldElem> for FieldScalar {
    fn from(fe: &FieldElem) -> Self {
        Self::from_bigint(&BigInt::from_bytes(&fe.0.to_bytes()))
    }
}

impl From<&FieldElem> for BigInteger {
    fn from(fe: &FieldElem) -> Self {
        BigInt::from_bytes(&fe.0.to_bytes()).into()
    }
}

impl From<FieldElem> for Scalar {
    fn from(fe: FieldElem) -> Self {
        Self(FieldScalar::from_bigint(&BigInt::from_bytes(
            &fe.0.to_bytes(),
        )))
    }
}

impl From<FieldElem> for FieldScalar {
    fn from(fe: FieldElem) -> Self {
        Self::from_bigint(&BigInt::from_bytes(&fe.0.to_bytes()))
    }
}

impl From<FieldElem> for BigInteger {
    fn from(fe: FieldElem) -> Self {
        BigInt::from_bytes(&fe.0.to_bytes()).into()
    }
}

/// A newtype wrapper around [BigInt]
pub struct BigInteger(pub BigInt);

impl BigInteger {
    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.to_bytes()
    }

    pub fn modulus(&self, modulus: &Self) -> Self {
        Self(self.0.modulus(&modulus.into()))
    }
}

impl From<&BigInteger> for BigInt {
    fn from(big: &BigInteger) -> Self {
        big.0.clone()
    }
}

impl AsRef<FE> for FieldElem {
    fn as_ref(&self) -> &FE {
        &self.0
    }
}

impl Deref for FieldElem {
    type Target = FE;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for FieldElem {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl TryFrom<BigInteger> for FieldElement {
    type Error = amcl_wrapper::errors::SerzDeserzError;

    fn try_from(big: BigInteger) -> Result<Self, Self::Error> {
        let mut sized = [0u8; 48];
        let bytes = big.to_bytes();
        let offset = 48 - bytes.len();
        sized[offset..].copy_from_slice(&bytes);

        Self::from_bytes(&sized)
    }
}

impl From<BigInteger> for FieldElem {
    fn from(big: BigInteger) -> Self {
        Self(big.try_into().expect("should be able to convert"))
    }
}

impl From<BigInt> for BigInteger {
    fn from(big: BigInt) -> Self {
        Self(big)
    }
}

impl From<&[u8]> for BigInteger {
    fn from(bytes: &[u8]) -> Self {
        Self(BigInt::from_bytes(bytes))
    }
}

impl From<&Vec<u8>> for BigInteger {
    fn from(bytes: &Vec<u8>) -> Self {
        Self(BigInt::from_bytes(bytes))
    }
}

impl Zeroize for BigInteger {
    fn zeroize(&mut self) {
        self.0.zeroize()
    }
}

impl Default for FieldElem {
    fn default() -> Self {
        Self(FE::zero())
    }
}

impl Zeroize for FieldElem {
    fn zeroize(&mut self) {
        self.0.zeroize()
    }
}
