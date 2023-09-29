//! All the relevant elliptic curve operations are implemented here
pub mod univarpoly;

pub use bls12_381_plus::{G1Projective, G2Projective, Scalar};
use univarpoly::UnivarPolynomial;

pub mod curve {
    use super::*;

    pub use bls12_381_plus::Gt;
    pub use univarpoly::ScalarVector;

    use bls12_381_plus::group::Curve;

    /// Pair two EC points
    pub fn pairing(a: &G1Projective, b: &G2Projective) -> Gt {
        bls12_381_plus::pairing(&a.to_affine(), &b.to_affine())
    }

    /// Get polynomials coefficients from given roots
    pub fn polynomial_from_roots(roots: &[Scalar]) -> UnivarPolynomial {
        UnivarPolynomial::new_with_roots(roots)
    }
}

pub mod traits {
    pub use bls12_381_plus::elliptic_curve::ops::MulByGenerator;
}
