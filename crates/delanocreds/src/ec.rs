//! All the relevant elliptic curve operations are implemented here
// if feature amcl_wrapper enabled
// #[cfg(feature = "amcl_wrapper")]
pub mod curve {
    pub use amcl_wrapper::extension_field_gt::GT;
    pub use amcl_wrapper::{
        constants::CurveOrder, field_elem::FieldElement, group_elem::GroupElement,
        group_elem_g1::G1, group_elem_g2::G2,
    };

    use amcl_wrapper::univar_poly::UnivarPolynomial;

    pub type CurveError = amcl_wrapper::errors::SerzDeserzError;
    pub type FieldElementVector = UnivarPolynomial;

    // GT::ate_pairing
    // GT is short for: G1 x G2 -> Gt
    // they calle dit Gt because it's a group of order r
    // r is the order of the groups G1 and G2
    // the 't' comes from 'trace' of the pairing
    pub fn pairing(a: &G1, b: &G2) -> GT {
        GT::ate_pairing(a, b)
    }

    /// Polynomials, UnivarPolynomial::new_with_roots
    pub fn polynomial_from_coeff(coeffs: &[FieldElement]) -> UnivarPolynomial {
        UnivarPolynomial::new_with_roots(coeffs)
    }
}

#[cfg(test)]
mod test {

    use super::curve::*;

    #[test]
    fn print_curve_order() {
        println!("CurveOrder: {:?}", CurveOrder.tostring());
        // convert CurveOrder.tostring() hex to radix 10
        let curve_order = CurveOrder.tostring();
        // iterate over string and convert the hex string into base 10 string
        curve_order
            .chars()
            .for_each(|c| print!("{}", c.to_digit(16).unwrap()));
        println!();
    }
}
