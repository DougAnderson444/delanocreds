use amcl_wrapper::field_elem::{FieldElement, FieldElementVector};
use amcl_wrapper::group_elem::GroupElement;
use amcl_wrapper::group_elem_g1::G1;
use amcl_wrapper::group_elem_g2::G2;
use amcl_wrapper::types::BigNum;
use amcl_wrapper::univar_poly::UnivarPolynomial;
use amcl_wrapper::univar_polynomial;
#[derive(Clone, Debug)]
pub enum InputType {
    String(String),
    VecString(Vec<String>),
}

pub enum Roots {
    FieldElement(FieldElement),
    VecFieldElement(Vec<FieldElement>),
}

pub fn convert_mess_to_bn(input: InputType) -> Roots {
    match input {
        InputType::String(mess) => {
            // convert the mess to bytes and then into a BigNum
            let mess_bytes = mess.as_bytes();
            let elem = FieldElement::from_bytes(mess_bytes).unwrap();
            Roots::FieldElement(elem)
        }
        InputType::VecString(mess_vec) => {
            let mut elem_vec = Vec::new();
            for mess in mess_vec {
                // convert the mess to bytes and then into a BigNum
                let mess_bytes = mess.as_bytes();
                let elem = FieldElement::from_bytes(mess_bytes).unwrap();
                elem_vec.push(elem);
            }
            Roots::VecFieldElement(elem_vec)
        }
    }
}

// roots and coefficients are the same
pub fn polyfromroots(coeffs: Vec<FieldElement>) -> UnivarPolynomial {
    UnivarPolynomial::new_with_roots(&coeffs[..])
}

/// Sum EC points list.
pub fn ec_sum(listpoints: Vec<G1>) -> G1 {
    let mut sum = G1::identity();
    for i in 0..listpoints.len() {
        sum += &listpoints[i];
    }
    sum
}
