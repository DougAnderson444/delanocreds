use amcl_wrapper::field_elem::FieldElement;
use amcl_wrapper::group_elem::GroupElement;
use amcl_wrapper::group_elem_g1::G1;
use amcl_wrapper::univar_poly::UnivarPolynomial;
use secrecy::ExposeSecret;
use secrecy::Secret;
use std::ops::Deref;

/// Attribute type
#[derive(Debug, Clone, Eq, Hash, PartialEq)]
pub struct Attribute(pub Vec<u8>);

pub fn attribute(a: impl AsRef<[u8]>) -> Attribute {
    Attribute(a.as_ref().to_vec())
}

// impl DeRef for Attibute
impl Deref for Attribute {
    type Target = Vec<u8>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct Entry(pub Vec<Attribute>);

impl Deref for Entry {
    type Target = Vec<Attribute>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl IntoIterator for Entry {
    type Item = Attribute;
    type IntoIter = ::std::vec::IntoIter<Attribute>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

/// Returns the coefficients of a polynomial with the given roots
/// The number of polynomial coefficients is one more than the degree of the polynomial.
pub fn polyfromroots(coeffs: Vec<FieldElement>) -> UnivarPolynomial {
    UnivarPolynomial::new_with_roots(&coeffs[..])
}

/// Sum EC points list.
pub fn ec_sum(listpoints: Vec<G1>) -> G1 {
    let mut sum = G1::identity();
    for pts in &listpoints {
        sum += pts;
    }
    sum
}

/// Iterates through each Attribute in the Entry and converts it to a FieldElement
pub fn convert_mess_to_bn(input: &Entry) -> Vec<FieldElement> {
    input
        .iter()
        .map(|entry| FieldElement::from_msg_hash(entry))
        .collect::<Vec<FieldElement>>()
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct Pedersen {
    pub g: G1,
    pub h: G1,
    // trapdoor: FieldElement,
}
pub type Trapdoor = FieldElement;
pub type PedersenCommit = G1;

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct PedersenOpen {
    pub open_randomness: FieldElement,
    pub announce_randomness: FieldElement,
    pub announce_element: Option<G1>,
}

impl PedersenOpen {
    pub fn element(&mut self, elem: G1) {
        self.announce_element = Some(elem);
    }
}
impl Default for Pedersen {
    fn default() -> Self {
        Self::new()
    }
}
impl Pedersen {
    pub fn new() -> Self {
        // h is the statement. d is the trapdoor. g is the generator. h = d*g
        let g = G1::generator();
        let d = Secret::new(FieldElement::random());
        let h = &g.scalar_mul_const_time(d.expose_secret());
        Pedersen {
            g,
            h: h.clone(),
            // trapdoor: d
        }
    }
    pub fn commit(&self, msg: FieldElement) -> (PedersenCommit, PedersenOpen) {
        let r = FieldElement::random();
        let pedersen_commit = &r * &self.h + &msg * &self.g;
        let pedersen_open = PedersenOpen {
            open_randomness: r,
            announce_randomness: msg,
            announce_element: None,
        };

        (pedersen_commit, pedersen_open)
    }

    /// Decrypts/Decommits the message
    pub fn decommit(&self, pedersen_open: &PedersenOpen, pedersen_commit: &PedersenCommit) -> bool {
        let c2 = pedersen_open.open_randomness.clone() * &self.h
            + pedersen_open.announce_randomness.clone() * &self.g;
        &c2 == pedersen_commit
    }
}
