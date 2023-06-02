use crate::attributes::Attribute;
use amcl_wrapper::errors::SerzDeserzError;
use amcl_wrapper::field_elem::FieldElement;
use amcl_wrapper::group_elem::GroupElement;
use amcl_wrapper::group_elem_g1::G1;
use secrecy::ExposeSecret;
use secrecy::Secret;
use std::ops::Deref;

#[derive(Clone, Debug, PartialEq)]
pub struct Entry(pub Vec<Attribute>);

impl Entry {
    pub fn new(attributes: &[Attribute]) -> Self {
        Entry(attributes.to_vec())
    }
}

pub fn entry(attributes: &[Attribute]) -> Entry {
    Entry(attributes.to_vec())
}

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

/// Iterates through each Attribute in the Entry and converts it to a FieldElement
pub fn convert_entry_to_bn(input: &Entry) -> Result<Vec<FieldElement>, SerzDeserzError> {
    input
        .iter()
        .map(|attr| FieldElement::from_bytes(attr))
        .collect()
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
        let d = Secret::new(FieldElement::random()); // trapdoor
        let h = &g.scalar_mul_const_time(d.expose_secret());
        Pedersen { g, h: h.clone() }
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
        let c2 = &self.h.scalar_mul_const_time(&pedersen_open.open_randomness)
            + &self
                .g
                .scalar_mul_const_time(&pedersen_open.announce_randomness);
        &c2 == pedersen_commit
    }
}
