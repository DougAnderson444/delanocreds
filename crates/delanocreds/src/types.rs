use std::{fmt::Display, ops::Deref};

use crate::ec::curve::{G1, G2};

pub type CommitmentType = G1;

#[derive(Clone, Debug)]
pub enum Generator {
    G1(GeneratorG1),
    G2(GeneratorG2),
}
#[derive(Clone, Debug)]

pub enum Group {
    G1(G1),
    G2(G2),
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct GeneratorG1(pub G1);

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct GeneratorG2(pub G2);

impl Deref for GeneratorG1 {
    type Target = G1;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Deref for GeneratorG2 {
    type Target = G2;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Display for GeneratorG1 {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "G1({})", self.0)
    }
}

impl Display for GeneratorG2 {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "G2({})", self.0)
    }
}

impl From<G1> for GeneratorG1 {
    fn from(g: G1) -> Self {
        Self(g)
    }
}
