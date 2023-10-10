//! The Verification key is made up of a VK::G1 as the first element, and VK::G2 as subsequent. Due
//! to this fact, we need an enum to represent the VK.

use bls12_381_plus::{G1Projective, G2Projective};

/// Verification Key
/// This key has elements from both G1 and G2,
/// so to make a Vector of [VK], we need to use enum
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum VK {
    G1(G1Projective),
    G2(G2Projective),
}
