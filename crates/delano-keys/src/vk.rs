//! The Verification Key ([VK]) is made up of a [VK::G1] as the first element, and [VK::G2] as subsequent. Due
//! to this fact, we need an enum to represent the [VK].

use blastkids::GroupEncoding;
use bls12_381_plus::{G1Affine, G2Affine};
use bls12_381_plus::{G1Projective, G2Projective};

/// Verification Key [VK]
/// This key has elements from both [G1Projective] and [G2Projective],
/// so to make a Vector of [VK], we need to use enum
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VK {
    G1(G1Projective),
    G2(G2Projective),
}

impl VK {
    /// Convert the [VK] to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            VK::G1(g1) => g1.to_compressed().to_vec(),
            VK::G2(g2) => g2.to_compressed().to_vec(),
        }
    }
}

/// VKCompact is a [VK] but just the [G1Compressed] and the first [G2Compressed]
#[derive(Debug, Clone, PartialEq)]
pub struct VKCompact {
    pub g1: [u8; G1Affine::COMPRESSED_BYTES],
    pub g2: [u8; G2Affine::COMPRESSED_BYTES],
}

impl VKCompact {
    /// Creates a new [VKCompact] from [G1Affine] and [G2Affine]
    pub fn new(g1: G1Affine, g2: G2Affine) -> Self {
        Self {
            g1: g1.to_compressed(),
            g2: g2.to_compressed(),
        }
    }
}

/// Trys to convert a Vec<[VK]> to a [VKCompact] by taking the first G1 and the first G2
impl TryFrom<Vec<VK>> for VKCompact {
    type Error = String;

    fn try_from(vk: Vec<VK>) -> Result<Self, Self::Error> {
        if vk.is_empty() {
            return Err("Empty VK".to_string());
        }

        let g1 = match &vk[0] {
            VK::G1(g1) => g1.to_compressed(),
            VK::G2(_) => return Err("First element is not G1".to_string()),
        };

        let g2 = match &vk[1] {
            VK::G2(g2) => g2.to_compressed(),
            VK::G1(_) => return Err("Second element is not G2".to_string()),
        };

        Ok(Self { g1, g2 })
    }
}

/// A Verification Key [VK] in compressed form as [VKCompressed]
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum VKCompressed {
    G1(Vec<u8>),
    G2(Vec<u8>),
}

/// From [VK] to [VKCompressed]
impl From<VK> for VKCompressed {
    fn from(vk: VK) -> Self {
        match vk {
            VK::G1(g1) => Self::G1(g1.to_compressed().into()),
            VK::G2(g2) => Self::G2(g2.to_compressed().into()),
        }
    }
}

/// From &[VK] to [VKCompressed]
impl From<&VK> for VKCompressed {
    fn from(vk: &VK) -> Self {
        match vk {
            VK::G1(g1) => Self::G1(g1.to_compressed().into()),
            VK::G2(g2) => Self::G2(g2.to_compressed().into()),
        }
    }
}

/// TryFrom [VKCompressed] to [VK]
impl std::convert::TryFrom<VKCompressed> for VK {
    type Error = String;

    fn try_from(vk_compressed: VKCompressed) -> Result<Self, Self::Error> {
        match vk_compressed {
            VKCompressed::G1(g1) => {
                let mut bytes = [0u8; G1Affine::COMPRESSED_BYTES];
                bytes.copy_from_slice(g1.as_ref());
                let g1_maybe = G1Affine::from_compressed(&bytes);

                if g1_maybe.is_none().into() {
                    return Err("Invalid G1 point".to_string());
                }

                Ok(VK::G1(g1_maybe.unwrap().into()))
            }
            VKCompressed::G2(g2) => {
                let mut g2_bytes = [0u8; G2Affine::COMPRESSED_BYTES];
                g2_bytes.copy_from_slice(g2.as_ref());
                let g2 = G2Affine::from_compressed(&g2_bytes);

                if g2.is_none().into() {
                    return Err("Invalid G2 point".to_string());
                }

                Ok(VK::G2(g2.unwrap().into()))
            }
        }
    }
}

/// Implement TryFrom<Vec<u8>> for Verification Key [VK]
/// This is used to convert a Vec<u8> into a [VK] enum variant
impl std::convert::TryFrom<Vec<u8>> for VK {
    type Error = String;

    fn try_from(v: Vec<u8>) -> Result<Self, Self::Error> {
        match v.len() {
            48 => {
                let mut bytes = [0u8; G1Affine::COMPRESSED_BYTES];
                bytes.copy_from_slice(&v[..]);
                let g1_maybe = G1Affine::from_compressed(&bytes);

                if g1_maybe.is_none().into() {
                    return Err("Invalid G1 point".to_string());
                }

                Ok(VK::G1(g1_maybe.unwrap().into()))
            }
            96 => {
                let mut g2_bytes = [0u8; G2Affine::COMPRESSED_BYTES];
                g2_bytes.copy_from_slice(&v[..]);
                let g2 = G2Affine::from_compressed(&g2_bytes);

                if g2.is_none().into() {
                    return Err("Invalid G2 point".to_string());
                }

                Ok(VK::G2(g2.unwrap().into()))
            }
            _ => Err("Invalid Verification Key (VK) length".to_string()),
        }
    }
}

impl TryFrom<&Vec<u8>> for VKCompressed {
    type Error = String;

    fn try_from(v: &Vec<u8>) -> Result<Self, Self::Error> {
        match v.len() {
            48 => {
                let mut bytes = [0u8; 48];
                bytes.copy_from_slice(&v[..]);
                let g1_maybe = G1Affine::from_compressed(&bytes);

                if g1_maybe.is_none().into() {
                    return Err("Invalid G1 point".to_string());
                }

                Ok(VKCompressed::G1(g1_maybe.unwrap().to_bytes().into()))
            }
            96 => {
                let mut g2_bytes = [0u8; 96];
                g2_bytes.copy_from_slice(&v[..]);
                let g2 = G2Affine::from_compressed(&g2_bytes);

                if g2.is_none().into() {
                    return Err("Invalid G2 point".to_string());
                }

                Ok(VKCompressed::G2(g2.unwrap().to_bytes().into()))
            }
            _ => Err("Invalid Verification Key (VK) length".to_string()),
        }
    }
}

/// Implement AsRef<u8> for Verification Key compressed [VKCompressed]
impl AsRef<[u8]> for VKCompressed {
    fn as_ref(&self) -> &[u8] {
        match self {
            VKCompressed::G1(g1) => g1.as_ref(),
            VKCompressed::G2(g2) => g2.as_ref(),
        }
    }
}

/// Impl From<Vec<u8>> for [VKCompressed]
impl From<Vec<u8>> for VKCompressed {
    fn from(v: Vec<u8>) -> Self {
        match v.len() {
            48 => {
                let mut bytes = [0u8; 48];
                bytes.copy_from_slice(&v[..]);
                let g1_maybe = G1Affine::from_compressed(&bytes);

                if g1_maybe.is_none().into() {
                    panic!("Invalid G1 point");
                }

                VKCompressed::G1(g1_maybe.unwrap().to_bytes().into())
            }
            96 => {
                let mut g2_bytes = [0u8; 96];
                g2_bytes.copy_from_slice(&v[..]);
                let g2 = G2Affine::from_compressed(&g2_bytes);

                if g2.is_none().into() {
                    panic!("Invalid G2 point");
                }

                VKCompressed::G2(g2.unwrap().to_bytes().into())
            }
            _ => panic!("Invalid VK length"),
        }
    }
}

#[cfg(test)]
mod vk_tests {
    use blastkids::Group;

    use super::*;

    #[test]
    fn test_vk_compressed() {
        let vk = VK::G1(G1Projective::random(&mut rand::thread_rng()));
        let vk_compressed: VKCompressed = vk.clone().into();
        let vk2: VK = vk_compressed.try_into().unwrap();

        assert_eq!(vk, vk2);

        // G2
        let vk = VK::G2(G2Projective::random(&mut rand::thread_rng()));
        let vk_compressed: VKCompressed = vk.clone().into();
        let vk2: VK = vk_compressed.try_into().unwrap();

        assert_eq!(vk, vk2);
    }
}
