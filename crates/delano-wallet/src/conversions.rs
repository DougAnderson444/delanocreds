//! Module that contains conversion from Compressed crate type to Compresesed WIT types.
use crate::bindings::delano::wallet::types;
use delano_keys::vk::VKCompressed;
use delanocreds::{
    keypair::{
        CredProofCompressed, IssuerPublicCompressed, NymProofCompressed, SignatureCompressed,
    },
    set_commits::ParamSetCommitmentCompressed,
    zkp::{DamgardTransformCompressed, PedersenCompressed, PedersenOpenCompressed},
    *,
};

/// delanocreds::keypair::CredProofCompressed: TryFrom<types::CredProofCompressed>
impl From<types::CredProofCompressed> for CredProofCompressed {
    fn from(cred_proof: types::CredProofCompressed) -> Self {
        CredProofCompressed {
            sigma: cred_proof.sigma.into(),
            commitment_vector: cred_proof.commitment_vector,
            witness_pi: cred_proof.witness_pi,
            nym_proof: cred_proof.nym_proof.into(),
        }
    }
}

/// types::CredProofCompressed: From<delanocreds::keypair::CredProofCompressed>
impl From<CredProofCompressed> for types::CredProofCompressed {
    fn from(cred_proof: CredProofCompressed) -> Self {
        types::CredProofCompressed {
            sigma: cred_proof.sigma.into(),
            commitment_vector: cred_proof.commitment_vector,
            witness_pi: cred_proof.witness_pi,
            nym_proof: cred_proof.nym_proof.into(),
        }
    }
}

/// types::CredProofCompressed: From<&delanocreds::keypair::CredProofCompressed>
impl From<&CredProofCompressed> for types::CredProofCompressed {
    fn from(cred_proof: &CredProofCompressed) -> Self {
        types::CredProofCompressed {
            sigma: cred_proof.sigma.clone().into(),
            commitment_vector: cred_proof.commitment_vector.clone(),
            witness_pi: cred_proof.witness_pi.clone(),
            nym_proof: cred_proof.nym_proof.clone().into(),
        }
    }
}
/// delanocreds::keypair::SignatureCompressed: From<types::SignatureCompressed>
impl From<types::SignatureCompressed> for SignatureCompressed {
    fn from(signature: types::SignatureCompressed) -> Self {
        SignatureCompressed {
            z: signature.z,
            y_g1: signature.y_g1,
            y_hat: signature.y_hat,
            t: signature.t,
        }
    }
}

/// NymProofCompressed: From<types::NymProofCompressed>
impl From<types::NymProofCompressed> for NymProofCompressed {
    fn from(nym_proof: types::NymProofCompressed) -> Self {
        NymProofCompressed {
            challenge: nym_proof.challenge,
            pedersen_open: nym_proof.pedersen_open.into(),
            pedersen_commit: nym_proof.pedersen_commit,
            public_key: nym_proof.public_key,
            response: nym_proof.response,
            damgard: nym_proof.damgard.into(),
        }
    }
}

/// delanocreds::zkp::DamgardTransformCompressed: From<types::DamgardTransformCompressed>
impl From<types::DamgardTransformCompressed> for DamgardTransformCompressed {
    fn from(damgard: types::DamgardTransformCompressed) -> Self {
        DamgardTransformCompressed {
            pedersen: damgard.pedersen.into(),
        }
    }
}

/// delanocreds::zkp::PedersenCompressed: From<types::PedersenCompressed>
impl From<types::PedersenCompressed> for PedersenCompressed {
    fn from(pedersen: types::PedersenCompressed) -> Self {
        PedersenCompressed::from(pedersen.h)
    }
}

/// PedersenOpenCompressed: From<types::PedersenOpenCompressed>
impl From<types::PedersenOpenCompressed> for PedersenOpenCompressed {
    fn from(pedersen_open: types::PedersenOpenCompressed) -> Self {
        PedersenOpenCompressed {
            open_randomness: pedersen_open.open_randomness,
            announce_randomness: pedersen_open.announce_randomness,
            announce_element: pedersen_open.announce_element,
        }
    }
}

/// IssuerPublicCompressed: From<types::IssuerPublicCompressed>
impl From<types::IssuerPublicCompressed> for IssuerPublicCompressed {
    fn from(issuer_public: types::IssuerPublicCompressed) -> Self {
        IssuerPublicCompressed {
            parameters: issuer_public.parameters.into(),
            vk: issuer_public.vk.iter().map(|vk| vk.into()).collect(),
        }
    }
}

/// VKCompressed: From<&types::VkCompressed>
impl From<&types::VkCompressed> for VKCompressed {
    fn from(vk: &types::VkCompressed) -> Self {
        match vk {
            types::VkCompressed::G1(g1) => VKCompressed::G1(g1.to_vec()),
            types::VkCompressed::G2(g2) => VKCompressed::G2(g2.to_vec()),
        }
    }
}

/// ParamSetCommitmentCompressed: From<types::ParamSetCommitmentCompressed>
impl From<types::ParamSetCommitmentCompressed> for ParamSetCommitmentCompressed {
    fn from(param_set_commitment: types::ParamSetCommitmentCompressed) -> Self {
        ParamSetCommitmentCompressed {
            pp_commit_g1: param_set_commitment.pp_commit_g1,
            pp_commit_g2: param_set_commitment.pp_commit_g2,
        }
    }
}

/// types::SignatureCompressed: From<delanocreds::keypair::SignatureCompressed>
impl From<SignatureCompressed> for types::SignatureCompressed {
    fn from(signature: SignatureCompressed) -> Self {
        types::SignatureCompressed {
            z: signature.z,
            y_g1: signature.y_g1,
            y_hat: signature.y_hat,
            t: signature.t,
        }
    }
}

/// types::NymProofCompressed: From<delanocreds::keypair::NymProofCompressed>a
impl From<NymProofCompressed> for types::NymProofCompressed {
    fn from(nym_proof: NymProofCompressed) -> Self {
        types::NymProofCompressed {
            challenge: nym_proof.challenge,
            pedersen_open: nym_proof.pedersen_open.clone().into(),
            pedersen_commit: nym_proof.pedersen_commit,
            public_key: nym_proof.public_key,
            response: nym_proof.response,
            damgard: nym_proof.damgard.clone().into(),
        }
    }
}

/// types::DamgardTransformCompressed: From<delanocreds::zkp::DamgardTransformCompressed>
impl From<DamgardTransformCompressed> for types::DamgardTransformCompressed {
    fn from(damgard: DamgardTransformCompressed) -> Self {
        types::DamgardTransformCompressed {
            pedersen: damgard.pedersen.clone().into(),
        }
    }
}

/// types::PedersenCompressed: From<delanocreds::zkp::PedersenCompressed>
impl From<PedersenCompressed> for types::PedersenCompressed {
    fn from(pedersen: PedersenCompressed) -> Self {
        types::PedersenCompressed { h: pedersen.h() }
    }
}

/// types::PedersenOpenCompressed: From<delanocreds::zkp::PedersenOpenCompressed>
impl From<PedersenOpenCompressed> for types::PedersenOpenCompressed {
    fn from(pedersen_open: PedersenOpenCompressed) -> Self {
        types::PedersenOpenCompressed {
            open_randomness: pedersen_open.open_randomness,
            announce_randomness: pedersen_open.announce_randomness,
            announce_element: pedersen_open.announce_element,
        }
    }
}

/// types::IssuerPublicCompressed: From<&delanocreds::keypair::IssuerPublicCompressed>
impl From<&IssuerPublicCompressed> for types::IssuerPublicCompressed {
    fn from(issuer_public: &IssuerPublicCompressed) -> Self {
        types::IssuerPublicCompressed {
            parameters: issuer_public.parameters.clone().into(),
            vk: issuer_public.vk.iter().map(|vk| vk.into()).collect(),
        }
    }
}

/// types::IssuerPublicCompressed: From<delanocreds::keypair::IssuerPublicCompressed>
impl From<IssuerPublicCompressed> for types::IssuerPublicCompressed {
    fn from(issuer_public: IssuerPublicCompressed) -> Self {
        types::IssuerPublicCompressed {
            parameters: issuer_public.parameters.into(),
            vk: issuer_public.vk.iter().map(|vk| vk.into()).collect(),
        }
    }
}

/// types::ParamSetCommitmentCompressed: From<delanocreds::set_commits::ParamSetCommitmentCompressed>
impl From<ParamSetCommitmentCompressed> for types::ParamSetCommitmentCompressed {
    fn from(param_set_commitment: ParamSetCommitmentCompressed) -> Self {
        types::ParamSetCommitmentCompressed {
            pp_commit_g1: param_set_commitment.pp_commit_g1,
            pp_commit_g2: param_set_commitment.pp_commit_g2,
        }
    }
}

/// types::VkCompressed: From<&delano_keys::vk::VKCompressed>
impl From<&VKCompressed> for types::VkCompressed {
    fn from(vk: &VKCompressed) -> Self {
        match vk {
            VKCompressed::G1(g1) => types::VkCompressed::G1(g1.to_vec()),
            VKCompressed::G2(g2) => types::VkCompressed::G2(g2.to_vec()),
        }
    }
}

/// types::CredentialCompressed: From<delanocreds::CredentialCompressed>
impl From<CredentialCompressed> for types::CredentialCompressed {
    fn from(cred: CredentialCompressed) -> Self {
        types::CredentialCompressed {
            commitment_vector: cred.commitment_vector,
            issuer_public: cred.issuer_public.into(),
            opening_vector: cred.opening_vector,
            sigma: cred.sigma.into(),
            update_key: cred.update_key,
        }
    }
}

/// types::CredentialCompressed: From<&delanocreds::CredentialCompressed>
impl From<&CredentialCompressed> for types::CredentialCompressed {
    fn from(cred: &CredentialCompressed) -> Self {
        types::CredentialCompressed {
            commitment_vector: cred.commitment_vector.clone(),
            issuer_public: cred.issuer_public.clone().into(),
            opening_vector: cred.opening_vector.clone(),
            sigma: cred.sigma.clone().into(),
            update_key: cred.update_key.clone(),
        }
    }
}

/// delanocreds::CredentialCompressed: From<types::CredentialCompressed>
impl From<types::CredentialCompressed> for CredentialCompressed {
    fn from(cred: types::CredentialCompressed) -> Self {
        CredentialCompressed {
            commitment_vector: cred.commitment_vector,
            issuer_public: cred.issuer_public.into(),
            opening_vector: cred.opening_vector,
            sigma: cred.sigma.into(),
            update_key: cred.update_key,
        }
    }
}

#[cfg(test)]
mod conversion_tests {
    use super::*;

    // Size summary of NymProofCompressed:
    // | Field             | Size (bytes) |
    // |-------------------|--------------|
    // | challenge         | 32           |
    // | pedersen_open     | 112          |
    // | pedersen_commit   | 48           |
    // | public_key        | 48           |
    // | response          | 32           |
    // | damgard           | 48           |
    // | Total             | 320          |
    #[test]
    fn test_nym_proof_decompress_roundtrip() {
        let npc = types::NymProofCompressed {
            challenge: vec![69u8; 32], //Scalar bytes is 32
            pedersen_open: types::PedersenOpenCompressed {
                announce_randomness: vec![69u8; 32],    // Scalar bytes is 32
                open_randomness: vec![69u8; 32],        // Scalar bytes is 32
                announce_element: Some(vec![69u8; 48]), // G1Affine bytes is 48
            },
            pedersen_commit: vec![69u8; 48], // G1Affine bytes is 48
            public_key: vec![69u8; 48],      // G1Affine bytes is 48
            response: vec![69u8; 32],        // Scalar bytes is 32
            damgard: types::DamgardTransformCompressed {
                pedersen: types::PedersenCompressed { h: vec![69u8; 48] }, // G1 compressed bytes is 48
            },
        };

        let npc2 = NymProofCompressed::from(npc.clone());
        let npc3 = types::NymProofCompressed::from(npc2);
        assert_eq!(npc, npc3);
    }

    // CredProofCompressed rount trip
    #[test]
    fn test_cred_proof_compressed_round_trip() {
        let cpc = types::CredProofCompressed {
            sigma: types::SignatureCompressed {
                z: vec![69u8; 48],     // G1 compressed bytes is 48
                y_g1: vec![69u8; 48],  // G1 compressed bytes is 48
                y_hat: vec![69u8; 96], // G2 compressed bytes is 96
                t: vec![69u8; 48],     // G1 compressed bytes is 48
            },
            commitment_vector: vec![vec![69u8; 48]], // G1 compressed bytes is 48
            witness_pi: vec![69u8; 48],              // G1 compressed bytes is 48
            nym_proof: types::NymProofCompressed {
                challenge: vec![69u8; 32], //Scalar bytes is 32
                pedersen_open: types::PedersenOpenCompressed {
                    announce_randomness: vec![69u8; 32],    // Scalar bytes is 32
                    open_randomness: vec![69u8; 32],        // Scalar bytes is 32
                    announce_element: Some(vec![69u8; 48]), // G1Affine bytes is 48
                },
                pedersen_commit: vec![69u8; 48], // G1Affine bytes is 48
                public_key: vec![69u8; 48],      // G1Affine bytes is 48
                response: vec![69u8; 32],        // Scalar bytes is 32
                damgard: types::DamgardTransformCompressed {
                    pedersen: types::PedersenCompressed { h: vec![69u8; 48] }, // G1 compressed bytes is 48
                },
            },
        };

        let cpc2 = CredProofCompressed::from(cpc.clone());
        let cpc3 = types::CredProofCompressed::from(cpc2);
        assert_eq!(cpc, cpc3);
    }

    // SignatureCompressed, size summary
    // | Field             | Size (bytes) |
    // |-------------------|--------------|
    // | z                 | 48           |
    // | y_g1              | 48           |
    // | y_hat             | 96           |
    // | t                 | 48           |
    // | Total             | 240          |
    #[test]
    fn test_signature_compressed_round_trip() {
        let sc = types::SignatureCompressed {
            z: vec![69u8; 48],     // G1 compressed bytes is 48
            y_g1: vec![69u8; 48],  // G1 compressed bytes is 48
            y_hat: vec![69u8; 96], // G2 compressed bytes is 96
            t: vec![69u8; 48],     // G1 compressed bytes is 48
        };

        let sc2 = SignatureCompressed::from(sc.clone());
        let sc3 = types::SignatureCompressed::from(sc2);
        assert_eq!(sc, sc3);
    }

    // DamgardTransformCompressed
    #[test]
    fn test_damgard_transform_compressed_round_trip() {
        let dtc = types::DamgardTransformCompressed {
            pedersen: types::PedersenCompressed { h: vec![69u8; 48] }, // G1 compressed bytes is 48
        };

        let dtc2 = DamgardTransformCompressed::from(dtc.clone());
        let dtc3 = types::DamgardTransformCompressed::from(dtc2);
        assert_eq!(dtc, dtc3);
    }

    // PedersenCompressed
    #[test]
    fn test_pedersen_compressed_round_trip() {
        let pc = types::PedersenCompressed { h: vec![69u8; 48] }; // G1 compressed bytes is 48

        let pc2 = PedersenCompressed::from(pc.clone());
        let pc3 = types::PedersenCompressed::from(pc2);
        assert_eq!(pc, pc3);
    }

    // PedersenOpenCompressed
    #[test]
    fn test_pedersen_open_compressed_round_trip() {
        let poc = types::PedersenOpenCompressed {
            announce_randomness: vec![69u8; 32],    // Scalar bytes is 32
            open_randomness: vec![69u8; 32],        // Scalar bytes is 32
            announce_element: Some(vec![69u8; 48]), // G1Affine bytes is 48
        };

        let poc2 = PedersenOpenCompressed::from(poc.clone());
        let poc3 = types::PedersenOpenCompressed::from(poc2);
        assert_eq!(poc, poc3);
    }

    // IssuerPublicCompressed
    #[test]
    fn test_issuer_public_compressed_round_trip() {
        let ipc = types::IssuerPublicCompressed {
            parameters: types::ParamSetCommitmentCompressed {
                pp_commit_g1: vec![vec![69u8; 48]], // G1 compressed bytes is 48
                pp_commit_g2: vec![vec![69u8; 96]], // G2 compressed bytes is 96
            },
            vk: vec![
                types::VkCompressed::G1(vec![69u8; 48]),
                types::VkCompressed::G2(vec![69u8; 96]),
            ],
        };

        let ipc2 = IssuerPublicCompressed::from(ipc.clone());
        let ipc3 = types::IssuerPublicCompressed::from(ipc2);
        assert_eq!(ipc, ipc3);
    }

    // VKCompressed
    #[test]
    fn test_vk_compressed_round_trip() {
        let vkc = types::VkCompressed::G1(vec![69u8; 48]);

        let vkc2 = VKCompressed::from(&vkc);
        let vkc3 = types::VkCompressed::from(&vkc2);
        assert_eq!(vkc, vkc3);
    }

    // ParamSetCommitmentCompressed
    #[test]
    fn test_param_set_commitment_compressed_round_trip() {
        let psc = types::ParamSetCommitmentCompressed {
            pp_commit_g1: vec![vec![69u8; 48]], // G1 compressed bytes is 48
            pp_commit_g2: vec![vec![69u8; 96]], // G2 compressed bytes is 96
        };

        let psc2 = ParamSetCommitmentCompressed::from(psc.clone());
        let psc3 = types::ParamSetCommitmentCompressed::from(psc2);
        assert_eq!(psc, psc3);
    }

    // CredentialCompressed
    #[test]
    fn test_credential_compressed_round_trip() {
        let cc = types::CredentialCompressed {
            commitment_vector: vec![vec![69u8; 48]], // G1 compressed bytes is 48
            issuer_public: types::IssuerPublicCompressed {
                parameters: types::ParamSetCommitmentCompressed {
                    pp_commit_g1: vec![vec![69u8; 48]], // G1 compressed bytes is 48
                    //
                    pp_commit_g2: vec![vec![69u8; 96]], // G2 compressed bytes is 96
                },
                vk: vec![
                    types::VkCompressed::G1(vec![69u8; 48]),
                    types::VkCompressed::G2(vec![69u8; 96]),
                ],
            },
            opening_vector: vec![vec![69u8; 48]], // G1 compressed bytes is 48
            sigma: types::SignatureCompressed {
                z: vec![69u8; 48],     // G1 compressed bytes is 48
                y_g1: vec![69u8; 48],  // G1 compressed bytes is 48
                y_hat: vec![69u8; 96], // G2 compressed bytes is 96
                t: vec![69u8; 48],     // G1 compressed bytes is 48
            },
            update_key: Some(vec![vec![vec![69u8; 48]]]), // G1 compressed bytes is 48
        };

        let cc2 = CredentialCompressed::from(cc.clone());
        let cc3 = types::CredentialCompressed::from(cc2);
        assert_eq!(cc, cc3);
    }
}
