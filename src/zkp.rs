use amcl_wrapper::constants::CurveOrder;
use amcl_wrapper::field_elem::FieldElement;
use amcl_wrapper::group_elem::GroupElement;
use amcl_wrapper::group_elem_g2::G2;
use amcl_wrapper::types::BigNum;
use anyhow::Result;
use sha2::{Digest, Sha256};

pub struct ChallengeState {
    name: String,
    g_2: G2,
    statement: Vec<G2>,
    hash: [u8; 32],
}

pub type Challenge = FieldElement;
pub type Response = Vec<FieldElement>; // Vec<BigNum>;
/// Schnorr proof (non-interactive using Fiat Shamir heuristic) of the statement
/// ZK(x, m_1....m_n; h = g^x and h_1^m_1...h_n^m_n) and generilized version
pub struct ZkpSchnorrFiatShamir {}

impl ZkpSchnorrFiatShamir {
    fn new() -> Self {
        ZkpSchnorrFiatShamir {}
    }
    /// Setup for the Schnorr proof (non-interactive using FS heuristic) of the statement ZK(x ; h = g^x)
    /// How you make a Schnorr proof (Step by step):
    /// 1. Setup: (g, h) = setup()
    /// 2. Prover: (c, s) = prove((g, h), x)
    /// 3. Verifier: verify((g, h), c, s)
    ///
    pub fn setup() -> G2 {
        G2::generator()
    }

    /// The code below is from the original implementation of the Schnorr proof (non-interactive using FS heuristic) of the statement ZK(x ; h = g^x)
    fn challenge(state: &ChallengeState) -> FieldElement {
        // transform the state into a byte array
        let mut state_bytes = Vec::new();
        state_bytes.extend_from_slice(state.name.as_bytes());
        state_bytes.extend_from_slice(state.g_2.to_string().as_bytes());

        for stmt in &state.statement {
            state_bytes.extend_from_slice(stmt.to_string().as_bytes());
        }

        state_bytes.extend_from_slice(&state.hash);

        FieldElement::from_msg_hash(&state_bytes)
    }

    /// Schnorr proof (non-interactive using FS heuristic)
    pub fn non_interact_prove(
        g_2: &G2,
        stms: &Vec<G2>,
        secret_wit: &Vec<FieldElement>,
    ) -> Result<(Response, Challenge)> {
        // match on the statement

        // FieldElement::random() for each statement item
        let w_list = (0..stms.len())
            .map(|_| FieldElement::random())
            .collect::<Vec<FieldElement>>();

        // wit_list = [w_list[i] * g for i in range(len(w_list))]
        let witness_list = w_list.iter().map(|li| li * g_2).collect::<Vec<G2>>();

        // sum all w_list items into announcement
        let announcement = witness_list.iter().fold(G2::identity(), |acc, x| acc + x);

        // SHAKE3 hash the &announcement.to_bytes(false)
        let hash: [u8; 32] = Sha256::digest(announcement.to_bytes(false)).into();

        let state = ChallengeState {
            name: "schnorr".to_string(),
            g_2: g_2.clone(),
            statement: stms.clone(),
            hash,
        };

        // generate challenge. How do you take the modulo of the Group order using amcl_wrapper? I don't see a method for it. I'm using the modulo of the field order. Is that correct? I'm not sure how to do it with the group order. I'm using the modulo of the field order. Is that correct?
        // let mut c = BigNum::frombytes(&Self::challenge(&state).to_bytes());
        let mut c = Self::challenge(&state).to_bignum();
        c.rmod(&CurveOrder);

        // r = [(w_list[i] - c * secret_wit[i]) % o for i in range(len(secret_wit))], use rmod(&CurveOrder) instead of  `% o`
        let r = (0..secret_wit.len())
            .map(|i| {
                let a = w_list[i].clone();
                let b = FieldElement::try_from(c).unwrap() * secret_wit[i].clone();
                let mut r = BigNum::frombytes(&(a - b).to_bytes());
                r.rmod(&CurveOrder);
                r
            })
            .collect::<Vec<BigNum>>();

        let c: Challenge = FieldElement::from_hex(c.tostring()).unwrap();
        let r: Response = r
            .iter()
            .map(|x| FieldElement::from_hex(x.tostring()).unwrap())
            .collect::<Vec<FieldElement>>();

        Ok((r, c))
    }

    /// Verify the statement ZK(x ; h = g^x)
    pub fn non_interact_verify(g_2: &G2, stms: &[G2], proof_list: &(Response, Challenge)) -> bool {
        let (r, c) = proof_list;

        // W_list = [r[i] * g + c * stm[i] for i in range(len(r))]
        let w_list = (0..r.len())
            .map(|i| r[i].clone() * g_2 + c * stms[i].clone())
            .collect::<Vec<G2>>();
        // sum all w_list items into announcement
        let announcement = w_list.iter().fold(G2::identity(), |acc, x| acc + x);
        let state = ChallengeState {
            name: "schnorr".to_string(),
            g_2: g_2.clone(),
            statement: stms.to_vec(),
            hash: Sha256::digest(announcement.to_bytes(false)).into(),
        };
        let mut hash = Self::challenge(&state).to_bignum();
        hash.rmod(&CurveOrder);

        FieldElement::from_hex(hash.tostring()).unwrap() == *c
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_non_interact_prove() {
        // 0. ZkpSchnorrFiatShamir::new()
        // 1. Setup
        // 2. Prove
        // 3. Verify
        let g_2 = ZkpSchnorrFiatShamir::setup();
        let x = FieldElement::random();
        let h = x.clone() * g_2.clone();

        // create a vec of secrets for iter 0 to 5
        let secrets = (0..5)
            .map(|_| FieldElement::random())
            .collect::<Vec<FieldElement>>();

        // create stm for len of secrets, sec[i * g_2]
        let stm = secrets.iter().map(|s| s * g_2.clone()).collect::<Vec<G2>>();

        let proof_list /* (r, c) */ = ZkpSchnorrFiatShamir::non_interact_prove(&g_2, &stm, &secrets).unwrap();
        // let proof = (r, c);
        let result = ZkpSchnorrFiatShamir::non_interact_verify(&g_2, &stm, &proof_list);
        assert!(result);

        // create a proof for statement
        let proof_single =
            ZkpSchnorrFiatShamir::non_interact_prove(&g_2, &vec![h.clone()], &vec![x]).unwrap();
        let result_single =
            ZkpSchnorrFiatShamir::non_interact_verify(&g_2, &vec![h], &proof_single);
        assert!(result_single);
    }
}
