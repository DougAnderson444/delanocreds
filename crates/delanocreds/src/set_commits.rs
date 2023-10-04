use crate::ec::curve::{pairing, polynomial_from_roots, Gt};
use crate::ec::univarpoly::UnivarPolynomial;
use crate::ec::{G1Projective, G2Projective, Scalar};
use crate::entry::entry_to_scalar;
use crate::entry::Entry;
use crate::keypair::MaxCardinality;
use bls12_381_plus::elliptic_curve::bigint::{self, Encoding};
use bls12_381_plus::elliptic_curve::ops::MulByGenerator;
use bls12_381_plus::ff::Field;
use bls12_381_plus::group::{Curve, Group};
use rand::rngs::ThreadRng;
use secrecy::ExposeSecret;
use secrecy::Secret;
use sha2::{Digest, Sha256};

/// Public Parameters of the Set Commitment
/// - `pp_commit_g1`: Root Issuer's public parameters commitment for G1
/// - `pp_commit_g2`: Root Issuer's public parameter commitment for G2
#[derive(Clone, Debug)]
pub struct ParamSetCommitment {
    pub pp_commit_g1: Vec<G1Projective>,
    pub pp_commit_g2: Vec<G2Projective>,
}

impl ParamSetCommitment {
    /// New constructor. Initializes the ParamSetCommitment
    ///
    /// # Arguments
    /// t: [MaxCardinality] of the set. Cardinality of the set is in [1, t]. t is a public parameter.
    ///
    /// # Returns
    /// ParamSetCommitment
    pub fn new(t: &usize) -> ParamSetCommitment {
        let base: Secret<Scalar> = Secret::new(Scalar::random(ThreadRng::default())); // security parameter λ

        // pp_commit_g1 and pp_commit_g2 are vectors of G1 and G2 elements respectively.
        // They are used to compute the commitment and witness.
        // The number of polynomial coefficients is one more than the degree of the polynomial.
        // Since `pp_commit_g2` is used to compute the witness, we need to add one more element to the vector.
        // Hence use [..=] instead of [..] to ensure the last element is included.
        let pp_commit_g1 = (0..=*t)
            .map(|i| {
                G1Projective::mul_by_generator(&base.expose_secret().pow(&[i as u64, 0, 0, 0]))
            })
            .collect::<Vec<G1Projective>>();
        let pp_commit_g2 = (0..=*t)
            .map(|i| {
                G2Projective::mul_by_generator(&base.expose_secret().pow(&[i as u64, 0, 0, 0]))
            })
            .collect::<Vec<G2Projective>>();

        ParamSetCommitment {
            pp_commit_g2,
            pp_commit_g1,
        }
    }
}

/// Public trait Commitment common for both SetCommitment and CrossSetCommitment
/// This trait is used to define the common functions for both SetCommitment and CrossSetCommitment
pub trait Commitment {
    /// Creates a new commitment scheme.
    ///
    /// # Arguments
    /// - `t`: max cardinality of the set. Cardinality of the set is in [1, t]. t is a public parameter.
    ///
    /// # Returns
    /// A Commitment scheme, either SetCommitment or CrossSetCommitment
    fn new(t: MaxCardinality) -> Self;

    /// Public parameters of the commitment scheme.
    fn public_parameters(self) -> ParamSetCommitment;

    /// Commit to a set of messages
    ///
    /// # Arguments
    /// `param_sc`: [ParamSetCommitment] public parameters for the commitment scheme, as P^ai, P_hat^ai, P = g1, P_hat = g2, Order, BG
    /// `mess_set_str`: a vector of [Entry]s
    ///
    /// # Returns
    /// Tuple of (commitment, witness) if
    ///
    /// # Method
    /// 1. Convert the message set to a vector of Scalars
    /// 2. Compute the commitment as a product of P^ai, P_hat^ai, where ai is the ith element of the message set
    /// 3. Compute the witness as a product of P^ai, P_hat^ai, where ai is the ith element of the message set
    /// 4. Return the commitment and witness
    fn commit_set(param_sc: &ParamSetCommitment, mess_set_str: &Entry) -> (G1Projective, Scalar) {
        let mess_set: Vec<Scalar> = entry_to_scalar(mess_set_str);
        eprintln!("mess_set length: {:?}", mess_set.len());
        let monypol_coeff = polynomial_from_roots(&mess_set);
        eprintln!(
            "monypol_coeff length: {:?}",
            monypol_coeff.coefficients().len()
        );
        let pre_commit = generate_pre_commit(monypol_coeff, param_sc);

        let open_info = Scalar::random(ThreadRng::default());

        // multiply pre_commit by rho (open_info = rho). Rho is a random element in Zp. Zp is the set of integers modulo p.
        let commitment = pre_commit * open_info;
        (commitment, open_info)
    }

    /// Open a commitment to a set of messages. This is the verification step. Verifies the opening information of a set.
    ///
    /// # Arguments
    ///
    /// param_sc: public parameters for the commitment scheme, as P^ai, P_hat^ai, P = g1, P_hat = g2, Order, BG
    /// commitment: commitment to a set of messages
    /// open_info: opening information of the commitment
    /// mess_set_str: a message set as a string
    ///
    /// # Returns
    ///
    /// bool: true if the opening information is valid, false otherwise
    fn open_set(
        param_sc: &ParamSetCommitment,
        commitment: &G1Projective,
        open_info: &Scalar,
        mess_set_str: &Entry,
    ) -> bool {
        let mess_set: Vec<Scalar> = entry_to_scalar(mess_set_str);
        let monypol_coeff = polynomial_from_roots(&mess_set);
        let pre_commit = generate_pre_commit(monypol_coeff, param_sc);

        // multiply pre_commit by rho. Rho is a random element in Zp. Zp is the set of integers modulo p.
        let commitment_check = pre_commit * open_info;

        *commitment == commitment_check
    }

    /// Opens a subet of Attributes for an Entry
    /// `open_subset` generates a witness for the subset only if
    /// the length of the subset is less than the length of the message set
    ///
    /// # Arguments
    ///
    /// param_sc: public parameters for the commitment scheme, as P^ai, P_hat^ai, P = g1, P_hat = g2, Order, BG
    /// mess_set_str: the message set
    /// open_info: opening information of the commitment
    /// subset_str: the subset of the message set
    ///
    /// # Returns
    /// Some witness for the subset or None if the subset is not a subset of the message set
    fn open_subset(
        param_sc: &ParamSetCommitment,
        all_messages: &Entry,
        open_info: &Scalar,
        subset: &Entry,
    ) -> Option<G1Projective> {
        if open_info.is_zero().into() {
            return None;
        }

        let mess_set: Vec<Scalar> = entry_to_scalar(all_messages);
        let mess_subset_t = entry_to_scalar(subset);

        // check if mess_subset is a subset of mess_set
        // compare the lengths of the two vectors
        if mess_subset_t.len() > mess_set.len() {
            return None;
        }

        // now, for each item in mess_subset_t, if item is in mess_set, checker = true, else checker = false
        // check to ensure all messages in mess_subset_t are in mess_set
        if !mess_subset_t.iter().all(|item| mess_set.contains(item)) {
            return None;
        }

        // creates a list of elements that are in mess_set but not in mess_subset_t,
        // use into_iter() to consume the owned value (mess_set) and return an iterator
        let create_witn_elements: Vec<Scalar> = mess_set
            .into_iter()
            .filter(|itm| !mess_subset_t.contains(itm))
            .collect::<Vec<Scalar>>();

        // compute a witness for the subset
        let coeff_witn = polynomial_from_roots(&create_witn_elements);
        let witn_sum = generate_pre_commit(coeff_witn, param_sc);

        let witness = witn_sum * open_info;
        Some(witness)
    }

    /// VerifySubset verifies the witness for the subset. Verifies if witness proves that subset_str is a subset of the original message set.
    ///
    /// # Arguments
    ///
    /// param_sc: public parameters for the commitment scheme, as P^ai, P_hat^ai, P = g1, P_hat = g2, Order, BG
    /// commitment: commitment to a set of messages
    /// subset_str: the subset of the message set
    /// witness: witness for the subset
    ///
    /// # Returns
    ///
    /// bool: true if the witness is valid, false otherwise
    fn verify_subset(
        param_sc: &ParamSetCommitment,
        commitment: &G1Projective,
        subset_str: &Entry,
        witness: &G1Projective,
    ) -> bool {
        let mess_subset_t: Vec<Scalar> = entry_to_scalar(subset_str);
        let coeff_t = polynomial_from_roots(&mess_subset_t);

        let subset_group_elements = param_sc
            .pp_commit_g2
            .iter()
            .zip(coeff_t.coefficients().iter())
            .map(|(g2, coeff)| g2 * coeff)
            .collect::<Vec<G2Projective>>();

        // sum all points
        let subset_elements_sum = subset_group_elements
            .iter()
            .fold(G2Projective::IDENTITY, |acc, x| acc + x);

        pairing(witness, &subset_elements_sum) == pairing(commitment, &G2Projective::GENERATOR)
    }
}

pub struct SetCommitment {
    param_sc: ParamSetCommitment,
}

// impl all default traits for SetCommitment
impl Commitment for SetCommitment {
    /// Creates a new commitment scheme.
    ///
    /// # Arguments
    /// - `t`: max cardinality of the set. Cardinality of the set is in [1, t]. t is a public parameter.
    ///
    /// # Returns
    /// A Commitment scheme, either SetCommitment or CrossSetCommitment
    fn new(t: MaxCardinality) -> Self {
        // return union type of SetCommitment and CrossSetCommitment.
        // A Rust union type is a type that can store only one of its members at a time.
        // ie. it can be either SetCommitment or CrossSetCommitment.
        // it looks like: `pub enum Commitment { SetCommitment(SetCommitment), CrossSetCommitment(CrossSetCommitment) }`
        Self {
            param_sc: ParamSetCommitment::new(&t),
        }
    }

    fn public_parameters(self) -> ParamSetCommitment {
        self.param_sc
    }
}

/// CrossSetCommitment extends the Set Commitment to provide aggregation witness and a batch verification
/// - `param_sc`: [`ParamSetCommitment`] public parameters for the commitment scheme, as P^ai, P_hat^ai, P = g1, P_hat = g2, Order, BG
pub struct CrossSetCommitment {
    pub param_sc: ParamSetCommitment,
}

// impl all default traits for CrossSetCommitment
impl Commitment for CrossSetCommitment {
    /// Creates a new commitment scheme.
    ///
    /// # Arguments
    /// - `t`: max cardinality of the set. Cardinality of the set is in [1, t]. t is a public parameter.
    ///
    /// # Returns
    /// A Commitment scheme, for CrossSetCommitment
    fn new(t: MaxCardinality) -> Self {
        CrossSetCommitment {
            param_sc: ParamSetCommitment::new(&t),
        }
    }

    /// Exports the public parameters of the commitment scheme.
    /// Values are borrowed from the commitment scheme.
    /// If the user needs the values to outlive the commitment scheme, they should clone the values.
    fn public_parameters(self) -> ParamSetCommitment {
        self.param_sc
    }
}

/// CrossSetCommitment is a commitment scheme that extends the Set Commitment to provide aggregation witness and a batch verification
impl CrossSetCommitment {
    /// Computes an aggregate proof of valid subsets of a set of messages.
    ///
    /// # Arguments
    /// witness_vector: a vector of witnessess
    /// commit_vector: the commitment vector
    ///
    /// # Returns
    /// a proof which is a aggregate of witnesses and shows all subsets are valid for respective sets
    pub fn aggregate_cross(
        witness_vector: &[G1Projective],
        commit_vector: &[G1Projective],
    ) -> G1Projective {
        // sum all elements in all witness_vectors
        witness_vector.iter().zip(commit_vector.iter()).fold(
            G1Projective::identity(),
            |acc, (witness, commit)| {
                let hash_i = hash_to_scalar(commit);
                acc + witness * hash_i
            },
        )
    }

    /// Verifies an aggregate proof of valid subsets of a set of messages.
    /// Filters out any selected [Entry]s that are empty
    ///
    /// # Arguments
    /// param_sc: public parameters
    /// commit_vector: the commitment vector
    /// entry_subsets_vector: Vector of sleected [Entry]s
    /// proof: a proof which is a aggregate of witnesses
    ///
    /// # Returns
    /// true if the proof is valid, false otherwise
    pub fn verify_cross(
        param_sc: &ParamSetCommitment,
        commit_vector: &[G1Projective],
        selected_entry_subset_vector: &[Entry],
        proof: &G1Projective,
    ) -> bool {
        // Steps:
        // 1. convert message str into the BN
        let subsets_vector: Vec<Vec<Scalar>> = selected_entry_subset_vector
            .iter()
            .enumerate()
            .filter(|(_, entry)| !entry.is_empty())
            .map(|(_, entry)| entry_to_scalar(entry))
            .collect();

        // create a union of sets
        let set_s = subsets_vector
            .iter()
            .fold(Vec::new(), |mut acc, x| {
                acc.extend(x.clone());
                acc
            })
            .into_iter()
            .collect::<Vec<Scalar>>();

        let coeff_set_s = polynomial_from_roots(&set_s);

        // 2. compute right side of verification, pp_commit_g2
        let set_s_group_element = param_sc
            .pp_commit_g2
            .iter()
            .zip(coeff_set_s.coefficients().iter())
            .map(|(g2, coeff)| g2 * coeff)
            .collect::<Vec<G2Projective>>();

        let set_s_elements_sum = set_s_group_element
            .iter()
            .fold(G2Projective::IDENTITY, |acc, x| acc + x);

        // right_side is the pairing of proof and set_s_elements_sum
        let right_side = pairing(proof, &set_s_elements_sum);

        let set_s_not_t = subsets_vector
            .into_iter()
            .map(|x| not_intersection(&set_s, x))
            .collect::<Vec<Vec<Scalar>>>();

        // 3. compute left side of verification
        let vector_gt = commit_vector
            .iter()
            .zip(set_s_not_t.iter())
            .map(|(commit, set_s_not_t)| {
                let coeff_s_not_t = polynomial_from_roots(set_s_not_t);

                let listpoints_s_not_t = param_sc
                    .pp_commit_g2
                    .iter()
                    .zip(coeff_s_not_t.coefficients().iter())
                    .map(|(g2, coeff)| g2 * coeff)
                    .collect::<Vec<G2Projective>>();

                let temp_sum = listpoints_s_not_t
                    .iter()
                    .fold(G2Projective::IDENTITY, |acc, x| acc + x);

                let hash_i = hash_to_scalar(commit);

                pairing(commit, &(hash_i * temp_sum))
            })
            .collect::<Vec<Gt>>();

        let left_side = vector_gt.iter().fold(Gt::IDENTITY, |acc, x| acc * *x);

        // 4. compare left and right side of verification to see if they are equal
        left_side == right_side
    }
}

fn hash_to_scalar(commit: &G1Projective) -> Scalar {
    // Note the choice of compressed vs uncompressed bytes is arbitrary.
    let chash = Sha256::digest(commit.to_affine().to_uncompressed().as_ref());
    bigint::U256::from_be_slice(&chash).into()
}

pub fn generate_pre_commit(
    monypol_coeff: UnivarPolynomial,
    param_sc: &ParamSetCommitment,
) -> G1Projective {
    // multiply each pp_commit_g1 by each monypol_coeff and put result in a vector
    let coef_points = param_sc
        .pp_commit_g1
        .iter()
        .zip(monypol_coeff.coefficients().iter())
        .map(|(g1, coeff)| g1 * coeff)
        .collect::<Vec<G1Projective>>();

    eprintln!("coef_points length: {:?}", coef_points.len());
    //sum all the elements in coef_points as Scalars into a pre_commit
    coef_points
        .iter()
        .fold(G1Projective::IDENTITY, |acc, x| acc + x)
}

/// Returns where the two Arguments do not intersect
pub fn not_intersection(list_s: &[Scalar], list_t: Vec<Scalar>) -> Vec<Scalar> {
    list_s
        .iter()
        .filter(|value| !list_t.contains(value))
        .cloned()
        .collect::<Vec<Scalar>>()
}

#[cfg(target_arch = "wasm32")]
/// This function gets imported and called by ./tests/wasm.rs to run the same tests this module
/// runs, only in wasm32.
pub fn test_aggregate_verify_cross() {
    use super::*;
    // check aggregation of witnesses using cross set commitment scheme

    // Set 1
    let age = "age = 30";
    let name = "name = Alice";
    let drivers = "driver license = 12";

    // Set 2
    let gender = "Gender = male";
    let company = "company = ACME Inc.";
    let alt_drivers = "driver license type = B";

    let set_str: Entry = Entry(vec![
        Attribute::new(age),
        Attribute::new(name),
        Attribute::new(drivers),
    ]);

    let set_str2: Entry = Entry(vec![
        Attribute::new(gender),
        Attribute::new(company),
        Attribute::new(alt_drivers),
    ]);

    // create two set commitments for two sets set_str and set_str2
    let max_cardinal = 5;

    // CrossSetCommitment should be;
    // Ways to create a CrossSetCommitment:
    // new(max_cardinal) -> CrossSetCommitment
    // from(PublicParameters) -> CrossSetCommitmen

    let csc = CrossSetCommitment::new(MaxCardinality(max_cardinal));
    let (commitment_1, opening_info_1) = CrossSetCommitment::commit_set(&csc.param_sc, &set_str);
    let (commitment_2, opening_info_2) = CrossSetCommitment::commit_set(&csc.param_sc, &set_str2);

    let commit_vector = &vec![commitment_1, commitment_2];

    // create a witness for each subset -> W1 and W2
    let subset_str_1 = Entry(vec![
        Attribute::new(age),
        Attribute::new(name),
        Attribute::new(drivers),
    ]);

    let subset_str_2 = Entry(vec![Attribute::new(gender), Attribute::new(company)]);

    let witness_1 =
        CrossSetCommitment::open_subset(&csc.param_sc, &set_str, &opening_info_1, &subset_str_1)
            .expect("Some Witness");

    let witness_2 =
        CrossSetCommitment::open_subset(&csc.param_sc, &set_str2, &opening_info_2, &subset_str_2)
            .expect("Some Witness");

    // aggregate all witnesses for a subset is correct -> proof
    let proof = CrossSetCommitment::aggregate_cross(&vec![witness_1, witness_2], commit_vector);

    // verification aggregated witnesses
    assert!(CrossSetCommitment::verify_cross(
        &csc.param_sc,
        commit_vector,
        &[subset_str_1, subset_str_2],
        &proof
    ));
}

#[cfg(test)]
mod test {
    use crate::attributes::Attribute;

    use super::*;

    #[test]
    fn test_commit_and_open() {
        let max_cardinal = 5;

        // Set 1
        let age = "age = 30";
        let name = "name = Alice";
        let drivers = "driver license = 12";

        let set_str: Entry = Entry(vec![
            Attribute::new(age),
            Attribute::new(name),
            Attribute::new(drivers),
        ]);

        let sc = SetCommitment::new(MaxCardinality(max_cardinal));
        let (commitment, witness) = SetCommitment::commit_set(&sc.param_sc, &set_str);
        // assrt open_set with pp, commitment, O, set_str
        assert!(SetCommitment::open_set(
            &sc.param_sc,
            &commitment,
            &witness,
            &set_str
        ));
    }

    #[test]
    fn test_open_verify_subset() {
        let max_cardinal = 5;

        // Set 1
        let age = "age = 30";
        let name = "name = Alice";
        let drivers = "driver license = 12";

        let set_str = Entry(vec![
            Attribute::new(age),
            Attribute::new(name),
            Attribute::new(drivers),
        ]);

        let subset_str_1 = Entry(vec![Attribute::new(age), Attribute::new(name)]);
        let sc = SetCommitment::new(MaxCardinality(max_cardinal));
        let (commitment, opening_info) = SetCommitment::commit_set(&sc.param_sc, &set_str);
        let witness_subset =
            SetCommitment::open_subset(&sc.param_sc, &set_str, &opening_info, &subset_str_1);

        // assert that there is some witness_subset
        assert!(witness_subset.is_some());

        let witness_subset = witness_subset.expect("Some witness");

        assert!(SetCommitment::verify_subset(
            &sc.param_sc,
            &commitment,
            &subset_str_1,
            &witness_subset
        ));
    }

    #[test]
    fn test_aggregate_verify_cross() {
        // check aggregation of witnesses using cross set commitment scheme

        // Set 1
        let age = "age = 30";
        let name = "name = Alice";
        let drivers = "driver license = 12";

        // Set 2
        let gender = "Gender = male";
        let company = "company = ACME Inc.";
        let alt_drivers = "driver license type = B";

        let set_str: Entry = Entry(vec![
            Attribute::new(age),
            Attribute::new(name),
            Attribute::new(drivers),
        ]);

        let set_str2: Entry = Entry(vec![
            Attribute::new(gender),
            Attribute::new(company),
            Attribute::new(alt_drivers),
        ]);

        // create two set commitments for two sets set_str and set_str2
        let max_cardinal = 5;

        // CrossSetCommitment should be;
        // Ways to create a CrossSetCommitment:
        // new(max_cardinal) -> CrossSetCommitment
        // from(PublicParameters) -> CrossSetCommitmen

        let csc = CrossSetCommitment::new(MaxCardinality(max_cardinal));
        let (commitment_1, opening_info_1) =
            CrossSetCommitment::commit_set(&csc.param_sc, &set_str);
        let (commitment_2, opening_info_2) =
            CrossSetCommitment::commit_set(&csc.param_sc, &set_str2);

        let commit_vector = &vec![commitment_1, commitment_2];

        // create a witness for each subset -> W1 and W2
        let subset_str_1 = Entry(vec![
            Attribute::new(age),
            Attribute::new(name),
            Attribute::new(drivers),
        ]);

        let subset_str_2 = Entry(vec![Attribute::new(gender), Attribute::new(company)]);

        let witness_1 = CrossSetCommitment::open_subset(
            &csc.param_sc,
            &set_str,
            &opening_info_1,
            &subset_str_1,
        )
        .expect("Some Witness");

        let witness_2 = CrossSetCommitment::open_subset(
            &csc.param_sc,
            &set_str2,
            &opening_info_2,
            &subset_str_2,
        )
        .expect("Some Witness");

        // aggregate all witnesses for a subset is correct -> proof
        let proof = CrossSetCommitment::aggregate_cross(&vec![witness_1, witness_2], commit_vector);

        // verification aggregated witnesses
        assert!(CrossSetCommitment::verify_cross(
            &csc.param_sc,
            commit_vector,
            &[subset_str_1, subset_str_2],
            &proof
        ));
    }

    #[test]
    fn test_little_endien_power() {
        let base: Scalar = Scalar::ONE + Scalar::ONE;

        // Little endian means the least signifcant byte is written first
        let result = &base.pow(&[2u64, 0, 0, 0]);

        let expected = Scalar::from(4u64);

        assert_eq!(result, &expected);
    }

    // #[test]
    // fn test_generator() {
    //     let g1 = G1Projective::GENERATOR;
    //     let g2 = G2Projective::GENERATOR;
    //     println!("G1 generator: {:?}", g1);
    //     println!("G2 generator: {:?}", g2);
    //
    //     // rand Scalar
    //     let fe = Scalar::random(ThreadRng::default());
    //     println!("Random Scalar: {:?}", fe);
    //
    // }
}
