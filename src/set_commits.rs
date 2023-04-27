use crate::utils::polyfromroots;
use crate::utils::InputType;
use amcl_wrapper::extension_field_gt::GT;
use amcl_wrapper::field_elem::FieldElement;
use amcl_wrapper::group_elem::GroupElement;
use amcl_wrapper::group_elem_g1::G1;
use amcl_wrapper::group_elem_g2::G2;
use std::collections::HashSet;

/// First tuple is the public parameters commitment for G2, type we get returned from the Python code: [g_2.mul(alpha_trapdoor.pow(i)) for i in range(max_cardinality)] # This loops through the range of max_cardinality and multiplies g_2 by alpha_trapdoor raised to the power of i. Which is a list of G2 elements, or in Rust a Vec<G2>.
/// Second tuple is the public parameters commitment for G1, type we get returned from the Rust code: [g_1.mul(alpha_trapdoor.pow(i)) for i in range(max_cardinality)] # This loops through the range of max_cardinality and multiplies g_1 by alpha_trapdoor raised to the power of i.
/// Third entry in the tuple is the type returned from the G1 generator.
/// Fourth is the type returned from the G2 generator.
/// Last is the type of the group order
#[derive(Clone, Debug)]
pub struct ParamSetCommitment {
    pub pp_commit_g1: Vec<G1>,
    pub pp_commit_g2: Vec<G2>,
    pub g_2: G2,
    pub g_1: G1,
    pub max_cardinality: usize,
}

impl ParamSetCommitment {
    /// New constructor. Initializes the ParamSetCommitment
    ///
    /// # Arguments
    /// t: max cardinality of the set. Cardinality of the set is in [1, t]. t is a public parameter.
    /// alpha_trapdoor: Pederson trapdoor, which is a secret key generated from the setup function as a random order of the Group
    ///
    /// # Returns
    /// ParamSetCommitment
    pub fn new(t: usize, base: FieldElement) -> ParamSetCommitment {
        let g_2 = G2::generator();
        let g_1 = G1::generator();

        // take length of t as size by using
        let mut pp_commit_g1: Vec<G1> = Vec::with_capacity(t);
        let mut pp_commit_g2: Vec<G2> = Vec::with_capacity(t);

        for i in 0..t {
            pp_commit_g1.push(g_1.clone() * base.pow(&FieldElement::from(i as u64)));
            pp_commit_g2.push(g_2.clone() * base.pow(&FieldElement::from(i as u64)));
        }

        ParamSetCommitment {
            pp_commit_g2,
            pp_commit_g1,
            g_2,
            g_1,
            max_cardinality: t,
        }
    }
}

/// public trait Commitment common for both SetCommitment and CrossSetCommitment
/// This trait is used to define the common functions for both SetCommitment and CrossSetCommitment
///
/// # Returns
/// ParamSetCommitment: public parameters for the commitment scheme
/// AlphaTrapdoor: Pederson trapdoor, which is a secret key generated from the setup function as a random order of the Group
pub trait Commitment {
    fn setup(max_cardinality: usize) -> (ParamSetCommitment, FieldElement) {
        let alpha_trapdoor = FieldElement::random();

        (
            ParamSetCommitment::new(max_cardinality, alpha_trapdoor.clone()),
            alpha_trapdoor,
        )
    }
    /// Commit to a set of messages
    ///
    /// # Arguments
    /// param_sc: public parameters for the commitment scheme, as P^ai, P_hat^ai, P = g1, P_hat = g2, Order, BG
    /// mess_set_str: a message set as a string
    ///
    /// # Returns
    /// Tuple of (commitment, witness)
    ///
    /// # Method
    /// 1. Convert the message set to a vector of FieldElements
    /// 2. Compute the commitment as a product of P^ai, P_hat^ai, where ai is the ith element of the message set
    /// 3. Compute the witness as a product of P^ai, P_hat^ai, where ai is the ith element of the message set
    /// 4. Return the commitment and witness
    fn commit_set(param_sc: &ParamSetCommitment, mess_set_str: &InputType) -> (G1, FieldElement) {
        let mess_set = convert_mess_to_bn(mess_set_str);
        // get monypol_coeff using polyfromroots() fn from utils.rs
        let monypol_coeff = polyfromroots(mess_set);

        // multiply each G1 in Vec<G1> by each coefficient in the polynomial (FieldElementVector)
        let mut coef_points = Vec::with_capacity(monypol_coeff.coefficients().len());
        for i in 0..monypol_coeff.coefficients().len() {
            // G1 times a FieldElementVector is of type G1Vector?
            coef_points
                .push(param_sc.pp_commit_g1[i].clone() * monypol_coeff.coefficients()[i].clone());
        }

        // use amcl_wrapper to sum all the elements in coef_points as FieldElements into a pre_commit
        let pre_commit = coef_points.iter().fold(G1::identity(), |acc, x| acc + x);

        // get a random element in Zp
        let rho = FieldElement::random();

        // multiply pre_commit by rho. Rho is a random element in Zp. Zp is the set of integers modulo p.
        let commitment = pre_commit * rho.clone();
        // open_info is rho.
        let open_info = rho;
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
        commitment: &G1,
        open_info: &FieldElement,
        mess_set_str: &InputType,
    ) -> bool {
        let mess_set = convert_mess_to_bn(mess_set_str);
        // get monypol_coeff using polyfromroots() fn from utils.rs
        let monypol_coeff = polyfromroots(mess_set);

        // multiply each G1 in Vec<G1> by each coefficient in the polynomial (FieldElementVector)
        let mut coef_points = Vec::with_capacity(monypol_coeff.coefficients().len());
        for i in 0..monypol_coeff.coefficients().len() {
            // G1 times a FieldElementVector is of type G1Vector?
            coef_points
                .push(param_sc.pp_commit_g1[i].clone() * monypol_coeff.coefficients()[i].clone());
        }

        // sum all coef_points
        let pre_commit = coef_points.iter().fold(G1::identity(), |acc, x| acc + x);

        // multiply pre_commit by rho. Rho is a random element in Zp. Zp is the set of integers modulo p.
        let commitment_check = pre_commit * open_info;

        *commitment == commitment_check
    }

    /// OpenSubset Generates a witness for the subset if the length of the subset is less than the length of the message set
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
        mess_set_str: &InputType,
        open_info: &FieldElement,
        subset_str: &InputType,
    ) -> Option<G1> {
        let mess_set = convert_mess_to_bn(mess_set_str);
        let mess_subset_t = convert_mess_to_bn(subset_str);

        // check if mess_subset is a subset of mess_set
        // compare the lengths of the two vectors
        if mess_subset_t.len() > mess_set.len() {
            return None;
        }

        // now, for each item in mess_subset_t, if item is in mess_set, checker = true, else checker = false
        let mut checker = true;

        // check to ensure all messages in mess_subset_t are in mess_set
        for item in &mess_subset_t {
            if !mess_set.contains(item) {
                checker = false;
                break;
            }
        }

        // if checker is false, return None
        if !checker {
            return None;
        }

        // creates a list of elements that are in mess_set but not in mess_subset_t,
        // Equivalent to this Python code: `create_witn_elements = [item for item in mess_set if item not in mess_subset_t] `
        let mut create_witn_elements = Vec::new();
        for itm in mess_set {
            if !mess_subset_t.contains(&itm) {
                create_witn_elements.push(itm);
            }
        }

        // compute a witness for the subset
        let coeff_witn = polyfromroots(create_witn_elements);

        // multiply each G1 in pp_commit_g1 Vec<G1> by each coefficient witness in the polynomial (FieldElementVector)
        let mut witn_groups = Vec::with_capacity(coeff_witn.coefficients().len());
        for i in 0..coeff_witn.coefficients().len() {
            // G1 times a FieldElementVector is of type G1Vector?
            witn_groups
                .push(param_sc.pp_commit_g1[i].clone() * coeff_witn.coefficients()[i].clone());
        }

        //print len of witn_groups
        println!("len of witn_groups: {}", witn_groups.len());

        // summ all witn_groups points to get a single point
        let witn_sum = witn_groups.iter().fold(G1::identity(), |acc, x| acc + x);

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
        commitment: &G1,
        subset_str: &InputType,
        witness: &G1,
    ) -> bool {
        let mess_subset_t = convert_mess_to_bn(subset_str);
        let coeff_t = polyfromroots(mess_subset_t);

        let mut subset_group_elements = Vec::with_capacity(coeff_t.coefficients().len());
        for i in 0..coeff_t.coefficients().len() {
            // G1 times a FieldElementVector is of type G1Vector?
            subset_group_elements
                .push(param_sc.pp_commit_g2[i].clone() * coeff_t.coefficients()[i].clone());
        }

        // sum all points
        let subset_elements_sum = subset_group_elements
            .iter()
            .fold(G2::identity(), |acc, x| acc + x);

        GT::ate_pairing(witness, &subset_elements_sum) == GT::ate_pairing(commitment, &param_sc.g_2)
    }
}

pub fn convert_mess_to_bn(input: &InputType) -> Vec<FieldElement> {
    match input {
        InputType::String(mess) => {
            let mess_bn = FieldElement::from_msg_hash(mess.as_bytes());
            vec![mess_bn]
        }
        InputType::VecString(mess_vec) => {
            let mut mess_bn_vec = Vec::new();
            for mess in mess_vec {
                let mess_bn = FieldElement::from_msg_hash(mess.as_bytes());
                mess_bn_vec.push(mess_bn);
            }
            mess_bn_vec
        }
    }
}

pub struct SetCommitment {}

// impl all default traits for SetCommitment
impl Commitment for SetCommitment {}

/// Here is CrossSetCommitment that extends the Set Commitment to provide aggregation witness and a batch verification
pub struct CrossSetCommitment {
    pub param_sc: ParamSetCommitment,
    _alpha_trapdoor: FieldElement,
}

// impl all default traits for CrossSetCommitment
impl Commitment for CrossSetCommitment {}

/// CrossSetCommitment is a commitment scheme that extends the Set Commitment to provide aggregation witness and a batch verification
/// New constructor obtained from Commitment trait impl
impl CrossSetCommitment {
    ///
    /// # Arguments
    /// t: max cardinality of the set. Cardinality of the set is in [1, t]. t is a public parameter.
    ///
    /// # Returns
    /// CrossSet Commitment scheme
    pub fn new(t: usize) -> Self {
        let (param_sc, alpha_trapdoor) = CrossSetCommitment::setup(t);
        Self {
            param_sc,
            _alpha_trapdoor: alpha_trapdoor,
        }
    }

    /// Computes an aggregate proof of valid subsets of a set of messages.
    ///
    /// # Arguments
    /// witness_vector: a vector of witnessess
    /// commit_vector: the commitment vector
    ///
    /// # Returns
    /// a proof which is a aggregate of witnesses and shows all subsets are valid for respective sets
    pub fn aggregate_cross(witness_vector: &Vec<G1>, commit_vector: &[G1]) -> G1 {
        let mut proof = G1::identity();

        for i in 0..witness_vector.len() {
            // generate a BigNumber challenge t_i by hashing a number of EC points
            // join all the commit_vector elements into a single vector of hex
            let c_string = commit_vector[i].to_hex();
            let hash_i: FieldElement = FieldElement::from_msg_hash(c_string.as_bytes());

            // append witnessness_group_elements
            // add to existing proof
            proof += witness_vector[i].clone() * hash_i;
        }
        proof
    }

    /// Verifies an aggregate proof of valid subsets of a set of messages.
    /// # Arguments
    /// param_sc: public parameters
    /// commit_vector: the commitment vector
    /// subsets_vector_str: the message sets vector
    /// proof: a proof which is a aggregate of witnesses
    ///
    /// # Returns
    /// true if the proof is valid, false otherwise
    pub fn verify_cross(
        param_sc: &ParamSetCommitment,
        commit_vector: &Vec<G1>,
        subsets_vector_str: &[InputType],
        proof: &G1,
    ) -> bool {
        // Steps:
        // 1. convert message str into the BN
        let subsets_vector = subsets_vector_str
            .iter()
            .map(convert_mess_to_bn)
            .collect::<Vec<Vec<FieldElement>>>();
        // create a union of sets
        let set_s = subsets_vector
            .iter()
            .fold(Vec::new(), |mut acc, x| {
                acc.extend(x.clone());
                acc
            })
            .into_iter()
            .collect::<HashSet<FieldElement>>()
            .into_iter()
            .collect::<Vec<FieldElement>>();

        let coeff_set_s = polyfromroots(set_s.clone());

        // 2. compute right side of verification, pp_commit_g2
        let mut set_s_group_element = Vec::with_capacity(coeff_set_s.coefficients().len());
        for i in 0..coeff_set_s.coefficients().len() {
            set_s_group_element
                .push(param_sc.pp_commit_g2[i].clone() * coeff_set_s.coefficients()[i].clone());
        }

        let set_s_elements_sum = set_s_group_element
            .iter()
            .fold(G2::identity(), |acc, x| acc + x);

        // right_side is the pairing of proof and set_s_elements_sum
        let right_side = GT::ate_pairing(proof, &set_s_elements_sum);
        let set_s_not_t = subsets_vector
            .iter()
            .map(|x| not_intersection(&set_s, x.clone()))
            .collect::<Vec<Vec<FieldElement>>>();
        // 3. compute left side of verification, such as this Python code:
        let mut vector_gt = Vec::with_capacity(commit_vector.len());
        let mut left_side = GT::one();
        for j in 0..commit_vector.len() {
            let coeff_s_not_t = polyfromroots(set_s_not_t[j].clone());
            // use amcl_wrapper to multiply FieldElementVector by a FieldElement: `&coeff_s_not_t * param_sc.pp_commit_g2`
            // len of pp_commit_g2
            let mut listpoints_s_not_t = Vec::with_capacity(coeff_s_not_t.coefficients().len());
            for i in 0..coeff_s_not_t.coefficients().len() {
                listpoints_s_not_t.push(
                    param_sc.pp_commit_g2[i].clone() * coeff_s_not_t.coefficients()[i].clone(),
                );
            }
            let temp_sum = listpoints_s_not_t
                .iter()
                .fold(G2::identity(), |acc, x| acc + x);

            let c_string = commit_vector[j].to_hex();
            let hash_i: FieldElement = FieldElement::from_msg_hash(c_string.as_bytes());

            let gt_element = GT::ate_pairing(&commit_vector[j], &(hash_i * temp_sum));
            vector_gt.push(gt_element);
        }

        for item in &vector_gt {
            left_side = left_side * item.clone();
        }

        // 4. compare left and right side of verification to see if they are equal
        left_side == right_side
    }
}

pub fn mul_and_fold(monypol_coeff: Vec<FieldElement>, param_sc: ParamSetCommitment) -> G1 {
    // multiply each pp_commit_g1 by each monypol_coeff and put result in a vector
    let mut coef_points: Vec<G1> = Vec::with_capacity(monypol_coeff.len());
    for (i, coeff) in monypol_coeff.iter().enumerate() {
        coef_points.push(param_sc.pp_commit_g1[i].clone() * coeff);
    }

    // use amcl_wrapper to sum all the elements in coef_points as FieldElements into a pre_commit
    let folded = coef_points.iter().fold(G1::identity(), |acc, x| acc + x);
    folded
}

pub fn not_intersection(
    list_s: &Vec<FieldElement>,
    list_t: Vec<FieldElement>,
) -> Vec<FieldElement> {
    let mut set_s_not_t = Vec::new();
    for value in list_s {
        if !list_t.contains(value) {
            set_s_not_t.push(value.clone());
        }
    }
    set_s_not_t
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_commit_and_open() {
        let max_cardinal = 5;

        // Set 1
        let age = "age = 30";
        let name = "name = Alice";
        let drivers = "driver license = 12";

        let set_str: InputType =
            InputType::VecString(vec![age.to_owned(), name.to_owned(), drivers.to_owned()]);

        let (pp, _alpha) = SetCommitment::setup(max_cardinal);
        let (commitment, witness) = SetCommitment::commit_set(&pp, &set_str);
        // assrt open_set with pp, commitment, O, set_str
        assert!(SetCommitment::open_set(
            &pp,
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

        let set_str: InputType =
            InputType::VecString(vec![age.to_owned(), name.to_owned(), drivers.to_owned()]);

        let subset_str_1: InputType = InputType::VecString(vec![age.to_owned(), name.to_owned()]);
        let (pp, _alpha) = SetCommitment::setup(max_cardinal);
        let (commitment, opening_info) = SetCommitment::commit_set(&pp, &set_str);
        let witness_subset =
            SetCommitment::open_subset(&pp, &set_str, &opening_info, &subset_str_1);

        // assert that there is some witness_subset
        assert!(witness_subset.is_some());

        let witness_subset = witness_subset.expect("Some witness");

        assert!(SetCommitment::verify_subset(
            &pp,
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

        let set_str: InputType =
            InputType::VecString(vec![age.to_owned(), name.to_owned(), drivers.to_owned()]);

        let set_str2: InputType = InputType::VecString(vec![
            gender.to_owned(),
            company.to_owned(),
            alt_drivers.to_owned(),
        ]);

        // create two set commitments for two sets set_str and set_str2
        let max_cardinal = 5;
        let (pp, _alpha) = CrossSetCommitment::setup(max_cardinal);
        let (commitment_1, opening_info_1) = CrossSetCommitment::commit_set(&pp, &set_str);
        let (commitment_2, opening_info_2) = CrossSetCommitment::commit_set(&pp, &set_str2);

        // create a witness for each subset -> W1 and W2
        let subset_str_1: InputType = InputType::VecString(vec![age.to_owned(), name.to_owned()]);

        let subset_str_2: InputType =
            InputType::VecString(vec![gender.to_owned(), company.to_owned()]);

        let witness_1 =
            CrossSetCommitment::open_subset(&pp, &set_str, &opening_info_1, &subset_str_1)
                .expect("Some Witness");

        let witness_2 =
            CrossSetCommitment::open_subset(&pp, &set_str2, &opening_info_2, &subset_str_2)
                .expect("Some Witness");

        // aggregate all witnesses for a subset is correct-> proof
        let proof = CrossSetCommitment::aggregate_cross(
            &vec![witness_1, witness_2],
            &vec![commitment_1.clone(), commitment_2.clone()],
        );

        // verification aggregated witnesses
        assert!(CrossSetCommitment::verify_cross(
            &pp,
            &vec![commitment_1, commitment_2],
            &[subset_str_1, subset_str_2],
            &proof
        ));
    }
}
