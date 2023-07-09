use crate::entry::convert_entry_to_bn;
use crate::entry::Entry;
use crate::keypair::MaxCardinality;
use amcl_wrapper::errors::SerzDeserzError;
use amcl_wrapper::extension_field_gt::GT;
use amcl_wrapper::field_elem::FieldElement;
use amcl_wrapper::group_elem::GroupElement;
use amcl_wrapper::group_elem_g1::G1;
use amcl_wrapper::group_elem_g2::G2;
use amcl_wrapper::univar_poly::UnivarPolynomial;
use secrecy::ExposeSecret;
use secrecy::Secret;

/// Public Parameters of the Set Commitment
/// - `pp_commit_g1`: Root Issuer's public parameters commitment for G1
/// - `pp_commit_g2`: Root Issuer's Public parameter commitment for G2
/// - `g_1`: G1 generator.
/// - `g_2`: G2 generator.
/// - `max_cardinality`: The Max Cardinality of this set. Cardinality of the set is in [1, t]
#[derive(Clone, Debug)]
pub struct ParamSetCommitment {
    pub pp_commit_g1: Vec<G1>,
    pub pp_commit_g2: Vec<G2>,
    pub g_1: G1, // TODO: Netype this as a Generator type instead of plain G1.
    pub g_2: G2,
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
    pub fn new(t: &usize) -> ParamSetCommitment {
        let g_2 = G2::generator();
        let g_1 = G1::generator();
        let base: Secret<FieldElement> = Secret::new(FieldElement::random());

        // pp_commit_g1 and pp_commit_g2 are vectors of G1 and G2 elements respectively.
        // They are used to compute the commitment and witness.
        // The number of polynomial coefficients is one more than the degree of the polynomial.
        // Since `pp_commit_g2` is used to compute the witness, we need to add one more element to the vector.
        // Hence use [..=] instead of [..] to ensure the last element is included.
        let pp_commit_g1 = (0..=*t)
            .map(|i| {
                g_1.scalar_mul_const_time(&base.expose_secret().pow(&FieldElement::from(i as u64)))
            })
            .collect::<Vec<G1>>();
        let pp_commit_g2 = (0..=*t)
            .map(|i| {
                g_2.scalar_mul_const_time(&base.expose_secret().pow(&FieldElement::from(i as u64)))
            })
            .collect::<Vec<G2>>();

        ParamSetCommitment {
            pp_commit_g2,
            pp_commit_g1,
            g_2,
            g_1,
            max_cardinality: *t,
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

    /// Generates a new commitment scheme.
    fn setup(max_cardinality: MaxCardinality) -> ParamSetCommitment {
        ParamSetCommitment::new(&max_cardinality)
    }
    /// Commit to a set of messages
    ///
    /// # Arguments
    /// `param_sc`: [ParamSetCommitment] public parameters for the commitment scheme, as P^ai, P_hat^ai, P = g1, P_hat = g2, Order, BG
    /// `mess_set_str`: a vector of [Entry]s
    ///
    /// # Returns
    /// Tuple of (commitment, witness) or a SerzDeserzError if
    ///
    /// # Method
    /// 1. Convert the message set to a vector of FieldElements
    /// 2. Compute the commitment as a product of P^ai, P_hat^ai, where ai is the ith element of the message set
    /// 3. Compute the witness as a product of P^ai, P_hat^ai, where ai is the ith element of the message set
    /// 4. Return the commitment and witness
    fn commit_set(
        param_sc: &ParamSetCommitment,
        mess_set_str: &Entry,
    ) -> Result<(G1, FieldElement), SerzDeserzError> {
        // TODO: Verify the message set string length is no more than the max cardinality in ParamSetCommitment
        let mess_set = convert_entry_to_bn(mess_set_str)?;
        let monypol_coeff = UnivarPolynomial::new_with_roots(&mess_set);
        let pre_commit = generate_pre_commit(monypol_coeff, param_sc);

        let open_info = FieldElement::random();

        // multiply pre_commit by rho (open_info = rho). Rho is a random element in Zp. Zp is the set of integers modulo p.
        let commitment = pre_commit.scalar_mul_const_time(&open_info);
        Ok((commitment, open_info))
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
        mess_set_str: &Entry,
    ) -> Result<bool, SerzDeserzError> {
        let mess_set = convert_entry_to_bn(mess_set_str)?;
        let monypol_coeff = UnivarPolynomial::new_with_roots(&mess_set);
        let pre_commit = generate_pre_commit(monypol_coeff, param_sc);

        // multiply pre_commit by rho. Rho is a random element in Zp. Zp is the set of integers modulo p.
        let commitment_check = pre_commit * open_info;

        Ok(*commitment == commitment_check)
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
        open_info: &FieldElement,
        subset: &Entry,
    ) -> Result<Option<G1>, SerzDeserzError> {
        if open_info.is_zero() {
            return Ok(None);
        }

        let mess_set = convert_entry_to_bn(all_messages)?;
        let mess_subset_t = convert_entry_to_bn(subset)?;

        // check if mess_subset is a subset of mess_set
        // compare the lengths of the two vectors
        if mess_subset_t.len() > mess_set.len() {
            return Ok(None);
        }

        // now, for each item in mess_subset_t, if item is in mess_set, checker = true, else checker = false
        // check to ensure all messages in mess_subset_t are in mess_set
        if !mess_subset_t.iter().all(|item| mess_set.contains(item)) {
            return Ok(None);
        }

        // creates a list of elements that are in mess_set but not in mess_subset_t,
        // use into_iter() to consume the owned value (mess_set) and return an iterator
        let create_witn_elements: Vec<FieldElement> = mess_set
            .into_iter()
            .filter(|itm| !mess_subset_t.contains(itm))
            .collect::<Vec<FieldElement>>();

        // compute a witness for the subset
        let coeff_witn = UnivarPolynomial::new_with_roots(&create_witn_elements);
        let witn_sum = generate_pre_commit(coeff_witn, param_sc);

        let witness = witn_sum * open_info;
        Ok(Some(witness))
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
        subset_str: &Entry,
        witness: &G1,
    ) -> Result<bool, SerzDeserzError> {
        let mess_subset_t = convert_entry_to_bn(subset_str)?;
        let coeff_t = UnivarPolynomial::new_with_roots(&mess_subset_t);

        let subset_group_elements = param_sc
            .pp_commit_g2
            .iter()
            .zip(coeff_t.coefficients().iter())
            .map(|(g2, coeff)| g2 * coeff)
            .collect::<Vec<G2>>();

        // sum all points
        let subset_elements_sum = subset_group_elements
            .iter()
            .fold(G2::identity(), |acc, x| acc + x);

        Ok(GT::ate_pairing(witness, &subset_elements_sum)
            == GT::ate_pairing(commitment, &param_sc.g_2))
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
            param_sc: SetCommitment::setup(t),
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
        let param_sc = CrossSetCommitment::setup(t);
        // return union type of SetCommitment and CrossSetCommitment.
        // A Rust union type is a type that can store only one of its members at a time.
        // ie. it can be either SetCommitment or CrossSetCommitment.
        // it looks like: `pub enum Commitment { SetCommitment(SetCommitment), CrossSetCommitment(CrossSetCommitment) }`
        CrossSetCommitment { param_sc }
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
    pub fn aggregate_cross(witness_vector: &[G1], commit_vector: &[G1]) -> G1 {
        // TODO: Needs to ensure that elements in the witness_vector are no longer than the max_cardinality in ParamSetCommitment
        // check number of entries in `witness_vector` against `self.param_sc.max_cardinality` to ensure within bounds
        // ie. witness_vector.len() <= self.param_sc.max_cardinality

        // sum all elements in all witness_vectors
        witness_vector.iter().zip(commit_vector.iter()).fold(
            G1::identity(),
            |acc, (witness, commit)| {
                let hash_i: FieldElement = g1_hash_to_field_el(commit);
                acc + witness.scalar_mul_const_time(&hash_i)
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
        commit_vector: &[G1],
        selected_entry_subset_vector: &[Entry],
        proof: &G1,
    ) -> Result<bool, SerzDeserzError> {
        // Steps:
        // 1. convert message str into the BN
        let subsets_vector = selected_entry_subset_vector
            .iter()
            .enumerate()
            .filter(|(_, entry)| !entry.is_empty())
            .map(|(_, entry)| convert_entry_to_bn(entry))
            .collect::<Result<Vec<Vec<FieldElement>>, SerzDeserzError>>()?;

        // create a union of sets
        let set_s = subsets_vector
            .iter()
            .fold(Vec::new(), |mut acc, x| {
                acc.extend(x.clone());
                acc
            })
            .into_iter()
            .collect::<Vec<FieldElement>>();

        let coeff_set_s = UnivarPolynomial::new_with_roots(&set_s);

        // 2. compute right side of verification, pp_commit_g2
        let set_s_group_element = param_sc
            .pp_commit_g2
            .iter()
            .zip(coeff_set_s.coefficients().iter())
            .map(|(g2, coeff)| g2 * coeff)
            .collect::<Vec<G2>>();

        let set_s_elements_sum = set_s_group_element
            .iter()
            .fold(G2::identity(), |acc, x| acc + x);

        // right_side is the pairing of proof and set_s_elements_sum
        let right_side = GT::ate_pairing(proof, &set_s_elements_sum);

        let set_s_not_t = subsets_vector
            .into_iter()
            .map(|x| not_intersection(&set_s, x))
            .collect::<Vec<Vec<FieldElement>>>();

        // 3. compute left side of verification
        let vector_gt = commit_vector
            .iter()
            .zip(set_s_not_t.iter())
            .map(|(commit, set_s_not_t)| {
                let coeff_s_not_t = UnivarPolynomial::new_with_roots(set_s_not_t);

                let listpoints_s_not_t = param_sc
                    .pp_commit_g2
                    .iter()
                    .zip(coeff_s_not_t.coefficients().iter())
                    .map(|(g2, coeff)| g2 * coeff)
                    .collect::<Vec<G2>>();

                let temp_sum = listpoints_s_not_t
                    .iter()
                    .fold(G2::identity(), |acc, x| acc + x);

                let hash_i: FieldElement = g1_hash_to_field_el(commit);

                GT::ate_pairing(commit, &(hash_i * temp_sum))
            })
            .collect::<Vec<GT>>();

        let left_side = vector_gt.iter().fold(GT::one(), |acc, x| acc * x.clone());

        // 4. compare left and right side of verification to see if they are equal
        Ok(left_side == right_side)
    }
}

fn g1_hash_to_field_el(commit: &G1) -> FieldElement {
    FieldElement::from_msg_hash(&commit.to_bytes(false))
}

pub fn generate_pre_commit(
    monypol_coeff: amcl_wrapper::univar_poly::UnivarPolynomial,
    param_sc: &ParamSetCommitment,
) -> G1 {
    // multiply each pp_commit_g1 by each monypol_coeff and put result in a vector
    let coef_points = param_sc
        .pp_commit_g1
        .iter()
        .zip(monypol_coeff.coefficients().iter())
        .map(|(g1, coeff)| g1 * coeff)
        .collect::<Vec<G1>>();

    // sum all the elements in coef_points as FieldElements into a pre_commit
    coef_points.iter().fold(G1::identity(), |acc, x| acc + x)
}

/// Returns where the two Arguments do not intersect
pub fn not_intersection(list_s: &[FieldElement], list_t: Vec<FieldElement>) -> Vec<FieldElement> {
    list_s
        .iter()
        .filter(|value| !list_t.contains(value))
        .cloned()
        .collect::<Vec<FieldElement>>()
}

#[cfg(test)]
mod test {
    use crate::attributes::attribute;

    use super::*;

    #[test]
    fn test_commit_and_open() -> Result<(), SerzDeserzError> {
        let max_cardinal = 5;

        // Set 1
        let age = "age = 30";
        let name = "name = Alice";
        let drivers = "driver license = 12";

        let set_str: Entry = Entry(vec![attribute(age), attribute(name), attribute(drivers)]);

        let pp = SetCommitment::setup(MaxCardinality(max_cardinal));
        let (commitment, witness) = SetCommitment::commit_set(&pp, &set_str)?;
        // assrt open_set with pp, commitment, O, set_str
        assert!(SetCommitment::open_set(
            &pp,
            &commitment,
            &witness,
            &set_str
        )?);
        Ok(())
    }

    #[test]
    fn test_open_verify_subset() -> Result<(), SerzDeserzError> {
        let max_cardinal = 5;

        // Set 1
        let age = "age = 30";
        let name = "name = Alice";
        let drivers = "driver license = 12";

        let set_str = Entry(vec![attribute(age), attribute(name), attribute(drivers)]);

        let subset_str_1 = Entry(vec![attribute(age), attribute(name)]);
        let pp = SetCommitment::setup(MaxCardinality(max_cardinal));
        let (commitment, opening_info) = SetCommitment::commit_set(&pp, &set_str)?;
        let witness_subset =
            SetCommitment::open_subset(&pp, &set_str, &opening_info, &subset_str_1)?;

        // assert that there is some witness_subset
        assert!(witness_subset.is_some());

        let witness_subset = witness_subset.expect("Some witness");

        assert!(SetCommitment::verify_subset(
            &pp,
            &commitment,
            &subset_str_1,
            &witness_subset
        )?);
        Ok(())
    }

    #[test]
    fn test_aggregate_verify_cross() -> Result<(), SerzDeserzError> {
        // check aggregation of witnesses using cross set commitment scheme

        // Set 1
        let age = "age = 30";
        let name = "name = Alice";
        let drivers = "driver license = 12";

        // Set 2
        let gender = "Gender = male";
        let company = "company = ACME Inc.";
        let alt_drivers = "driver license type = B";

        let set_str: Entry = Entry(vec![attribute(age), attribute(name), attribute(drivers)]);

        let set_str2: Entry = Entry(vec![
            attribute(gender),
            attribute(company),
            attribute(alt_drivers),
        ]);

        // create two set commitments for two sets set_str and set_str2
        let max_cardinal = 5;

        // CrossSetCommitment should be;
        // Ways to create a CrossSetCommitment:
        // new(max_cardinal) -> CrossSetCommitment
        // from(PublicParameters) -> CrossSetCommitment

        let pp = CrossSetCommitment::setup(MaxCardinality(max_cardinal));
        let (commitment_1, opening_info_1) = CrossSetCommitment::commit_set(&pp, &set_str)?;
        let (commitment_2, opening_info_2) = CrossSetCommitment::commit_set(&pp, &set_str2)?;

        let commit_vector = &vec![commitment_1, commitment_2];

        // create a witness for each subset -> W1 and W2
        let subset_str_1 = Entry(vec![attribute(age), attribute(name), attribute(drivers)]);

        let subset_str_2 = Entry(vec![attribute(gender), attribute(company)]);

        let witness_1 =
            CrossSetCommitment::open_subset(&pp, &set_str, &opening_info_1, &subset_str_1)?
                .expect("Some Witness");

        let witness_2 =
            CrossSetCommitment::open_subset(&pp, &set_str2, &opening_info_2, &subset_str_2)?
                .expect("Some Witness");

        // aggregate all witnesses for a subset is correct-> proof
        // TODO: System should not allow you to aggregate witnesses of a higher cardinality than the max cardinality in ParamSetCommitment
        let proof = CrossSetCommitment::aggregate_cross(&vec![witness_1, witness_2], commit_vector);

        // verification aggregated witnesses
        assert!(CrossSetCommitment::verify_cross(
            &pp,
            commit_vector,
            &[subset_str_1, subset_str_2],
            &proof
        )?);
        Ok(())
    }

    #[test]
    fn test_generator() {
        let g1 = G1::generator();
        let g2 = G2::generator();
        println!("G1 generator: {:?}", g1);
        println!("G2 generator: {:?}", g2);

        // rand FE
        let fe = FieldElement::random();
        println!("Random FE: {:?}", fe);
    }
}
