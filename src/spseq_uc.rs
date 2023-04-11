use crate::set_commits::Commitment;
use crate::set_commits::CrossSetCommitment;
use amcl_wrapper::group_elem::GroupElement;
use amcl_wrapper::group_elem_g1::G1;
use amcl_wrapper::group_elem_g2::G2;
///
///
pub struct EQC_Sign {
    csc_scheme: CrossSetCommitment,
}

impl EQC_Sign {
    /// New constructor. Initializes the EQC_Sign
    ///
    /// # Arguments
    /// t: max cardinality of the set. Cardinality of the set is in [1, t]. t is a public parameter.
    ///
    /// # Returns
    /// EQC_Sign
    pub fn new(t: usize) -> EQC_Sign {
        let (pp, alpha) = CrossSetCommitment::new(t);
        EQC_Sign {
            csc_scheme: CrossSetCommitment {},
        }
    }

    /// Setup. Sets up the signature scheme by creating public parameters and a secret key
    ///
    /// # Arguments
    /// &self
    ///
    /// # Returns
    /// public parameters and secret key tuple
    pub fn setup(&self) {
        todo!()
        // let (pp, sk) = csc::setup();
        // (pp, sk)
    }
}
