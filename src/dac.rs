/// This is implementation of delegatable anonymous credential using SPSQE-UC signatures and set commitment.
// See  the following for the details:
// - Practical Delegatable Anonymous Credentials From Equivalence Class Signatures, PETS 2023.
//    https://eprint.iacr.org/2022/680
use amcl_wrapper::group_elem::GroupElement;
use amcl_wrapper::group_elem_g1::G1;
use amcl_wrapper::group_elem_g2::G2;

struct DAC {
    // spseq_uc: EQC_Sign,
}

impl DAC {
    /// New constructor
    /// # Arguments
    /// t: max cardinality of the set. Cardinality of the set is in [1, t]. t is a public parameter.
    /// l_message: the max number of the messagses. The number of the messages is in [1, l_message]. l_message is a public parameter.
    ///
    /// # Returns
    /// DAC
    pub fn new(t: usize, l_message: usize) -> DAC {
        DAC {}
    }
}
