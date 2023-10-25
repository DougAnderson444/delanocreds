// Route constants
pub(crate) const HOME: &str = env!("BASE_PATH");
/// ACCOUNT is env!("BASE_PATH") and "account"
pub(crate) const ACCOUNT: &str = concat!(env!("BASE_PATH"), "account");
/// OFFER is env!("BASE_PATH") and "offer"
pub(crate) const OFFER: &str = "offer";
/// For testing purposes only
pub(crate) const TEST: &str = concat!(env!("BASE_PATH"), "test");
