// We need async traits because the user is likely to have to approve wallet functions and we don't want to block the main thread
#![feature(async_fn_in_trait)]

// Anywhere in delanocreds where there is `expose_secret()` needs to be moved here as a trait
// and then implemented for the type that is being exposed.
// default implementation should be to just return the value in the same way that delanocreds does currently

/// Creates Verification Key [delanocreds::VK] given generators for G1 and G2

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {}
}
