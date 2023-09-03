use delano_crypto::basic::BasicSecretsManager;
use delano_crypto::Seed;
use delanocreds::keypair::MaxCardinality;
use delanocreds::Issuer;

#[test]
pub fn create_with_secrets_manager() {
    let seed = Seed::new([69u8; 32]);
    let manager = BasicSecretsManager::from_seed(seed).expect("test seed to work");

    let account = manager.account(1);

    let size = 8;
    let sk = account.derive(size);

    // Now that we have a sk vector, we can create the Issuer
    let _issuer = Issuer::new_with_secret(sk, MaxCardinality::default());
}
