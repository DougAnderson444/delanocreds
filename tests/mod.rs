use delano_keys::kdf::{derive, Manager};
use delano_keys::vk::VK;
use delanocreds::Issuer;
use delanocreds::MaxCardinality;
use secrecy::zeroize::Zeroizing;

#[test]
pub fn create_with_secrets_manager() {
    let seed = Zeroizing::new([69u8; 32]);
    let manager = Manager::from_seed(seed);

    let account = manager.account(1);

    let size = 4;
    let expanded_secret = account.expand_to(size);

    // Now that we have a sk vector, we can create the Issuer
    let issuer = Issuer::new_with_secret(expanded_secret, MaxCardinality::default());

    // A verification key is made up of a VK::G1 as the first element, and VK::G2 as subsequent
    // elements. So we take our given VK::G1 and use it as elem[0], and then derive the balance
    // from the PK::G2.

    // Anyone can derive the VK from the given root PKs in G1 ad G2
    // We need to create a VK[0] = VK::G1 and VK[1..size] = PK::G2
    let vk: Vec<VK> = derive(&account.pk_g1, &account.pk_g2, issuer.public.vk.len() as u8);

    // assert lengths are correct
    assert_eq!(vk.len() as u8, size + 1u8);

    // assert matches issuer.public.vk.len
    assert_eq!(issuer.public.vk.len() as u8, size + 1u8);

    // issuer.public.vk[0] should match vk_0 with elements cast to VK::G1
    assert_eq!(issuer.public.vk[0], vk[0]);
    assert_eq!(issuer.public.vk[1], vk[1]);
    assert_eq!(issuer.public.vk[2], vk[2]);
    assert_eq!(issuer.public.vk[3], vk[3]);
    // rest
    assert_eq!(issuer.public.vk, vk);
}
