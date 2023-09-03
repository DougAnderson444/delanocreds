# Delano Secret

Secret generator and manager. Implements the Wallets traits from Delanocreds.

Create a Secret Manager then pass as an argument into Delanocreds crate.

If you want you own secret control flow mechanisms, you can implement the Wallet trait and pass your own struct into Delanocreds.

This gives you ultimate flexibility.

## Usage

```rust
// use delano_crypto::{Secret, SecretManager, SecretManagerConfig, SecretManagerError, SecretManagerResult, SecretType};
// use delanocreds::{Wallet, WalletConfig, WalletError, WalletResult, WalletType};

// Create a Secret Manager from a seed
// TODO

// Pass the manager into a delanocreds instance or constructor

```
