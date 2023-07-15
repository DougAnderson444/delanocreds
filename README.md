# **Del**egatable **Ano**nymous **Cred**ential**s** (Delanocreds)

This library enables you to create, issue, delegate/extend/restrict/transfer, and verify credentials in an anonymous way.

Create Root Credentials, then delegate the ability to add or remove credentials, without revealing the identity of any of the holders in the delegation chain, including the prover!

Useful if you want the ability to delegate credentials, capabilities, or other data without revealing the identity of the delegation or holder(s).

Holders can also selectively prove attributes and remove the ability for delegatees to prove selected attributes.

[![Example Explainer](https://github.com/hyperledger/aries-rfcs/raw/main/concepts/0104-chained-credentials/use-case.png)](https://github.com/hyperledger/aries-rfcs/blob/main/concepts/0104-chained-credentials/README.md)

## Project Status

⚠️ New project, somewhat work in progress. API is not stable yet.

Roadmap:

-   [x] Passing tests
-   [x] Basic Public API
-   [ ] Stable API
-   [ ] DelanoWallet (Store, Sign, Backup Credentials)
-   [ ] DelanoNet (Data Exchange Network)

## Delegation

What can be delegated is the ability to add a number of additional attribute Entries (zero to MaxEntries), but only if the credential is marked as _extendable_.

Even if there is no ability for a credential holder to add additional attributes, the following always holds true:

-   Credentials holders can always assign their credential to a new public key
-   Attributes are always selectable for presentation by a holder
-   Attributes are always removable by a holder

It is important to note that the Credential can always be assigned to a new public key, that is what makes this scheme anonymizable.

Therefore, while holders may restrict the ability of delegatees to _add_ attributes, they will always be
able to assign the credential to a new public key for the attributes they _do_ have.

You may wish to apply a Credential Strategy such that the Credential is properly handled by the holder. This is left to the user, as the use cases of Credentials are varied too widely to provide a one-size-fits-all solution.

### Root Issuer Summary of Choices/Options:

-   **Maxiumum Attribute Entries**: Credntials have a maximum number of entries.
    Each entry holds up to MaxCardinality of Attributes.
    The Root Issuer sets a maximum number of entries (`message_l`)
-   **Maximum Cardinality (Attributes per Entry)**: There is a set maximum number of items total (`cardinality`, `message_l[n].len()` <= `cardinality`)
-   **Extendable Limit**: What the maximum number of additional entries may be (current entries length up to `k_prime`, `k_prime` is at most `message_l`.
    Or in other words: `current < k_prime < message_l`),

### Attributes

Attributes can be created from any bytes, such as "age > 21" or even a `jpg`. These bytes are hashed to the BLS12-381 curve, which means they are also content addressable! Once an Attribute is created, it can be referenced by it's [Content Identifier (CID)](https://cid.ipfs.tech/) instead of the value itself. This means we can also refer to attributes by their CID, and not have to worry about revealing the actual content of the attribute or re-hashing the content when it needs to be referenced.

The algorithm used to hash the attributes is Sha3 SHAKE256, with a length of 48 bytes which is longer than the typical 32 bytes. If you try to create an Attribute out of a CID with a different hash or length, it will fail and result in an error. For this reason, use the Attribute methods provided by this library when creating Attributes.

```rust
use delanocreds::attributes::Attribute;

let some_test_attr = "read";

let read_attr = Attribute::new(some_test_attr); // using the new method

// Try Attribute from cid
let attr_from_cid = Attribute::try_from(read_attr.cid()).unwrap();
assert_eq!(read_attr, attr_from_cid);

// Attribute from_cid
let attr_from_cid = Attribute::from_cid(&read_attr).unwrap();
assert_eq!(read_attr, attr_from_cid);
```

### Entries

A Credential is comprised of one or more Entries. Each Entry contains one or more Attributes. Entries are used to group Attributes together, and are also used to delegate the ability to add or remove Attributes.

```md
//! Attribute Entries:
//! ==> Entry Level 0: [Attribute, Attribute, Attribute]
//! ==> Entry Level 1: [Attribute]
//! ==> Entry Level 2: [Attribute, Attribute]
//! ==> Additonal Entry? Only if 3 < Extendable < MaxEntries
```

### Redact

Holders of a Credential can redact any [Entry] from the Credential, which will remove the ability to create proofs on any Attributes in that entry. This is useful if you want to remove the ability for a delegatee to prove a specific attribute, but still allow them to prove other attributes.

This is done by zeroizing the Opening Information in the Credential.

## Bindings

The intention is to provide the following bindings:

-   [x] Rust API
-   [ ] wasm bindgen (wasm32-unknown-unknown)
-   [ ] wasm interface types (WIT)

## Target API (TODO)

Current full API is available by looking at the `src/lib.rs` tests. Below is a small sampling of how to use the API.

```rust
use anyhow::Result;
use delanocreds::entry::{Entry, MaxEntries};
use delanocreds::attributes::Attribute;
use delanocreds::keypair::{Issuer, UserKey, verify_proof};

fn main() -> Result<()> {
    // Build a RootIssuer with ./config.rs default sizes
    let mut issuer = Issuer::default();

    // Create Entry of 2 Attributes
    let over_21 = Attribute::new("age > 21");
    let seniors_discount = Attribute::new("age > 65");
    let root_entry = Entry::new(&[over_21.clone(), seniors_discount.clone()]);

    // Along comes Alice
    let alice = UserKey::new();
    // Alice creates an anonymous pseudonym of her keys
    // This Nym must use the public parameters of the Issuer
    let nym = alice.nym(issuer.public.parameters.clone());

    let cred = issuer
        .credential() // CredentialBuilder for this Issuer
        .with_entry(root_entry.clone()) // adds a Root Entry
        .max_entries(&MaxEntries::default()) // set the Entry ceiling
        .issue_to(&nym.public)?; // issues to a Nym

    // Send the (powerful) Root Credential, Attributes, and Entrys to Alice

    // Alice can use the Credential to prove she is over 21
    let (proof, selected_attributes) = nym.proof_builder(&cred, &[root_entry.clone()])
        .select_attribute(over_21.clone())
        .prove();
    assert!(verify_proof(&issuer.public.vk, &proof, &selected_attributes).unwrap());

    // Alice can offer variations of the Credential to others
    let bob = UserKey::new();
    let bobby_nym = bob.nym(issuer.public.parameters.clone());

    let (offer, provable_entries) = nym.offer_builder(&cred, &[root_entry])
        .without_attribute(seniors_discount) // resticts the ability to prove attribute Entry (note: Removes the entire Entry, not just one Attribute)
        .additional_entry(Entry::new(&[Attribute::new("10% off")])) // adds a new Entry
        .max_entries(3) // restrict delegatees to only 3 entries total
        .offer_to(&bobby_nym.public)?;

    // Send to Bob so he can accept the Credential
    let bobby_cred = bobby_nym.accept(&offer);

    // and prove all entries
    let (proof, selected_attributes) = bobby_nym.proof_builder(&bobby_cred, &provable_entries)
        .select_attribute(over_21)
        .prove();

    assert!(verify_proof(&issuer.public.vk, &proof, &selected_attributes).unwrap());

    Ok(())
}
```

## Features

## Advantages

This scheme has the following advantages over other anonymous credential schemes:

-   **Attributes**: User can selectively disclose and prove some of the attributes in the credential.
-   **Expressiveness**: S (selective disclosure), R (arbitrary computable relations over attributes, meaning you can do more than just selective disclosure)
-   **Rest**: Means whether it is possible to apply a restriction on the delegator’s power during the delegation.
-   **Selective Anonymity**: Strong anonymity guarantees meaning that no one can trace or learn information about the user’s identity or anything beyond what they suppose to show during both the issuing/delegation and showing of credentials.
-   **Credential Size**: O(1), meaning the size of the credential is constant.
-   **Show Size**: O(L), meaning the size of the showing grows linearly in the number of delegations.
-   **Undisclosed attributes**: O(u), meaning the size of the undisclosed attributes grows linearly in the number of delegations.

Table 1. Comparison of practical DAC schemes

| Scheme   | Attributes | Expressiveness | Rest | Selective Anonymity | Credential Size | Show Size |
| -------- | ---------- | -------------- | ---- | ------------------- | --------------- | --------- |
| [BB18]() | ✔️         | S/R            | ≈    | 🌓†                 | O(1)            | O(u)      |
| [CDD]()  | ✔️         | S/R            | ✖️   | 🌗♣                 | O(nL)           | O(uL)     |
| [CL]()   | ≈          | ✖️             | ✖️   | 🌙\*                | O(nL)           | O(uL)     |
| [This]() | ✔️         | S              | ✔️   | 🌚‡                 | O(1)            | O(L)      |

🌓† Requires a trusted setup and have a trapdoor associated to their parameters.

🌗♣ It does not support an anonymous delegation phase.

🌙∗
It also allows an adversarial CA but no delegators’s keys leaks.

🌚‡ We consider a malicious issuer key CA and all delegators keys can be exposed.

# Tests

`cargo test --workspace`

# Build Binary Release

`cargo build --bin delanocreds-bin --release`

Run the built binary:

`./target/release/delanocreds-bin.exe`

## Speed

This library can generate, issue, delegate, prove and verify 30 selected credentials out of 100 issued attributes in less than 400ms on [Intel i5-3470 CPU @ 3.20GHz](https://cpu.userbenchmark.com/Intel-Core-i5-3470/Rating/2771).

That's fast enough for time-critical applications like public transportation, ticketing, etc.

# Quick Bench

It's fast. Selecting 30 attributes out of 96 total, the following benchmarks were observed for each step:

After running `cargo run --release`:

| Step          | Time (ms) |
| ------------- | --------- |
| Setup         | 100       |
| Issue         | 81        |
| Offer         | 5         |
| Accept        | 69        |
| Prove         | 19        |
| Verify        | 72        |
| ============= | ========= |
| **Total**     | **346**   |

Bench Variables:

-   l - upper bound for the length of the commitment vector
-   t - upper bound for the cardinality of the committed sets
-   n < t - number of attributes in each attribute set A_i in commitment
-   C_i (same for each commitment level)
-   k - length of attribute set vector
-   k_prime - number of attributes sets which can be delegated

We set the above parameters as t = 25, l = 15, k = 4, k' = 7 and n = 10 to cover many different use-cases

Assumption:

-   each time a credential is delegated, an attribute is added

# Docs

`cargo doc --workspace --no-deps --open`

To build the docs incrementally, use `cargo watch -x 'doc --workspace --no-deps --open'`.

Build the docs in Windows for Github pages: `./build_docs.bat`

## References

Rust implementation of `<https://github.com/mir-omid/DAC-from-EQS>` in [paper](https://eprint.iacr.org/2022/680.pdf) ([PDF](https://eprint.iacr.org/2022/680.pdf)).
