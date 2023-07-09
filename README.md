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
-   [ ] Stable Public API
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

-   Rust API
-   wasm bindgen (wasm32-unknown-unknown)
-   wasm interface types (WIT)

## Target API (TODO)

Current API is available by looking at the `keypair.rs` tests.

```rust
use std::result::Result;
use delanocreds::spseq_uc::*;
use delanocreds::utils::Entry;
use delanocreds::dac::Dac;
use delanocreds::attributes::{Attribute, AttributeName, AttributeValue};

fn main() -> Result<(), amcl_wrapper::errors::SerzDeserzError> {
    // Build a RootIssuer
    let max_entries = 10;
    let max_cardinality = 5;
    let mut root_issuer = RootIssuerBuilder::new().max_entries(max_entries).max_cardinality(max_cardinality).build();

    // get an Attributes builder with the constraints of the RootIssuer
    let mut entry_builder = root_issuer.entry_builder();

    // use Root Issuer to generate a root credential
    // it will only allow you to build with attributes up to the limits of the RootIssuer
    // if you add more, it will overwrite the oldest attributes / give you an error

    // Individual attributes are referenced by Provers generating a proof
    let read_attr   = Attribute::new("read"); // using the new method
    let create_attr = Attribute::from("create"); // using the from method
    let update_attr = attribute("update"); // using the attribute convenience method
    let delete_attr = attribute("delete");

    // Generate and insert First Entry using read attribute
    // Root issuer can add `max_entries` into the builder
    // Returns None is limit has been reached
    let Some(read_entry) = entry_builder.entry(vec![read_attr]);

    // Generate and insert Second Entry using create, update and delete elements
    let Some(change_entry) = entry_builder.entry(vec![create_attr, update_attr, delete_attr]);

    // update _only_ entry
    let Some(update_entry) = entry_builder.entry(vec![update_attr]);

    let all_entries: AttributeEntries = entry_builder.drain(); // generate the attributes entries

    let alice = Keypair::user::generate();
    let ally_nym = Keypair::nym::from(alice);

    let cred_ally = root_issuer
        .entries(all_entries) // Add the entries to the root credential
        .extendable(max_entries) // Allow the delegated party to add more entries up to max_entries
        .delegable() // Allow the delegated party to delegate the credential further
        .issue_to(ally_nym.proof);

    // serialize and send to alice
    // let cred_ally_bytes = cred_ally.serialize_cred();
    // let entries_bytes = cred_ally.serialize_entries();

    // Alice loads the credential
    // let cred_ally = Credential::deserialize(&cred_ally_bytes, &all_entries)?;

    // Alice can use the credential herself to prove she can CRUD like a boss
    let ally_proof = cred_ally
        .attribute(read_attr)
        .attribute(create_attr)
        .attribute(update_attr)
        .attribute(delete_attr)
        .prove(ally_nym.secret)?;

    // Serialize and send to Bobwith { features = ["serde", "serde_bytes", "serde_json"] }
    // let ally_proof_bytes = ally_proof.into_bytes();

    // Bob can deserialize and verify the proof
    // let ally_proof = Proof::deserialize(&ally_proof_bytes)?;

    // Alice asserting her power anonymously
    assert!(dac.verify(
        &root_issuer.public(),
        &ally_proof,
        vec![read_attr, create_attr, delete_attr]
    )?);

    // Alice can delegate some of her power to Bob, perhaps just to read
    let bob = Keypair::user::generate();
    let bobby_nym = Keypair::nym::from(alice);

    // Select which of the attribute entries bobby is allow to hold and show.
    // Anything not selected will be redacted from the cred issued to bobby
    // Selection happens on the Entry level, not the attibute level. So if you select an entry, all attributes in that entry will be available to bobby
    let bobby_offer = cred_ally
        // Explicitly, Choose, Add, and Redact which entries bobby to be able to prove.
        // Any new entries here (within ally's limits) will be added to the credential,
        // and any entries not here will be redacted from the credential
        .allow_entries(vec![read_entry, update_entry])
        .extendable(max_entries) // Allow the delegated party to add more entries up to max_entries
        .delegatable() // Allow the delegated party to further delegate the credential to others
        .issue_to(&bobby_nym.proof); // builds the offer

    // Serialize and send
    // let bobby_offer_bytes = bobby_offer.serialize()?;

    // Bob must deserialize and accept the delegation offer
    // let bobby_offer = Offer::deserialize(&bobby_offer_bytes)?;
    let bobby_cred = bobby_offer.accept(&bobby_nym.secret)?;

    // Now Bob can use the credential to prove he can read (read element from the read entry)
    let bobby_proof = bobby_cred
        .attribute(read_attr)
        .attribute(update_attr)
        .prove()?;

    // Others can verify Bob's power without knowing it's Bob, since all they see if Bobbys nym
    // let bobby_proof_bytes = bobby_proof.serialize()?;
    // let bobby_proof = Proof::deserialize(&bobby_proof_bytes)?;

    let bobby_power = dac.verify_proof(&bobby_proof, &bobby_nym.proof, vec![read_attr, update_attr])?;

    assert!(bobby_power); // Bob asserting his power

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

Rust implementation of https://github.com/mir-omid/DAC-from-EQS in [paper](https://eprint.iacr.org/2022/680.pdf) ([PDF](https://eprint.iacr.org/2022/680.pdf)).
