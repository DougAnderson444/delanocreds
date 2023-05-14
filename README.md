# **Del**egatable **Ano**nymous **Cred**ential**s** (Delanocreds)

Create messages that can be held by third parties, re-delegated, and verified without revealing the identity of any of the holders in the delegation chain.

Useful if you want the ability to delegate credntials, capabiltiies, or other data without revealing the identity of the delegation or holder(s).

You can also selectively delegate.

## Project Status

⚠️ New project, very work in progress. API is not stable yet.

## API

```rust
use std::result::Result;
use delanocreds::spseq_uc::*;
use delanocreds::utils::InputType;
use delanocreds::dac::Dac*;
use delanocreds::attributes::{Attribute, AttributeName, AttributeValue};
use indexmap::indexmap;

fn main() -> Result<(), amcl_wrapper::errors::SerzDeserzError> {
    // Build a RootIssuer
    let max_entries = 10;
    let max_cardinality = 5;
    let mut root_issuer = RootIssuer::new().max_entries(max_entries).max_cardinality(max_cardinality).build();

    // get an Attributes builder with the constraints of the RootIssuer
    let mut entry_builder = root_issuer.entry_builder();

    // use Root Issuer to generate a root credential
    // it will only allow you to build with attributes up to the limits of the RootIssuer
    // if you add more, it will overwrite the oldest attributes / give you an error

    // Individual attributes are referenced by Provers generating a proof
    // Can add `max_cardinality` into the builder
    let read_attr   = entry_builder.attribute(AttributeName("read"),   AttributeValue("*"))?;
    let create_attr = entry_builder.attribute(AttributeName("create"), AttributeValue("*"))?;
    let update_attr = entry_builder.attribute(AttributeName("update"), AttributeValue("*"))?;
    let delete_attr = entry_builder.attribute(AttributeName("delete"), AttributeValue("*"))?;

    // Generate and insert First Entry using read attribute
    // Cred Holders can add `max_entries` into the builder
    // Returns None is limit has been reached
    let Some(read_entry) = entry_builder.entry("read_entry", vec![read_attr]);

    // Generate and insert Second Entry using create, update and delete elements
    let Some(change_entry) = entry_builder.entry("change_entry", vec![create_attr, update_attr, delete_attr]);

    let all_entries: AttributeEntries = entry_builder.build(); // generate the attributes entries

    // An Attribute Entry is/are selected by Issuers when issuing/delegating a credential
    let read_entry = all_entries["read_entry"]; // get the read entry
    let change_entry = all_entries["change_entry"]; // get the change entry

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
        .allow(vec![read_entry, update_attr])
        .extendable(max_entries) // Allow the delegated party to add more entries up to max_entries
        .delegable() // Allow the delegated party to further delegate the credential to others
        .issue_to(&bobby_nym.proof);

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

`cargo test`

# Docs

`cargo doc --workspace --no-deps --open`

To build the docs incrementally, use `cargo watch -x 'doc --workspace --no-deps --open'`.

## References

Rust implementation of https://github.com/mir-omid/DAC-from-EQS in [paper](https://eprint.iacr.org/2022/680.pdf) ([PDF](https://eprint.iacr.org/2022/680.pdf)).
