# **Del**egatable **Ano**nymous **Cred**ential**s** (Delanocreds)

This library enables you to create, issue, delegate/extend/restrict/transfer, and verify credentials in an anonymous way.

Create Root Credentials, then delegate the ability to add or remove credentials, without revealing the identity of any of the holders in the delegation chain, including the prover!

Useful if you want the ability to delegate credentials, capabilities, or other data without revealing the identity of the delegation or holder(s).

Holders can also selectively prove attributes and remove the ability for delegatees to prove selected attributes.

[![Example Explainer](https://github.com/hyperledger/aries-rfcs/raw/main/concepts/0104-chained-credentials/use-case.png)](https://github.com/hyperledger/aries-rfcs/blob/main/concepts/0104-chained-credentials/README.md)

## Project Status / Roadmap

API works and is stabilizing, but may change in the future.

Roadmap:

- [x] Passing tests
- [x] Basic Public API
- [ ] Stable API
- [ ] DelanoWallet (Store, Sign, Backup Credentials)
- [ ] DelanoNet (Data Exchange Network)

## Delegation

There are a few ways the delegation can be used:

### Delegate adding Entries

We can delegate the ability to add Entries (up to `MaxEntries`), but only if the credential is marked as `extendable` and the available Entry slots have not all been used by previous delegatees.

Even if there is no ability for a credential holder to add additional attributes, the following always holds true:

- Credentials holders can always assign their credential to a new public key
- Attributes are always able to be selectively shown or hidden by a holder

It is important to note that whether the current holder can add Entries or not, the Credential can always be assigned to a new public key, that is what makes this scheme anonymizable.

Therefore, while holders may restrict the ability of delegatees to _add_ attributes, they will always be
able to assign the credential to a new public key for the attributes they _do_ have.

### Issuer Delegation

This is where things get really powerful. The Root Issuer can delegate a blank credential to a server's Public Key, enabling the server to Issue credentials on it's behalf without ever giving up the root secret!

Example: You want to set up an email campaign to email contacts a Credential that allows them to prove they own that email address. Of course you want a bot to process the form for you instead of doing it by hand. You issue a delegatable credential to the Server's Public Key. Now only that Public Key can issue credentials on that empty Root credential, and if the keys are exposed because of a server hack you don't expose your root secret keys. Additional protocols can be layered on top such as adding an expiry date to the original credential, invalidating any credential that was issued after this date with a stolen key.

### Prover Delegation

Not online all the time to generate proofs? No problem! Users can actually even delegate proving of a credential to another (say, a server) who can generate the proof on their behalf, again without having to expose any of their secret keys. The User can disable additonal entries, or even redact entries, restricting the abilities of the server to change entry attributes or prove certain entries. Because the Attributes are all Sha2-256 hashed, the server does not even know the attribute values! In the event of stolen keys, all the theif would be able to do is make more proofs on our behalf (thank you for the free services).

## Root Issuer Summary of Choices/Options:

- **Maxiumum Attribute Entries**: Maximum number of `Entry`s per `Credential`.
- **Maximum Cardinality**: Maximum selectable number of `Attributes` per `Proof` or `Entry`

## Attributes

`Attribute`s can be created from any bytes, such as `age > 21` or even a `.jpg` file. These bytes are hashed usin Sha2-256, which means they are also content addressable! Once an `Attribute` is created, it can be referenced by it's [`Content Identifier` (`CID`)](https://cid.ipfs.tech/) instead of the value itself. This means we can also refer to attributes by their `CID`, and not have to worry about revealing the actual content of the attribute or re-hashing the content when it needs to be referenced.

The algorithm used to hash the attributes is Sha2-256, with a length of `32 bytes` which is the typical `32 byte` digest commonly seen. If you try to create an `Attribute` out of a `CID` with a different hash or length, it will fail and result in an error. For this reason, use the `Attribute` methods provided by this library when creating `Attribute`s.

```rust
use delanocreds::Attribute;

let some_test_attr = "read";

let read_attr = Attribute::new(some_test_attr); // using the new method

// Try Attribute from cid
let attr_from_cid = Attribute::try_from(read_attr.cid()).unwrap(); // Error if wrong type of CID
assert_eq!(read_attr, attr_from_cid);

// Attribute from_cid
let attr_from_cid = Attribute::from_cid(&read_attr).expect("a Sha2-256 hash type"); // Returns `None` if wrong type of CID
assert_eq!(read_attr, attr_from_cid);
```

If an Attribute is public, then you could store it to a content addressed storage like IPFS. If the Attribute is sensitive, then the Attribute can just be referred to by it's hash.

Note that if someone has both a `Credential` `Offer` and the `Attributes` or even their hashes, they will be able to claim the `Credential`, so you want to keep `Offer`s and their associated `Attributes` separate (or securely transported if together).

## Entries

A `Credential` is comprised of one or more `Entry`s. Each `Entry` contains one or more `Attribute`s. Entries are used to group `Attribute`s together.

```md
Attribute Entries:
==> Entry Level 0: [Attribute, Attribute, Attribute]
==> Entry Level 1: [Attribute]
==> Entry Level 2: [Attribute, Attribute]
==> Additonal Entry? Only if 3 < Extendable < MaxEntries
```

## Redact

Holders of a `Credential` can redact any `Entry` from the `Credential`, which will remove the ability to create proofs on any `Attribute`s in that `Entry`. This is useful if you want to remove the ability for a delegatee to prove a specific attribute, but still allow them to prove other attributes. It is important to note that if the ability to `prove` an Attribute is removed before delegating a `Credential`, then the entire Entry is removed -- not just the single `Attribute`. If you want to still allow a delegtee to use the other Attributes, you must create a new Entry with the other Attributes and delegate the extended `Credential`.

This is done by zeroizing the `Opening Information` for the `Entry` commitment in the Credential so a proof cannot be created.

## Bindings

The intention is to provide the following bindings:

- [x] Rust API
- [ ] wasm bindgen (wasm32-unknown-unknown)
- [x] [wasm interface types](https://component-model.bytecodealliance.org/design/wit.html) (WIT)

## Rust API

Current full API is available by looking at the `src/lib.rs` tests. Below is a small sampling of how to use the API.

```rust
use anyhow::Result;
use delanocreds::{Issuer, Nym, verify_proof, Nonce, Entry, MaxEntries, Attribute};

fn main() -> Result<()> {
    // Build a RootIssuer with ./config.rs default sizes
    let mut issuer = Issuer::default();

    // Create Entry of 2 Attributes
    let over_21 = Attribute::new("age > 21");
    let seniors_discount = Attribute::new("age > 65");
    let root_entry = Entry::new(&[over_21.clone(), seniors_discount.clone()]);

    // Along comes Alice's (pseudo)nym
    let alice_nym = Nym::new();

    // In order for Alice to be issued a Root Credential from the Issuer, the Nym must be randomized to keep her anonymous
    // as non-randomized Nym's are used only to accept Credentials.
    let alice_nym = alice_nym.randomize();

    // A verifier can demand the nym proof include a nonce to prevent replay attacks, or it can skip with with `None`
    // The nonce can be compared against the Pedersen open randomness in the `NymProof` to verify that a replay
    // attacker isn't reusing a previously generated proof
    let nonce = Nonce::default(); // generates a random nonce for us

    // Give a nonce to Alice so she can generate a NymProof using it
    let nym_proof = alice_nym.nym_proof(&nonce);

    let cred = issuer
        .credential() // CredentialBuilder for this Issuer
        .with_entry(root_entry.clone()) // adds a Root Entry
        .max_entries(&MaxEntries::default()) // set the Entry ceiling
        .issue_to(&nym_proof, Some(&nonce))?; // issues to a Nym

    // Send the (powerful) Root Credential, Attributes, and Entrys to Alice

    // Alice can use the Credential to prove she is over 21
    let (proof, selected_attributes) = alice_nym.proof_builder(&cred, &[root_entry.clone()])
        .select_attribute(over_21.clone())
        .prove(&nonce);

    assert!(verify_proof(&issuer.public, &proof, &selected_attributes, Some(&nonce)));

    // Alice can offer variations of the Credential to others
    let bobby_nym = Nym::new();

    let (offer, provable_entries) = alice_nym.offer_builder(&cred, &[root_entry])
        .without_attribute(seniors_discount) // resticts the ability to prove attribute Entry (note: Removes the entire Entry, not just one Attribute)
        .additional_entry(Entry::new(&[Attribute::new("10% off")])) // adds a new Entry
        .max_entries(3) // restrict delegatees to only 3 entries total
        .open_offer()?;

    // Send to Bob so he can accept the Credential
    let bobby_cred = bobby_nym.accept(&offer)?;

    // and prove all entries
    let (proof, selected_attributes) = bobby_nym.proof_builder(&bobby_cred, &provable_entries)
        .select_attribute(over_21)
        .prove(&nonce);

    assert!(verify_proof(&issuer.public, &proof, &selected_attributes, Some(&nonce)));

    Ok(())
}
```

## Features

### Advantages

This DAC scheme has the following advantages over other anonymous credential schemes:

- **Attributes**: User can selectively disclose and prove some of the attributes in the credential.
- **Expressiveness**: S (selective disclosure), R (arbitrary computable relations over attributes, meaning you can do more than just selective disclosure)
- **Rest**: Means whether it is possible to apply a restriction on the delegator’s power during the delegation.
- **Selective Anonymity**: Strong anonymity guarantees meaning that no one can trace or learn information about the user’s identity or anything beyond what they suppose to show during both the issuing/delegation and showing of credentials.
- **Credential Size**: O(1), meaning the size of the credential is constant.
- **Show Size**: O(L), meaning the size of the showing grows linearly in the number of delegations.
- **Undisclosed attributes**: O(u), meaning the size of the undisclosed attributes grows linearly in the number of delegations.

Table 1. Comparison of practical DAC schemes

| Scheme   | Attributes | Expressiveness | Rest | Selective Anonymity | Credential Size | Show Size |
| -------- | ---------- | -------------- | ---- | ------------------- | --------------- | --------- |
| [BB18]() | ✔️         | S/R            | ≈    | 🌓†                 | O(1)            | O(u)      |
| [CDD]()  | ✔️         | S/R            | ✖️   | 🌗♣                | O(nL)           | O(uL)     |
| [CL]()   | ≈          | ✖️             | ✖️   | 🌙\*                | O(nL)           | O(uL)     |
| [This]() | ✔️         | S              | ✔️   | 🌚‡                 | O(1)            | O(L)      |

🌓† Requires a trusted setup and have a trapdoor associated to their parameters.

🌗♣ It does not support an anonymous delegation phase.

🌙∗
It also allows an adversarial CA but no delegators’s keys leaks.

🌚‡ We consider a malicious issuer key CA and all delegators keys can be exposed.

## Hashing

[RFC9380](https://datatracker.ietf.org/doc/rfc9380/) recommends expanded message digest (XMD) for BLS12-381 curves when hashing to curve (as opposed to extendable-output function (XOF) for Sha3 SHAKE). Libraries that support XMD are [blst](https://github.com/supranational/blst/blob/78fee18b25e16975e27b2d0314f6a323a23e6e83/bindings/rust/src/lib.rs#L264) and [pairing_plus](https://docs.rs/pairing-plus/latest/pairing_plus/hash_to_field/struct.ExpandMsgXmd.html).

# Tests

`cargo test --workspace`

# Build Binary Release

`cargo build --bin delanocreds-bin --release`

Run the built binary:

`./target/release/delanocreds-bin.exe`

## Speed

This library can generate, issue, delegate, prove and verify 30 selected credentials out of 100 issued attributes in less than 400ms on [Intel i5-3470 CPU @ 3.20GHz](https://cpu.userbenchmark.com/Intel-Core-i5-3470/Rating/2771).

That's fast enough for time-critical applications like public transportation, ticketing, etc.

## Quick Bench

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

- l - upper bound for the length of the commitment vector
- t - upper bound for the cardinality of the committed sets
- n < t - number of attributes in each attribute set A_i in commitment
- C_i (same for each commitment level)
- k - length of attribute set vector
- k_prime - number of attributes sets which can be delegated

We set the above parameters as t = 25, l = 15, k = 4, k' = 7 and n = 10 to cover many different use-cases

Assumption:

- each time a credential is delegated, an attribute is added

## Docs

`cargo doc --workspace --no-deps --open`

To build the docs incrementally, use `cargo watch -x 'doc --workspace --no-deps --open'`.

Build the docs in Windows for Github pages: `./build_docs.bat`

## References

Rust implementation of [https://github.com/mir-omid/DAC-from-EQS](https://github.com/mir-omid/DAC-from-EQS) in [paper](https://eprint.iacr.org/2022/680.pdf) ([PDF](https://eprint.iacr.org/2022/680.pdf)).
