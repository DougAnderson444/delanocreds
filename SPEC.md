# Delanocreds (Working Draft) Spec

## Introduction

This library generally follows the [DAC-from-EQS](https://eprint.iacr.org/2022/680.pdf) paper where possible.

## Public Parameters

There are a few notable difference or absences from the paper:

- Public Parameter Generators: In the paper, the Group 1 and Group 2 Generators are kept in the state variables. In our implementation, we have decided to use the [convention](https://github.com/zcash/librustzcash/blob/6e0364cd42a2b3d2b958a54771ef51a8db79dd29/pairing/src/bls12_381/README.md#generators) as constants.

- Public Paramters Verification Key: The Verification Key can become quite long if the credential has many Entries available to it. However, by usinga key derivation function (`kdf`, like `blastkids` library), we can compress this down to a single G1 and G2. Delanocreds `IssuerPublic` has a `to_compact` function which will compact a VK to just these 2 Group points, making the JSON or QR Code smaller.

In the end, this gives us four values to identify an `Issuer`:

| Value                 | Each Size (bytes) | Number          |
| --------------------- | ----------------- | --------------- |
| `G1` Commits          | 48                | Cardinality + 1 |
| `G2` Commits          | 96                | Cardinality + 1 |
| `G1` Verification Key | 48                | MaxEntries      |
| `G2` Verification Key | 96                | MaxEntries      |

## Encoding Bytes

This is new technology, so there is no standard for encoding these values. So far, this is the only library offering a practical usabel solution. We have decided to use the following formats until we need to standardize:

- When a credential is passed to a Nym for acceptance/use, it must be serialized and transmitted somehow. Possibly using a QR Code, URL Link, SMS Text message, email, chat, or anything else.

- When the value is serialized to JSON, the values are Base64URL encoded in the JSON object (mostly for debugging / prettyprint display).

- When the value is serialized to bytes, the values are CBOR bytes of the Object (for passing Credentials around).

This should allow users to import/export the bytes in a reasonably short and convenient manner.

## Proving a Credential

- TODO: Presentation proof format.
- See [JSON Web Proofs spec](https://github.com/json-web-proofs/json-web-proofs)
