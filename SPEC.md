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

## Encoding Public Parameters

There is no standard for encoding these values. However, we have decided to use the following format:

Base64URL encoded strings separated by a `.`:

```text
<Base64URL<vk_g1>>.<Base64URL<vk_g2>>.<Base64URL<ck_g1>>.<Base64URL<ck_g2>>
```

Example of 48 bytes of `G1`, or 64 characters of Base64URL:

```md
EjRWeBI0VngSNFZ4EjRWeBI0VngSNFZ4EjRWeBI0VngSNFZ4EjRWeBI0VngSNFZ4
1234567890123456789012345678901234567890123456789012345678901234
1 2 3 4 5 6
```

An example of 96 bytes of `G2`, or 128 characters of Base64URL:

```md
EjRWeBI0VngSNFZ4EjRWeBI0VngSNFZ4EjRWeBI0VngSNFZ4EjRWeBI0VngSNFZ4EjRWeBI0VngSNFZ4EjRWeBI0VngSNFZ4EjRWeBI0VngSNFZ4EjRWeBI0VngSNFZ4
```

An example `VKG1`.`VKG2`.`CKG1`.`CKG2` (384 characters):

```md
l*HTpzGX15QmlWOMT6msD8NojE-XdLkFoU46PxcbrFhsVeg*-Xoa7*s68ArbIsa7.k-ArYFJxn2B9rNOgiCdPZVlr0NCZILYatdphu9x_UEkzTPESE5RdV-WsfQVdBCt-AkqisvCPCpEmCAUnLcUQUcbketT6QDsCtFELZHrj0XcLrAMmqAW779SAVsjBIb24.kJlLZzDrtzXUxtZKqTXVmXGyzMk6lhKc3xyoJ3K5yphAMY1tcDjGvFL6wrA48X9G.pYMbI5MW2Ht-64mR9mGR4XqnMiJTGlguVTG1k0NN-NqnaMtsv81gNVlAE4GfHoDuB_17GwbtvfzXabcl2Cjgkn2QEfyFlm55GrXLoH5b-\_xKgj4vGuBV50b2p7Mf-2x*
```

When the bytes are encoded to Base64, the character length should be no more than a total of 384 characters, with 3 extra characters for the `.` separators, makes a total of 387 characters.

Although this is too big for a tweet, which is capped at 280 characters, it is still small enough to be used in a URL or a QR Code (Max. 4,296 alphanumeric characters 7096). An example QR code is:

A MaxCardinality of 12 is the most Public Parameters that can be encoded in a standard QR Code with a compact VK.

## Proving a Credential

- TODO: Presentation proof format.
- See [JSON Web Proofs spec](https://github.com/json-web-proofs/json-web-proofs)
