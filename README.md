# Delegatable Anonymous Credentials

Create messages that can be held by third parties, re-delegated, and verified without revealing the identity of the holder.

Useful if you want the ability to delegate information without revealing the identity of the delegation.

You can also selectively delegate.

## Advantages

This scheme has the following advantages over other anonymous credential schemes:

-   Attributes: User can selectively disclose and prove some of the attributes in the credential.
-   Expressiveness: S (selective disclosure), R (arbitrary computable relations over attributes, meaning you can do more than just selective disclosure)
-   Rest: Means whether it is possible to apply a restriction on the delegator’s power during the delegation.
-   Selective Anonymity: Strong anonymity guarantees meaning that no one can trace or learn information about the user’s identity or anything beyond what they suppose to show during both the issuing/delegation and showing of credentials.
-   Credential Size: O(1), meaning the size of the credential is constant.
-   Show Size: O(L), meaning the size of the showing grows linearly in the number of delegations.
-   Undisclosed attributes: O(u), meaning the size of the undisclosed attributes grows linearly in the number of delegations.

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

## References

Rust implementation of https://github.com/mir-omid/DAC-from-EQS in [paper](https://eprint.iacr.org/2022/680.pdf) ([PDF](https://eprint.iacr.org/2022/680.pdf)).
