# Delanocreds Spec

## Introduction

-   Everything starts with the Issuer(s)
-   Issuer generates public parameters (PP) and verification key (VK)
-   PP and VK need to be made pubicly available, such as on a website (enterprise issuer) or dweb network (p2p issuer)
-   p2p might present a catch-22 since the issuer's PP & VK needs to be known to the holder, but the holder needs to discover the issuer in p2p network... maybe a p2p network of issuers? Or Out of band bootstrapping of immediate contacts? Or Issuers sending links to their contacts with Vouchers/Invites?
-   Need to pick formats, such as json web proofs? cbor (DAG'able)? json (readable)? borsh (fastest)?

## Issuing a Root Credential

-   Issuer generates a root credential
-   Issued to a Root Nym

## Offering a Credential

-   Holder generates
-   1. Offer, and 2) associated Entrys
-   Offer & Entrys should be kept seperate or confidential/encrypted since anyone holding both could accept the credential
-   Holder makes the offer availble to the next holder

## Accepting a Credential

-   New Holder accepts the offer and stored the resulting credential and Entrys for later use

## Proving a Credential

-   Holder selects which Entry Attributes to show and generates a proof
