# Threat Model

## Protected properties

HAP aims to preserve:

- exact record integrity;
- pseudonymous authorship proofs;
- Bitcoin-confirmed publication and ordering;
- append-only context;
- independent verification;
- recoverability from surviving lawful archives;
- replaceability of every server and interface.

## Explicitly unsolved by consensus

HAP does not solve:

- arbitrary external-world truth;
- proof that two identities are independent people;
- universal deletion of copied information;
- universal compliance by hostile clients or foreign operators;
- perfect detection of direct or mosaic identifiability;
- permanent availability if every copy is destroyed;
- automatic legitimacy of source, device, C2PA, identity, or public-interest declarations.

## Attacks and mitigations

### Forged or malformed records

Strict schemas, canonical encoding, Ed25519 verification, content-derived IDs, and unknown-critical-version rejection.

### Sybil attestations and dispute floods

Counts are descriptive, not votes. Exact duplicates are grouped. Relay rate limits, optional proof-of-work, batching costs, and local visibility policies limit resource abuse.

### False source independence

Different accounts, keys, outlets, or timestamps never prove independence. Exact byte reuse is deterministic; stronger lineage claims remain signed overlays.

### Dominant client manipulation

Reference clients expose profile version, linked context, local trust choices, and raw proofs. A hostile client can ignore them; HAP cannot force non-conforming software to behave responsibly.

### Harmful allegations about identifiable people

The reference profile uses precautionary person-impact states, fixed non-renewable challenge windows, context-complete exact-ID views, cooling periods, and no automatic public-interest or emergency bypass. Subject responses remain prominent without becoming an indefinite burner-key suppression mechanism. These controls reduce HAP-native amplification but cannot recall external copies.

### Burner-key emergency abuse

V1 contains no emergency amplification bypass. Future ecosystem profiles must not grant immediate mass reach through self-declaration or payment.

### Illegal or harmful evidence

Bitcoin contains only opaque commitments. Public record endpoints do not accept raw evidence. Evidence retrieval is deliberate, locally controlled, size bounded, and hash checked. Archive operators remain responsible for lawful storage and reporting.

### Bitcoin reorganisations

Nodes track block context, identify anchors by `txid:vout`, and rewind to the common active-chain ancestor.

### Malicious peers

Packages, snapshots, anchors, and evidence are independently validated. Imported anchor status remains untrusted until checked against local Bitcoin data.

### Founder or repository capture

No upgrade key or required service exists. Specifications, releases, vectors, and mirrors are portable. Independent implementations and maintainers remain an adoption requirement.
