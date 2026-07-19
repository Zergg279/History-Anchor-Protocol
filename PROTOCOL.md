# History Anchor Protocol v1.0

## 1. Purpose

History Anchor Protocol (HAP) is an open memory language interpreted from Bitcoin transactions. It defines signed historical records, deterministic batch manifests, portable packages, Bitcoin commitments, evidence relationships, a minimal provenance graph, and an optional responsible-publication profile.

HAP has no chain, coin, miner set, staking system, or independent consensus. Bitcoin's active proof-of-work chain is the sole canonical publication and ordering layer.

## 2. Canonical encoding

Consensus objects use `hap-canonical-json-v1`:

- UTF-8 JSON;
- object keys sorted lexicographically by Unicode code point;
- no insignificant whitespace;
- no floating-point values or NaN;
- integers restricted to the cross-language JSON-safe range;
- no Unicode normalisation or hidden extension fields;
- nesting depth limited to 32.

Conforming implementations must reproduce the published conformance vectors exactly. Unknown critical versions and fields are rejected rather than guessed.

## 3. Canonical publication

A package is canonically published only when its batch-manifest identifier appears in a valid HAP commitment confirmed in Bitcoin's active chain.

The commitment is 38 bytes:

| Bytes | Meaning |
|---:|---|
| 4 | ASCII `HIST` |
| 1 | commitment version `03` |
| 1 | type `01` (batch manifest) |
| 32 | SHA-256 batch manifest identifier |

An anchor is identified by `txid:vout`, because one Bitcoin transaction may contain more than one HAP commitment. No Bitcoin consensus change or miner upgrade is required.

## 4. Records

Record schema `hap.record`, version `1`, supports:

- `claim`
- `attestation`
- `dispute`
- `correction`
- `subject_response`
- `person_impact_notice`
- `restriction_notice`
- `withdrawal_notice`
- `legal_adjudication`
- `public_interest_justification`
- `view_decision`
- `provenance_assertion`

Records are signed with Ed25519 and identified by SHA-256 of the canonical signed envelope. Only `claim` has no target. Every other kind points to an earlier record identifier and never replaces it.

A signing key is a pseudonymous protocol identity. Legal names and external credentials are optional and are never required for base authorship, publication, verification, preservation, dispute, or correction.

## 5. Evidence

Records commit to filename, byte size, media type, SHA-256, and an optional content address. Evidence bytes remain outside Bitcoin. A node accepts evidence only when the exact bytes hash to the signed digest.

Integrity and availability are separate:

- Bitcoin plus signatures prove publication, ordering, and tamper evidence.
- Archive nodes, snapshots, torrents, direct transfer, and other content-addressed transports preserve and distribute the bytes.

No node is required to retrieve or retain every referenced file. Public relay endpoints accept structured signed records, not raw file uploads.

## 6. Batch manifests

Batch schema `hap.batch`, version `3`, orders unique record identifiers lexicographically, constructs the Merkle root, declares algorithms, and derives `batch_id` from the canonical manifest. The Bitcoin payload commits to `batch_id`.

A coordinator is only a cost-sharing convenience. Any user may create a one-record batch and anchor it directly.

## 7. Portable packages

Package schema `hap.package`, version `1`, contains the complete batch and every committed record in exact batch order. A package is rejected if any record, signature, identifier, ordering rule, Merkle root, manifest identifier, or package identifier fails.

The package is the retrievable preimage of the Bitcoin commitment. Direct-publication tools persist it before broadcasting the Bitcoin transaction.

## 8. Bitcoin discovery

Nodes scan blocks from an operator-selected activation height, inspect every transaction output for valid HAP commitments, record the active-chain block context, and rewind to the common ancestor during a reorganisation.

A commitment may be known before its package is available. It remains unresolved until any peer, archive, snapshot, torrent, or direct transfer supplies a package that validates against the Bitcoin-committed manifest identifier.

Bitcoin decides publication. Peer transport never decides validity.

## 9. Peer bootstrap

A first node can begin alone. A later node needs Bitcoin history plus the address of any existing HAP peer or a portable survival archive. Peer addresses are replaceable bootstrap hints; no official peer list is protocol authority.

One machine can bootstrap or recover a network. One machine alone is not a decentralised network.

## 10. Evidence-state assessment

`hap-evidence-assessment-v1` reports deterministic protocol facts:

- signature validity;
- active-chain Bitcoin publication;
- locally available evidence whose bytes match;
- Bitcoin-anchored attestations, disputes, and corrections;
- number of distinct attesting keys.

Classifications are `unpublished`, `bitcoin-anchored-claim`, `attested`, `multi-attested`, `contested`, or `corrected`.

Multiple keys do not prove multiple independent people. Proof-of-work, signatures, majority opinion, AI output, or repeated attestations never turn an arbitrary external-world assertion into mathematical truth.

## 11. Minimal provenance graph

`hap-provenance-graph-v1` separates:

- **protocol facts:** exact hashes, signatures, target links, Bitcoin status, and exact byte equality;
- **signed declarations:** source URIs or lineage statements that are authenticated but not independently proven true;
- **derived inferences:** signed `provenance_assertion` records naming an analytical ruleset and optional confidence;
- **external-world claims:** never determined by protocol consensus.

Different keys, URLs, outlets, or timestamps do not prove independent upstream origin. Exact duplicates can be grouped deterministically; stronger source-family and independence claims remain inspectable analytical overlays.

Internal record references use `hap:record:<record-id>`. External safe-relay source links use HTTPS.

## 12. Responsible-publication profile

`hap-responsible-publication-v1` is an optional client and relay profile. It is not a consensus rule and cannot invalidate a Bitcoin-confirmed publication.

The reference profile uses reserved tags:

- `hap:person-impact:none`
- `hap:person-impact:direct`
- `hap:person-impact:indirect-or-mosaic`
- `hap:person-impact:uncertain`
- `hap:view:enable-discovery`
- `hap:view:restrict-discovery`

Reference relays require one person-impact declaration for claims. Missing, direct, mosaic, or uncertain impact begins protected. An anchored person-impact or restriction notice starts one fixed, non-renewable challenge window. Later burner notices do not extend it. Subject responses and disputes remain prominently visible but do not by themselves suppress discovery indefinitely.

A public-interest justification is only a signed declaration and has no automatic effect. There is no unilateral emergency override.

The reference feed lists only Bitcoin-confirmed claims. Claims declared `none` are discoverable unless a fixed challenge window or recognised restriction is active. Protected claims may be enabled after the configured Bitcoin-block cooling period by a Bitcoin-anchored `view_decision` from an author recognised by that local client. Recognition is a local transparent trust-store choice, not protocol authority.

Exact-identifier access remains available, and record views return the complete linked context. Hostile clients can ignore this profile and must not be described as conforming responsible-publication clients.

## 13. Privacy, restriction, and erasure boundary

Bitcoin contains only an opaque commitment. Human-readable claims, personal data, locators, and evidence remain off-chain.

The protocol distinguishes:

1. permanent opaque proof of publication;
2. revocable indexing, serving, retrieval, and storage within compliant infrastructure;
3. copies outside compliant infrastructure that cannot be recalled.

Restriction and erasure are local operator actions represented by signed context records. They do not rewrite Bitcoin or globally invalidate the original publication.

## 14. Recovery

A survival archive contains a validated snapshot plus all locally preserved evidence bytes. Each evidence member is re-hashed before protocol state is imported.

One complete surviving archive and access to Bitcoin history are sufficient to reconstruct and re-seed the surviving HAP layer, excluding material the operator no longer lawfully or operationally retains.

## 15. Versioning

Unknown critical versions are rejected. New schemas add interpretation without changing historical objects. Algorithm migrations add new commitments and proofs without erasing old ones.

The responsible-publication profile, trust stores, and analytical overlays may evolve independently from base-protocol validity.
