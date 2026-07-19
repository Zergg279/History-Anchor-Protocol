# Architecture

## Base protocol

Bitcoin is the sole canonical publication and ordering layer. HAP has no chain, token, mining, staking, or truth-voting consensus.

A node:

1. creates or receives signed records;
2. builds or receives deterministic packages;
3. scans Bitcoin for 38-byte HAP commitments;
4. retrieves matching packages from any peer or archive;
5. validates every byte, signature, identifier, Merkle rule, and active-chain anchor locally;
6. preserves selected evidence;
7. serves verified packages to future nodes.

## Separation of concerns

### Consensus and publication

Bitcoin only.

### Validation

Small deterministic HAP code: canonical JSON, signatures, identifiers, Merkle batches, package hashes, Bitcoin commitments, and exact evidence hashes.

### Transport and preservation

Replaceable peers, archives, snapshots, torrents, and direct transfer. Transport never decides validity.

### Provenance and interpretation

A minimal graph distinguishes protocol facts, signed declarations, and signed analytical overlays. No overlay is consensus truth.

### Responsible publication

An optional local client profile controls discovery and amplification without changing base validity. Its trust store and cooling policy are visible local choices.

## Bootstrap and recovery

One node can bootstrap or re-seed the network. Actual decentralisation requires multiple unrelated operators, archives, and implementations.

No website, repository, domain, peer list, coordinator, or founder key is authoritative.
