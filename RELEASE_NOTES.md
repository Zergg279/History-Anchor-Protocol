# History Anchor Protocol v1.0.0

The first official source release of HAP: an ownerless, pseudonymous, Bitcoin-first memory protocol.

## Core properties

- Bitcoin is the sole canonical publication and ordering layer.
- No HAP blockchain, token, mining, staking, validator set, or truth vote.
- Direct publication is permissionless; batching is optional cost sharing.
- No required website, server, archive, coordinator, identity issuer, repository, or founder key.
- Packages, records, evidence hashes, and Bitcoin anchors are independently verifiable.
- One complete lawful archive plus Bitcoin history can re-seed the surviving network.
- The official release fixes a voluntary Bitcoin contribution address into signed release metadata and `hap funding`; it remains outside consensus and grants no founder fee, token, royalty, truth status, governance right, or protocol priority.

## Trust and safety boundary

- HAP proves exact bytes, signatures, Bitcoin publication, and reproducible relationships—not arbitrary physical truth.
- The minimal provenance graph distinguishes protocol facts, signed declarations, and derived analytical overlays.
- The optional reference responsible-publication profile protects person-impact claims from automatic discovery, includes fixed non-renewable challenge windows, publishes a transparent view manifest, and has no unilateral public-interest or emergency bypass.
- Permissionless publication is preserved; responsible amplification remains a disclosed local client decision.
- HAP can shape good-faith infrastructure but cannot recall external copies or force hostile publishers to honour context or restrictions.

## Verification posture

The complete shipped Python package has 92% branch-aware coverage, enforced by a 90% CI floor. The suite contains 212 passing tests, treats resource warnings as failures, and includes hostile-peer, malformed-Bitcoin-RPC, archive-corruption, CLI, recovery, and responsible-publication paths. Mainnet anchoring remains disabled by default.

This is the official v1 source and protocol release. The included automated and live-process tests do not replace real Bitcoin Core commissioning or independent review. Before unrestricted public hosting or mainnet use, complete the regtest/signet lifecycle and obtain security, privacy, and legal review.
