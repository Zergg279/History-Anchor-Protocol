# Changelog

## 1.0.0

- Hardened the complete shipped package to 92% branch-aware coverage with a permanent 90% CI floor.
- Added 140 tests across CLI, Bitcoin RPC, peer sync, API, validators, snapshots, recovery, archive corruption, funding, and failure cleanup; the suite now contains 212 passing tests and one environment-dependent Bitcoin Core skip.
- Made SQLite lifecycle cleanup idempotent and warning-free; resource warnings now fail CI.
- Fixed a hostile-peer resolver defect so a package is never imported unless its batch identifier exactly matches the discovered Bitcoin commitment.
- Made Bitcoin transactions the sole canonical publication and ordering layer.
- Added direct block scanning, active-chain reorganisation rewinds, and unresolved commitment tracking.
- Added deterministic portable packages, peer resolution, direct one-record anchoring, and pre-broadcast package persistence.
- Added content-addressed evidence storage, verified peer retrieval, and survival archives.
- Added append-only subject responses, person-impact notices, restrictions, withdrawals, adjudications, view decisions, and provenance assertions.
- Added `hap-provenance-graph-v1`, separating protocol facts, signed declarations, derived inferences, and external-world claims.
- Added `hap-responsible-publication-v1`: Bitcoin-only feed eligibility, direct/mosaic/uncertain person-impact protection, cooling periods, local accountable-author trust stores, context-complete views, and no unilateral emergency override.
- Kept responsible-publication rules outside base validity so pseudonymous permissionless publication remains intact.
- Renamed unsafe `corroborated` semantics to `multi-attested`; distinct keys are not presumed independent.
- Made anchors output-aware with `txid:vout` identity.
- Bounded package, rate-limiter, JSON, request, evidence, and peer resources.
- Added governance, trust, privacy/erasure, responsible-publication, and threat-model documents.
- Added an external voluntary-funding policy, pseudonymous attribution/genesis templates, a fixed signed-release Bitcoin contribution address, a content-derived funding manifest, `hap funding`, and a local no-network finalisation tool.
