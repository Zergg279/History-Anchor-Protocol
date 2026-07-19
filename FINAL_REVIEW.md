# Final architecture review — v1.0.0

## Verdict

The implementation preserves the founding architecture:

- Bitcoin transactions are the sole canonical publication and chronological ordering mechanism.
- HAP has no independent chain, token, mining, staking, validator set, or truth-voting consensus.
- Pseudonymous key generation, signed authorship, direct publication, verification, preservation, dispute, and correction require no central permission.
- HAP software is a lightweight interpreter, validator, package transport, archive, index, provenance reporter, and optional publication-policy client around Bitcoin commitments.
- No website, repository, coordinator, peer, archive, domain, trust store, identity issuer, or founder key is required by base protocol validity.
- One complete surviving lawful archive plus Bitcoin history can re-seed the surviving memory layer.

## Bitcoin integration

The commitment is an ordinary 38-byte `OP_RETURN` payload. Bitcoin miners and Bitcoin Core require no HAP upgrade. Nodes scan Bitcoin directly, track active-chain status, rewind on reorganisations, and identify anchors by `txid:vout`.

Bitcoin decides whether publication exists. Peers only transport packages and evidence.

## Protocol versus product

The bundled interface is a replaceable reference client. Deleting it, its domain, or the original repository does not alter protocol validity. Independent implementations can scan Bitcoin, retrieve packages, validate them, and publish new records.

GitHub is a first distribution channel, not ownership.

## Validation and truth boundary

V1 distinguishes:

- protocol facts reproducible from bytes, signatures, HAP links, and Bitcoin state;
- signed declarations whose authorship is proven but whose honesty is not;
- signed derived inferences naming an analysis ruleset;
- external-world claims that HAP never turns into consensus truth.

Different keys, outlets, URLs, or timestamps do not prove independent origin. Exact evidence hashes can be grouped deterministically. Stronger source-family analysis remains a challengeable overlay.

## Responsible publication without managed consensus

The optional `hap-responsible-publication-v1` profile is implemented separately from base validity.

It:

- lists only Bitcoin-confirmed claims in the reference feed;
- protects direct, mosaic, uncertain, or missing person-impact records;
- gives public-interest declarations no automatic effect;
- shows subject responses and disputes prominently without granting indefinite suppression;
- uses a fixed non-renewable notice challenge window and requires locally recognised accountable decisions for persistent restriction or enabling;
- implements no unilateral emergency bypass;
- keeps exact-ID access and linked context available.

A local recognised-author list is an explicit client trust store, not a HAP authority. A hostile client can ignore these rules and must not be described as profile-conforming.

## Privacy and erasure boundary

Bitcoin contains opaque commitments, not readable allegations or evidence. Compliant operators can restrict or erase off-chain indexing, locators, hosted evidence, and opening material. Copies already downloaded, mirrored, screenshotted, or republished outside compliant infrastructure cannot be recalled.

The protocol manages HAP-native propagation; it cannot guarantee universal deletion or reputational repair.

## Lightweight core

The Python reference implementation contains approximately 5,842 Python source lines and four direct runtime dependencies. It uses SQLite and Bitcoin Core rather than constructing a second consensus system.

Optional interfaces, AI analysis, institutional integrations, and alternative editorial views remain outside base validation.

## Verification status

The in-environment suite, conformance vectors, two-process HTTP lifecycle, syntax checks, wheel build, clean installation, and release-integrity checks are recorded in `BUILD_REPORT.md`.

The actual Bitcoin Core regtest and signet broadcast lifecycle cannot be claimed until executed against a real `bitcoind` process. Mainnet remains disabled by default.

## Release boundary

V1.0.0 is suitable as the first official open-source protocol and source-code release. It is not a guarantee that software cannot fail, a declaration of arbitrary truth, a universal moderation system, or permission to operate an unreviewed public archive in every jurisdiction.

Before unrestricted public hosting or mainnet activation, operators must complete real Bitcoin commissioning and independent security, privacy, and legal review.
