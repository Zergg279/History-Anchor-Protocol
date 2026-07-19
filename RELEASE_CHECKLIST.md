# Release checklist — v1.0.0

## Founding invariants

- [x] no HAP blockchain, token, mining, staking, validator set, or truth consensus;
- [x] Bitcoin transaction is canonical publication and ordering;
- [x] pseudonymous key creation and publication require no registration;
- [x] direct publication exists; batching is optional convenience;
- [x] no required website, domain, peer, coordinator, archive, repository, or founder key;
- [x] MIT licence, open specification, and independent implementation path;
- [x] one complete lawful archive plus Bitcoin history can re-seed the network.
- [x] voluntary funding is external to validity and grants no token, governance, truth, ranking, or publication privilege.

## Protocol and safety implementation

- [x] Bitcoin active-chain scan and reorganisation handling;
- [x] `txid:vout` anchor identity;
- [x] durable direct-publication package before broadcast;
- [x] strict signed records and append-only context kinds;
- [x] arbitrary peer package retrieval and independent validation;
- [x] evidence bytes accepted only by committed hash;
- [x] minimal provenance graph separates facts, declarations, and overlays;
- [x] no independence claim based on keys or outlet counts;
- [x] responsible reference feed lists Bitcoin-confirmed claims only;
- [x] direct, mosaic, uncertain, and missing person-impact states protect by default;
- [x] public-interest objects have no automatic effect;
- [x] subject responses and disputes remain prominent without granting indefinite burner-key suppression;
- [x] anchored notices create one fixed non-renewable challenge window; persistent restriction or enabling requires a local recognised decision;
- [x] no unilateral emergency amplification bypass;
- [x] exact-ID views expose linked context;
- [x] hostile-client and external-copy limitations stated explicitly;
- [x] bounded request, batch, package, JSON, relay, evidence, and peer resources;
- [x] mainnet opt-in and fee ceiling.

## Verification completed in this environment

- [x] 212-test unit and integration suite with one Bitcoin Core environment skip;
- [x] 92% branch-aware coverage across the complete shipped package and a 90% CI floor;
- [x] zero resource warnings with warning-to-error enforcement;
- [x] hostile-peer wrong-commitment regression test;
- [x] two-process HTTP network smoke lifecycle;
- [x] clean wheel build and clean virtual-environment installation;
- [x] release manifest and checksum verification;
- [x] Python and shell syntax checks.

## Publication identity and funding

- [x] stable public pseudonym configured as Horus;
- [x] Bitcoin mainnet Taproot (`bc1p...`) contribution address configured and checksum-validated;
- [x] `scripts/finalize_public_identity.py` completed;
- [x] `scripts/check_publication_markers.py` confirms no template markers remain;
- [ ] create a dedicated release-signing key and sign the genesis statement and release tag;
- [x] `hap funding`, `/v1/funding`, `FUNDING.md`, `FUNDING_MANIFEST.json`, and `GENESIS_STATEMENT.md` contain the identical project address;
- [ ] keep contribution accounting and obtain UK tax advice before funding becomes material.

## External commissioning still required

- [ ] run the included lifecycle against a real Bitcoin Core regtest node;
- [ ] confirm a real signet transaction and verify through an independent Bitcoin node;
- [ ] commission Docker, TLS, firewall, backup, destruction, and restore on the target host;
- [ ] run a networked dependency vulnerability audit;
- [ ] enable private vulnerability reporting and publish a monitored security contact on the chosen repository;
- [ ] obtain independent security, privacy, and legal review before unrestricted public hosting;
- [ ] obtain a second independently written validator before claiming mature protocol decentralisation.
