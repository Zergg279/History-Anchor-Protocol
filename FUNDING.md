# Funding History Anchor Protocol

HAP is an ownerless open protocol. Funding supports development, testing, documentation, audits, preservation research, and public infrastructure. It does not purchase protocol authority.

## Official v1.0.0 genesis contribution address

The official v1.0.0 reference release contains this fixed Bitcoin mainnet address:

`bc1pughulyqcqtxjz7xsa3lgd7pmkfd3ptper3z55n7gh4ffjjk2xrxsj6lqds`

Funding manifest identifier:

`09604d121490a3c598a0da039b469f76282ecb1e7690234d8e4315f8569f7c41`

The address is included in the source code, `FUNDING_MANIFEST.json`, this document, and the founder-attributed genesis release statement. A different address therefore produces a different source tree, Git commit, release tag, manifest identifier, and release artifact.

This makes unauthorised replacement **detectable** when users compare the source revision, release tag, funding manifest, and published artifact checksums. It does not make the address a Bitcoin or HAP consensus rule. A fork can publish a different address, but cannot truthfully present it as the original v1.0.0 source release.

The GitHub v1.0.0 release is not cryptographically signed by a dedicated Horus release key. Creating and publishing such a key remains an explicit future hardening step. Until then, users should obtain the address from the official repository release, compare the manifest identifier across independent mirrors where available, and verify published artifact checksums. Never trust an address copied only from an advertisement, social post, search result, or unverified mirror.

A static address creates an intentional privacy tradeoff: contributions and balance activity are publicly linkable. It must be a fresh project-only address that has never been used for personal savings, node operations, or another identity.

## Funding boundary

All support is voluntary and external to base-protocol validity.

Contributing funds provides **no**:

- token, equity, ownership, revenue share, or promised return;
- governance vote, protocol veto, or privileged validation status;
- priority over records, disputes, corrections, or security reports;
- entitlement to influence truth, ranking, amplification, or Bitcoin publication;
- warranty that the software or network cannot fail.

HAP contains no founder fee, premine, mandatory donation, protocol royalty, or consensus-enforced payment destination. A fork or independent implementation does not owe the founder or project anything.

## Optional invoice services

A later project website or self-hosted BTCPay Server may create fresh Bitcoin or Lightning invoices for improved privacy. Such a service is optional and replaceable. Its current destination must be authenticated by a founder or maintainer signing key and must never override the v1.0.0 genesis address silently.

## Separation from node services

Independent operators may charge transparent market prices for optional services such as batching, storage, retrieval, support, or institutional deployment. Those services cannot alter base validity or prevent direct Bitcoin publication.

Project contributions and operator service fees are separate:

- project contributions fund open-source work;
- operator fees pay a particular operator for an optional service;
- Bitcoin network fees pay miners for transaction inclusion.

## Custody and accounting

Initial project funds should use a dedicated wallet, separate from personal savings and node operational wallets, protected by hardware-backed keys and reliable backups. When multiple independent maintainers exist, project funds should move to a disclosed multisignature policy rather than depend indefinitely on one person.

Maintain records of:

- transaction ID and invoice identifier;
- date and time received;
- BTC amount and fair GBP value at receipt;
- stated purpose, where supplied;
- project expenditure and later disposals.

Support may have tax consequences. It is not automatically a charitable donation, and the project does not issue charitable tax receipts unless a qualifying legal entity is established separately.

## No private-key requests

No legitimate maintainer, contributor, funding page, or support channel will ask for a seed phrase, private key, wallet backup, or remote access to a contributor's wallet.
