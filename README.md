# History Anchor Protocol v1.0.0

**An ownerless, pseudonymous, Bitcoin-first memory protocol. MIT licensed. No token. No second blockchain. No required website.**

HAP lets anyone publish signed historical records whose canonical publication and ordering are defined by ordinary Bitcoin transactions.

```text
signed record + evidence fingerprints
                ↓
deterministic package / Merkle batch
                ↓
38-byte HIST commitment in Bitcoin OP_RETURN
                ↓
Bitcoin confirms publication and order
                ↓
independent HAP nodes scan Bitcoin, retrieve the package from any source,
validate it locally, preserve selected evidence, and re-serve it
```

Bitcoin is the only consensus and proof-of-work layer. HAP nodes do not mine blocks, issue a coin, vote on truth, or maintain a competing ledger.

## Protocol, not product

The reference web page is optional and replaceable. HAP is the public specification, Bitcoin commitments, portable signed packages, deterministic validation, peer transport, and independent archives.

Deleting every founder-operated website must not stop publication, verification, recovery, or independent implementation.

## What v1.0 implements

- local encrypted pseudonymous identities and Ed25519 signatures;
- direct one-record Bitcoin publication or optional permissionless batching;
- claims, attestations, disputes, corrections, subject responses, restrictions, adjudications, view decisions, and provenance assertions;
- exact evidence SHA-256 fingerprints and content-addressed local storage;
- deterministic Merkle batches and 38-byte Bitcoin commitments identified by `txid:vout`;
- package persistence before Bitcoin broadcast;
- Bitcoin Core block scanning and reorganisation handling;
- Bitcoin-first package discovery and independently validated peer exchange;
- minimal provenance graph separating protocol facts, signed declarations, and analytical overlays;
- optional responsible-publication reference profile with mosaic-person-impact protection, cooling periods, context-complete views, and no unilateral emergency bypass;
- observer, relay, coordinator, and archive node roles;
- bounded request, package, batch, evidence, and rate-limit policies;
- portable proofs, snapshots, and survival archives;
- one-node recovery: one complete lawful archive plus Bitcoin history can re-seed the surviving network;
- open protocol, MIT source, no founder master key, no required identity provider, and no required website.

## What “verified” means

HAP can prove reproducibly that:

- a particular key signed an exact record;
- exact evidence bytes match committed fingerprints;
- a batch contains that record;
- a matching commitment was confirmed in Bitcoin's active chain;
- signed supporting, opposing, corrective, contextual, or analytical records exist.

HAP does not determine arbitrary physical truth. Multiple keys are not assumed to be independent people. Source declarations are authenticated declarations, not automatically verified facts. Analytical overlays never become protocol truth through repetition.

## Responsible publication boundary

Base publication remains permissionless. The reference feed is separate and optional:

- it lists only Bitcoin-confirmed claims;
- claims with direct, mosaic, uncertain, or missing person-impact declarations begin protected;
- public-interest declarations have no automatic effect;
- subject responses and disputes remain equally prominent context but do not let burner keys suppress a record forever;
- anchored person-impact or restriction notices start one fixed non-renewable challenge window; persistent restriction or later enabling requires a locally recognised accountable decision;
- no unilateral emergency override exists;
- exact-ID access and linked context remain available.

The node exposes `/v1/view-manifest`, a content-derived disclosure of its profile, cooling periods, endpoints, and recognised accountable-author trust store.

This profile governs good-faith clients only. It cannot recall screenshots, force hostile mirrors to display context, or guarantee global erasure.

## Smallest useful deployment

One ordinary computer can bootstrap the network:

```text
Bitcoin Core + one HAP node + one data directory
```

That machine can publish, scan Bitcoin, verify packages, preserve selected evidence, and seed future nodes. One machine alone is not decentralisation; the protocol becomes decentralised as unrelated operators, archives, and implementations join.

## Install

Python 3.11–3.13:

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.lock
python -m pip install --no-deps .
```

Or with Docker:

```bash
cp .env.example .env
docker compose up -d --build
```

## Create a claim

The reference CLI conservatively defaults `--person-impact` to `uncertain`.

```bash
hap keygen --out identity.json

hap create \
  --wallet identity.json \
  --kind claim \
  --person-impact none \
  --title "A historical event" \
  --statement "A precise signed account." \
  --event-time "2026-07-19" \
  --evidence ./original-video.mp4 \
  --out record.json \
  --no-submit
```

Store the evidence locally by content address:

```bash
hap evidence-add ./original-video.mp4 --data-dir .history-anchor
```

## Publish directly through Bitcoin

This creates a one-record Merkle batch, writes its portable package before spending BTC, and broadcasts the 38-byte commitment:

```bash
hap direct-anchor record.json \
  --data-dir .history-anchor \
  --network signet \
  --package-out record-publication-package.json
```

For lower cost, submit records to any relay and let any coordinator batch them. A coordinator cannot invalidate direct publication.

## Discover from Bitcoin

```bash
hap scan-bitcoin --data-dir .history-anchor --start-height 0
hap resolve --data-dir .history-anchor \
  --peers https://peer-one.example,https://peer-two.example
```

Bitcoin decides which commitments exist. Packages from peers are rejected unless they exactly match the Bitcoin commitment.

## Run a node

```bash
export HAP_ADMIN_TOKEN='use-a-long-random-secret'
export HAP_BITCOIN_RPC_URL='http://127.0.0.1:38332'
export HAP_BITCOIN_COOKIE_FILE="$HOME/.bitcoin/signet/.cookie"
export HAP_BITCOIN_RPC_WALLET='hap-anchor'
export HAP_BITCOIN_EXPECTED_NETWORK='signet'

hap serve \
  --role coordinator \
  --data-dir .history-anchor \
  --peers https://another-node.example \
  --scan-interval 60 \
  --resolve-interval 60 \
  --serve-evidence
```

Mainnet is disabled by default. Commission the full lifecycle on regtest and signet before explicitly enabling mainnet.

## Preserve and recover

```bash
hap survival-export --data-dir .history-anchor --out hap-survival.tar.gz
hap survival-import hap-survival.tar.gz --data-dir restored-node
```

## Funding and founder attribution

HAP contains no founder fee, token, premine, mandatory donation, or protocol royalty. Voluntary Bitcoin support is external to protocol validity and grants no governance, truth, ranking, or publication privilege. See [FUNDING.md](FUNDING.md).

The v1.0.0 source release is attributed to **Horus**. Its fixed, project-only Bitcoin contribution address and content-derived funding manifest are included consistently in the source, CLI, node funding endpoint, funding document, and genesis statement. Run `hap funding` from a verified release to inspect them.

The address remains outside protocol validity: changing it produces a different fork and authenticated source artifact, not a different HAP consensus state. Never place a seed phrase, private key, wallet descriptor, extended public key, or legal-identity document in this repository.

The GitHub `v1.0.0` release tag was created through GitHub's website release flow and is not cryptographically signed. Horus may later publish a dedicated release-signing public key and detached signatures; such a key would authenticate future releases but could never become protocol authority.

## Core documents

- [CONSTITUTION.md](CONSTITUTION.md)
- [PROTOCOL.md](PROTOCOL.md)
- [FUNDING.md](FUNDING.md)
- [AUTHORS.md](AUTHORS.md)
- [GENESIS_STATEMENT.md](GENESIS_STATEMENT.md)
- [ARCHITECTURE.md](ARCHITECTURE.md)
- [TRUST_MODEL.md](TRUST_MODEL.md)
- [RESPONSIBLE_PUBLICATION.md](RESPONSIBLE_PUBLICATION.md)
- [PRIVACY_AND_ERASURE.md](PRIVACY_AND_ERASURE.md)
- [LEGAL_BOUNDARIES.md](LEGAL_BOUNDARIES.md)
- [GOVERNANCE.md](GOVERNANCE.md)
- [THREAT_MODEL.md](THREAT_MODEL.md)
- [DEPLOYMENT.md](DEPLOYMENT.md)
- [SECURITY.md](SECURITY.md)
- [FINAL_REVIEW.md](FINAL_REVIEW.md)
