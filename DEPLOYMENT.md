# Deployment

## Release posture

V1.0.0 is an official open-source protocol release. Default operation is Bitcoin signet with mainnet disabled. An operator must complete the included regtest and signet lifecycle before explicitly enabling irreversible mainnet publication.

No software can be guaranteed never to fail. Deployment safety comes from independent verification, backups, minimal wallet funding, staged activation, and external review.

## Requirements

- Linux server or ordinary desktop;
- Python 3.11–3.13 or Docker;
- Bitcoin Core on regtest, signet, or explicitly enabled mainnet;
- a dedicated minimally funded anchoring wallet;
- HTTPS reverse proxy before exposing the HTTP API publicly.

## Bitcoin Core

Example signet configuration:

```ini
signet=1
server=1
wallet=hap-anchor
```

Prefer cookie authentication or a restricted `rpcauth` user. Never expose Bitcoin RPC publicly.

## Activation height

A node scans Bitcoin from `HAP_BITCOIN_SCAN_START_HEIGHT`. Before any public mainnet use, publish a fixed activation height so nodes do not scan blocks that predate the protocol.

## Environment

```bash
HAP_DATA_DIR=/var/lib/hap
HAP_ROLE=coordinator
HAP_NODE_NAME=my-node
HAP_ADMIN_TOKEN_FILE=/run/secrets/hap_admin
HAP_REQUIRE_SUBMISSION_TOKEN=1
HAP_SUBMISSION_TOKENS_FILE=/run/secrets/submission_tokens
HAP_PEERS=https://peer-a.example,https://peer-b.example
HAP_MAX_BATCH_RECORDS=1000
HAP_MAX_PACKAGE_BYTES=67108864
HAP_BITCOIN_RPC_URL=http://127.0.0.1:38332
HAP_BITCOIN_COOKIE_FILE=/home/bitcoin/.bitcoin/signet/.cookie
HAP_BITCOIN_RPC_WALLET=hap-anchor
HAP_BITCOIN_EXPECTED_NETWORK=signet
HAP_BITCOIN_REQUIRED_FOR_READINESS=1
HAP_BITCOIN_SCAN_START_HEIGHT=0
HAP_BITCOIN_SCAN_INTERVAL_SECONDS=60
HAP_RESOLVE_INTERVAL_SECONDS=60
HAP_SERVE_EVIDENCE=0
HAP_ALLOW_MAINNET=0
HAP_RESPONSIBLE_PUBLICATION_PROFILE=1
HAP_RESPONSIBLE_COOLING_BLOCKS=6
HAP_RECOGNISED_ACCOUNTABLE_AUTHORS=
```

The recognised-author list is a disclosed local client trust store for `view_decision` records. It is not a protocol whitelist. Leaving it empty means person-impact records remain protected in the reference feed.

## Docker deployment

```bash
cp deploy/.env.production.example .env
mkdir -p deploy/secrets
openssl rand -hex 32 > deploy/secrets/admin_token
openssl rand -hex 32 > deploy/secrets/submission_tokens
openssl rand -hex 32 > deploy/secrets/bitcoin_rpc_password
chmod 600 deploy/secrets/*
./deploy/deploy.sh
```

The compose service binds only to `127.0.0.1:8339`. Put a maintained HTTPS reverse proxy in front of it and keep administrative endpoints inaccessible from the public internet where possible.

## One-node genesis

One node can start the network. New nodes bootstrap from any peer or survival archive, verify all packages against Bitcoin, and become alternative peers. Once independent complete peers exist, the original node is not required.

A bootstrap address cannot make an invalid package pass validation or create a Bitcoin publication.

## Public interface boundary

Use `/v1/feed` for the responsible reference feed and exact-ID `/v1/records/<id>` views for context-complete inspection. `/v1/records` exposes raw protocol objects for synchronisation and independent clients; it is not a responsible editorial feed.

## Mainnet gate

Mainnet requires all of:

- `HAP_ALLOW_MAINNET=1`;
- `HAP_BITCOIN_EXPECTED_NETWORK=mainnet`;
- a published activation height;
- a dedicated minimally funded wallet;
- an explicit `HAP_MAX_ANCHOR_FEE_BTC`;
- completed regtest and signet lifecycle;
- tested backup, destruction, and recovery;
- external security and legal review for any public service.

Bitcoin publication is irreversible. HAP cannot undo accidental on-chain commitments or recall off-protocol copies.
