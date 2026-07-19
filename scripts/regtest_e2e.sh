#!/usr/bin/env bash
set -euo pipefail

for command in bitcoind bitcoin-cli hap curl python; do
  command -v "$command" >/dev/null || { echo "Missing required command: $command" >&2; exit 1; }
done

ROOT=$(mktemp -d)
BTC_DIR="$ROOT/bitcoin"
HAP_DIR="$ROOT/hap"
CLIENT_DIR="$ROOT/client"
mkdir -p "$BTC_DIR" "$HAP_DIR" "$CLIENT_DIR"
RPC_PORT=19443
P2P_PORT=19444
HAP_PORT=18440
HAP_PID=""

cleanup() {
  [[ -n "$HAP_PID" ]] && kill "$HAP_PID" 2>/dev/null || true
  bitcoin-cli -regtest -datadir="$BTC_DIR" -rpcport="$RPC_PORT" stop >/dev/null 2>&1 || true
  rm -rf "$ROOT"
}
trap cleanup EXIT

bitcoind \
  -regtest -datadir="$BTC_DIR" -server=1 -daemonwait \
  -rpcport="$RPC_PORT" -port="$P2P_PORT" -fallbackfee=0.0002 -txindex=1

bitcoin-cli -regtest -datadir="$BTC_DIR" -rpcport="$RPC_PORT" createwallet hap-regtest >/dev/null
ADDR=$(bitcoin-cli -regtest -datadir="$BTC_DIR" -rpcport="$RPC_PORT" -rpcwallet=hap-regtest getnewaddress)
bitcoin-cli -regtest -datadir="$BTC_DIR" -rpcport="$RPC_PORT" generatetoaddress 101 "$ADDR" >/dev/null

export HAP_BITCOIN_RPC_URL="http://127.0.0.1:$RPC_PORT"
export HAP_BITCOIN_COOKIE_FILE="$BTC_DIR/regtest/.cookie"
export HAP_BITCOIN_RPC_WALLET=hap-regtest
export HAP_MAX_ANCHOR_FEE_BTC=0.001
export HAP_TEST_WALLET_PASSWORD='regtest-only-password'
export HAP_ADMIN_CLIENT_TOKEN='regtest-admin-token'
export HAP_ADMIN_TOKEN="$HAP_ADMIN_CLIENT_TOKEN"

hap serve --role coordinator --node-name regtest-e2e \
  --data-dir "$HAP_DIR" --host 127.0.0.1 --port "$HAP_PORT" \
  >"$ROOT/hap.log" 2>&1 &
HAP_PID=$!
for _ in $(seq 1 60); do
  curl -fsS "http://127.0.0.1:$HAP_PORT/healthz" >/dev/null 2>&1 && break
  sleep 0.25
done
curl -fsS "http://127.0.0.1:$HAP_PORT/readyz" >/dev/null

hap keygen --out "$CLIENT_DIR/wallet.json" --password-env HAP_TEST_WALLET_PASSWORD
hap --url "http://127.0.0.1:$HAP_PORT" create \
  --wallet "$CLIENT_DIR/wallet.json" --password-env HAP_TEST_WALLET_PASSWORD \
  --title "HAP regtest end-to-end proof" --event-time "2026-07-19" \
  --statement "This lifecycle proves local signing, batching, Bitcoin anchoring, verification, backup, and recovery." \
  --source "https://example.org/hap-regtest" --out "$CLIENT_DIR/record.json" >/dev/null

hap --url "http://127.0.0.1:$HAP_PORT" --admin-token-env HAP_ADMIN_CLIENT_TOKEN \
  batch --network regtest >"$CLIENT_DIR/batch.json"
BATCH_ID=$(python -c 'import json,sys; print(json.load(open(sys.argv[1]))["batch_id"])' "$CLIENT_DIR/batch.json")
RECORD_ID=$(python -c 'import json,sys; print(json.load(open(sys.argv[1]))["record_id"])' "$CLIENT_DIR/record.json")

hap --url "http://127.0.0.1:$HAP_PORT" --admin-token-env HAP_ADMIN_CLIENT_TOKEN anchor "$BATCH_ID" >"$CLIENT_DIR/anchor.json"
bitcoin-cli -regtest -datadir="$BTC_DIR" -rpcport="$RPC_PORT" generatetoaddress 1 "$ADDR" >/dev/null
hap --url "http://127.0.0.1:$HAP_PORT" --admin-token-env HAP_ADMIN_CLIENT_TOKEN verify-anchor "$BATCH_ID" >"$CLIENT_DIR/anchor-verification.json"
hap --url "http://127.0.0.1:$HAP_PORT" proof-bundle "$RECORD_ID" --out "$CLIENT_DIR/proof.json" >/dev/null
hap verify "$CLIENT_DIR/proof.json" >"$CLIENT_DIR/structure-verification.json"
hap verify-bitcoin "$CLIENT_DIR/proof.json" >"$CLIENT_DIR/bitcoin-verification.json"

# Prove Bitcoin-first discovery from a blank node: no HAP database or peer state is trusted.
DISCOVERY_DIR="$CLIENT_DIR/discovered"
hap scan-bitcoin --data-dir "$DISCOVERY_DIR" --start-height 0 --max-blocks 1000 >"$CLIENT_DIR/scan.json"
hap resolve --data-dir "$DISCOVERY_DIR" --peers "http://127.0.0.1:$HAP_PORT" >"$CLIENT_DIR/resolve.json"
hap check --data-dir "$DISCOVERY_DIR" >"$CLIENT_DIR/discovered-check.json"
hap backup --data-dir "$HAP_DIR" --out-dir "$CLIENT_DIR/backup" >"$CLIENT_DIR/backup.json"
SNAPSHOT=$(find "$CLIENT_DIR/backup" -name 'hap-snapshot-*.json' -print -quit)
hap import "$SNAPSHOT" --data-dir "$CLIENT_DIR/restored" >"$CLIENT_DIR/recovery.json"

python - <<PY
import json
from pathlib import Path
root=Path("$CLIENT_DIR")
anchor=json.loads((root/'anchor-verification.json').read_text())
bitcoin=json.loads((root/'bitcoin-verification.json').read_text())
recovery=json.loads((root/'recovery.json').read_text())
discovered=json.loads((root/'discovered-check.json').read_text())
resolve=json.loads((root/'resolve.json').read_text())
assert anchor['verified'] is True
assert anchor['confirmations'] >= 1
assert bitcoin['any_bitcoin_anchor_verified'] is True
assert resolve['resolved'] == 1
assert discovered['counts']['records'] == 1
assert discovered['counts']['bitcoin_commitments'] >= 1
assert recovery['counts']['records'] == 1
assert recovery['counts']['batches'] == 1
assert recovery['counts']['anchors'] == 1
print('HAP Bitcoin Core regtest end-to-end lifecycle passed')
PY
