#!/usr/bin/env bash
set -euo pipefail

for command in python curl; do
  command -v "$command" >/dev/null || { echo "Missing required command: $command" >&2; exit 1; }
done

ROOT=$(mktemp -d)
RELAY_PID=""
COORD_PID=""
cleanup() {
  [[ -n "$RELAY_PID" ]] && kill "$RELAY_PID" 2>/dev/null || true
  [[ -n "$COORD_PID" ]] && kill "$COORD_PID" 2>/dev/null || true
  wait "$RELAY_PID" "$COORD_PID" 2>/dev/null || true
  rm -rf "$ROOT"
}
trap cleanup EXIT

export PYTHONPATH="${PYTHONPATH:-}:$(pwd)"
export HAP_TEST_WALLET_PASSWORD='private-live-smoke-password'
export HAP_STAGE_TOKEN='private-stage-token'
export HAP_ADMIN_CLIENT_TOKEN='private-admin-token'

HAP_SUBMISSION_TOKENS="$HAP_STAGE_TOKEN" \
python -m hap.cli serve \
  --data-dir "$ROOT/relay" --host 127.0.0.1 --port 18401 \
  --role relay --node-name smoke-relay --require-submission-token \
  >"$ROOT/relay.log" 2>&1 &
RELAY_PID=$!

HAP_ADMIN_TOKEN="$HAP_ADMIN_CLIENT_TOKEN" HAP_SUBMISSION_TOKENS="$HAP_STAGE_TOKEN" \
python -m hap.cli serve \
  --data-dir "$ROOT/coordinator" --host 127.0.0.1 --port 18402 \
  --role coordinator --node-name smoke-coordinator --require-submission-token \
  --peers http://127.0.0.1:18401 --sync-interval 1 \
  >"$ROOT/coordinator.log" 2>&1 &
COORD_PID=$!

for port in 18401 18402; do
  for _ in $(seq 1 60); do
    curl -fsS "http://127.0.0.1:$port/healthz" >/dev/null 2>&1 && break
    sleep 0.1
  done
  curl -fsS "http://127.0.0.1:$port/readyz" >/dev/null
done

python -m hap.cli keygen --out "$ROOT/wallet.json" --password-env HAP_TEST_WALLET_PASSWORD >/dev/null
python -m hap.cli \
  --url http://127.0.0.1:18401 \
  --submission-token-env HAP_STAGE_TOKEN \
  create \
  --wallet "$ROOT/wallet.json" --password-env HAP_TEST_WALLET_PASSWORD \
  --title 'Private live deployment smoke record' \
  --statement 'This record crossed a token-gated relay and synchronised to an independent coordinator.' \
  --event-time '2026-07-19' --out "$ROOT/record.json" >/dev/null

RECORD_ID=$(python -c 'import json,sys; print(json.load(open(sys.argv[1]))["record_id"])' "$ROOT/record.json")
for _ in $(seq 1 60); do
  curl -fsS "http://127.0.0.1:18402/v1/records/$RECORD_ID" >/dev/null 2>&1 && break
  sleep 0.2
done
curl -fsS "http://127.0.0.1:18402/v1/records/$RECORD_ID" >/dev/null

python -m hap.cli \
  --url http://127.0.0.1:18402 \
  --admin-token-env HAP_ADMIN_CLIENT_TOKEN \
  batch --network signet >"$ROOT/batch.json"

python -m hap.cli --url http://127.0.0.1:18402 \
  proof-bundle "$RECORD_ID" --out "$ROOT/proof.json" >/dev/null
python -m hap.cli verify "$ROOT/proof.json" >"$ROOT/verify.json"

python - <<PY
import json
value=json.load(open("$ROOT/verify.json"))
assert value["record_valid"] is True
assert value["all_proofs_valid"] is True
print("Relay → peer sync → coordinator → batch → proof lifecycle passed")
PY
