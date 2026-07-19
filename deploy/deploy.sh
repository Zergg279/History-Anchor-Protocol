#!/usr/bin/env sh
set -eu
[ -f .env ] || { echo "Copy deploy/.env.production.example to .env and configure it" >&2; exit 1; }
[ -s deploy/secrets/admin_token ] || { echo "Missing deploy/secrets/admin_token" >&2; exit 1; }
[ -s deploy/secrets/submission_tokens ] || { echo "Missing deploy/secrets/submission_tokens" >&2; exit 1; }
[ -s deploy/secrets/bitcoin_rpc_password ] || { echo "Missing deploy/secrets/bitcoin_rpc_password" >&2; exit 1; }
docker compose -f docker-compose.production.yml config >/dev/null
docker compose -f docker-compose.production.yml build
docker compose -f docker-compose.production.yml up -d
docker compose -f docker-compose.production.yml ps
