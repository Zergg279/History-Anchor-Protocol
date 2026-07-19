#!/usr/bin/env sh
set -eu
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
DEST="${1:-./backups/$STAMP}"
mkdir -p "$DEST"
docker compose -f docker-compose.production.yml exec -T hap \
  sh -lc 'hap survival-export --data-dir /data --out /data/hap-survival.tar.gz'
docker compose -f docker-compose.production.yml cp hap:/data/hap-survival.tar.gz "$DEST/hap-survival.tar.gz"
sha256sum "$DEST/hap-survival.tar.gz" > "$DEST/SHA256SUMS"
echo "Survival archive written to $DEST"
