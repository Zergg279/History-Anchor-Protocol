#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

python scripts/check_publication_markers.py
HAP_REQUIRE_PUBLIC_IDENTITY=1 ./scripts/build_release.sh
python scripts/package_public_release.py --version 1.0.0 --out-dir release-assets
