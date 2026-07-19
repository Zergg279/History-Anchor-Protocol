#!/usr/bin/env bash
set -euo pipefail
if [[ "${HAP_REQUIRE_PUBLIC_IDENTITY:-0}" == "1" ]]; then
  python scripts/check_publication_markers.py
fi
ruff format --check hap tests scripts
ruff check hap tests scripts
bandit -q -r hap -ll
python -m coverage erase
python -m coverage run -m pytest -q
python -m coverage report
./scripts/network_smoke.sh
python -m compileall -q hap scripts
bash -n scripts/*.sh start-mac-linux.sh
rm -rf dist build *.egg-info
python -m pip wheel --no-deps --no-build-isolation . -w dist
