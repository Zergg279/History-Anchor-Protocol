#!/usr/bin/env bash
set -euo pipefail
if ! python -c 'import pip_audit' >/dev/null 2>&1; then
  echo 'pip-audit is not installed. Install it on a networked release machine, then rerun this script.' >&2
  exit 2
fi
python -m pip_audit -r requirements.lock --no-deps --disable-pip --progress-spinner off
