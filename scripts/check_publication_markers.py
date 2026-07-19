#!/usr/bin/env python3
"""Fail when publication placeholders or funding-manifest inconsistencies remain."""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from hap.funding import canonical_funding_manifest, funding_manifest_id  # noqa: E402

MARKERS = (
    "{{HAP_FOUNDER_PSEUDONYM}}",
    "{{HAP_GENESIS_BITCOIN_ADDRESS}}",
    "{{HAP_FUNDING_MANIFEST_ID}}",
)
TARGETS = (
    Path("AUTHORS.md"),
    Path("GENESIS_STATEMENT.md"),
    Path("FUNDING.md"),
    Path("hap/funding.py"),
)
MANIFEST_PATH = Path("FUNDING_MANIFEST.json")


def main() -> int:
    failures: list[str] = []
    for path in TARGETS:
        if not path.is_file():
            failures.append(f"missing: {path}")
            continue
        text = path.read_text(encoding="utf-8")
        for marker in MARKERS:
            if marker in text:
                failures.append(f"unresolved marker {marker} in {path}")

    if not MANIFEST_PATH.is_file():
        failures.append(f"missing: {MANIFEST_PATH}")
    else:
        try:
            stored = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            failures.append(f"invalid {MANIFEST_PATH}: {exc}")
        else:
            expected = canonical_funding_manifest()
            expected_id = funding_manifest_id()
            if stored.get("manifest_id") != expected_id:
                failures.append("funding manifest identifier does not match source")
            without_id = dict(stored)
            without_id.pop("manifest_id", None)
            if without_id != expected:
                failures.append("funding manifest content does not match source")

    if failures:
        print(
            "Publication identity/funding configuration is not finalised:",
            file=sys.stderr,
        )
        for failure in failures:
            print(f"  - {failure}", file=sys.stderr)
        return 1
    print("Publication identity and signed-release funding manifest are finalised.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
