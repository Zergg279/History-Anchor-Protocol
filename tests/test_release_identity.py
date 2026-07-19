from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "finalize_public_identity.py"
SPEC = importlib.util.spec_from_file_location("finalize_public_identity", SCRIPT)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)

VALID_ADDRESS = "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu"


def test_validate_pseudonym_accepts_stable_public_name() -> None:
    assert MODULE.validate_pseudonym("Permanent Witness") == "Permanent Witness"


@pytest.mark.parametrize("value", ["", "x", "name@example.com", "<script>", "\nname"])
def test_validate_pseudonym_rejects_unsafe_values(value: str) -> None:
    with pytest.raises(ValueError):
        MODULE.validate_pseudonym(value)


def test_validate_bitcoin_address_requires_valid_mainnet_native_segwit() -> None:
    assert MODULE.validate_bitcoin_address(VALID_ADDRESS) == VALID_ADDRESS
    with pytest.raises(ValueError):
        MODULE.validate_bitcoin_address("tb1qfm7h2v9n0invalid")
    with pytest.raises(ValueError):
        MODULE.validate_bitcoin_address(VALID_ADDRESS[:-1] + "x")
    with pytest.raises(ValueError):
        MODULE.validate_bitcoin_address("1BoatSLRHtKNngkdXEeobR76b53LETtpyT")


def test_finalizer_replaces_public_markers_and_creates_manifest(tmp_path: Path) -> None:
    for relative in MODULE.TARGETS:
        path = tmp_path / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            f"founder={MODULE.FOUNDER_MARKER}\naddress={MODULE.ADDRESS_MARKER}\n",
            encoding="utf-8",
        )

    for relative in (Path("GENESIS_STATEMENT.md"), Path("FUNDING.md")):
        path = tmp_path / relative
        current = path.read_text(encoding="utf-8") if path.exists() else ""
        path.write_text(
            current + f"manifest={MODULE.MANIFEST_ID_MARKER}\n",
            encoding="utf-8",
        )

    changed = MODULE.replace_markers(
        tmp_path,
        pseudonym="Permanent Witness",
        bitcoin_address=VALID_ADDRESS,
    )

    assert MODULE.MANIFEST_PATH in changed
    assert MODULE.remaining_markers(tmp_path) == []
    manifest = json.loads((tmp_path / MODULE.MANIFEST_PATH).read_text(encoding="utf-8"))
    identifier = manifest.pop("manifest_id")
    assert manifest == MODULE.canonical_manifest(VALID_ADDRESS)
    assert identifier == MODULE.manifest_id(manifest)
    for relative in MODULE.TARGETS:
        text = (tmp_path / relative).read_text(encoding="utf-8")
        assert "Permanent Witness" in text or relative == Path("hap/funding.py")
        assert VALID_ADDRESS in text
