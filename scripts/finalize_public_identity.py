#!/usr/bin/env python3
"""Insert the public founder pseudonym and genesis Bitcoin address locally.

This script intentionally does not collect, transmit, or persist a legal identity.
It edits only public release files in the current repository and creates a
content-derived funding manifest for the official source release.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path

FOUNDER_MARKER = "{{HAP_FOUNDER_PSEUDONYM}}"
ADDRESS_MARKER = "{{HAP_GENESIS_BITCOIN_ADDRESS}}"
MANIFEST_ID_MARKER = "{{HAP_FUNDING_MANIFEST_ID}}"
TARGETS = (
    Path("AUTHORS.md"),
    Path("GENESIS_STATEMENT.md"),
    Path("FUNDING.md"),
    Path("hap/funding.py"),
)
MANIFEST_PATH = Path("FUNDING_MANIFEST.json")

BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
BECH32_INDEX = {character: index for index, character in enumerate(BECH32_CHARSET)}
BECH32_CONST = 1
BECH32M_CONST = 0x2BC830A3


def validate_pseudonym(value: str) -> str:
    if any(character in value for character in ("\n", "\r", "\t")):
        raise ValueError("pseudonym contains an unsafe control character")
    pseudonym = value.strip()
    if not 2 <= len(pseudonym) <= 80:
        raise ValueError("pseudonym must contain between 2 and 80 characters")
    if any(character in pseudonym for character in ("@", "<", ">")):
        raise ValueError("pseudonym contains an unsafe or identity-linking character")
    if not re.search(r"[A-Za-z0-9]", pseudonym):
        raise ValueError("pseudonym must contain at least one letter or number")
    return pseudonym


def _bech32_polymod(values: list[int]) -> int:
    generators = (0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3)
    checksum = 1
    for value in values:
        top = checksum >> 25
        checksum = ((checksum & 0x1FFFFFF) << 5) ^ value
        for bit, generator in enumerate(generators):
            if (top >> bit) & 1:
                checksum ^= generator
    return checksum


def _bech32_hrp_expand(hrp: str) -> list[int]:
    return (
        [ord(character) >> 5 for character in hrp]
        + [0]
        + [ord(character) & 31 for character in hrp]
    )


def _convert_bits(
    values: list[int], from_bits: int, to_bits: int, *, pad: bool
) -> list[int] | None:
    accumulator = 0
    bits = 0
    result: list[int] = []
    max_value = (1 << to_bits) - 1
    max_accumulator = (1 << (from_bits + to_bits - 1)) - 1
    for value in values:
        if value < 0 or value >> from_bits:
            return None
        accumulator = ((accumulator << from_bits) | value) & max_accumulator
        bits += from_bits
        while bits >= to_bits:
            bits -= to_bits
            result.append((accumulator >> bits) & max_value)
    if pad:
        if bits:
            result.append((accumulator << (to_bits - bits)) & max_value)
    elif bits >= from_bits or ((accumulator << (to_bits - bits)) & max_value):
        return None
    return result


def validate_bitcoin_address(value: str) -> str:
    address = value.strip()
    if any(character in address for character in ("\n", "\r", "\t", " ")):
        raise ValueError("Bitcoin address contains whitespace or a control character")
    if not 14 <= len(address) <= 90:
        raise ValueError("Bitcoin address length is invalid")
    if address.lower() != address and address.upper() != address:
        raise ValueError("Bech32 address must not mix uppercase and lowercase")

    normalised = address.lower()
    separator = normalised.rfind("1")
    if separator < 1 or separator + 7 > len(normalised):
        raise ValueError("Bitcoin address is not valid Bech32/Bech32m")
    hrp = normalised[:separator]
    if hrp != "bc":
        raise ValueError("use a Bitcoin mainnet native-SegWit address beginning bc1")

    try:
        data = [BECH32_INDEX[character] for character in normalised[separator + 1 :]]
    except KeyError as exc:
        raise ValueError(
            "Bitcoin address contains an invalid Bech32 character"
        ) from exc

    checksum = _bech32_polymod(_bech32_hrp_expand(hrp) + data)
    if checksum == BECH32_CONST:
        encoding = "bech32"
    elif checksum == BECH32M_CONST:
        encoding = "bech32m"
    else:
        raise ValueError("Bitcoin address checksum is invalid")

    payload = data[:-6]
    if not payload:
        raise ValueError("Bitcoin address has no witness version")
    witness_version = payload[0]
    if witness_version > 16:
        raise ValueError("Bitcoin witness version is invalid")
    witness_program = _convert_bits(payload[1:], 5, 8, pad=False)
    if witness_program is None or not 2 <= len(witness_program) <= 40:
        raise ValueError("Bitcoin witness program is invalid")
    if witness_version == 0:
        if encoding != "bech32" or len(witness_program) not in (20, 32):
            raise ValueError(
                "version-0 address must use Bech32 and a 20/32-byte program"
            )
    elif encoding != "bech32m":
        raise ValueError("version-1+ address must use Bech32m")
    return normalised


def canonical_manifest(bitcoin_address: str) -> dict[str, object]:
    return {
        "schema": "hap.funding",
        "version": 1,
        "release_version": "1.0.0",
        "bitcoin_network": "mainnet",
        "genesis_donation_address": bitcoin_address,
        "purpose": "voluntary support for open-source HAP development",
        "consensus_effect": False,
        "governance_rights": False,
        "protocol_dependency": False,
    }


def manifest_id(manifest: dict[str, object]) -> str:
    encoded = json.dumps(
        manifest,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def replace_markers(root: Path, pseudonym: str, bitcoin_address: str) -> list[Path]:
    changed: list[Path] = []
    for relative_path in TARGETS:
        path = root / relative_path
        if not path.is_file():
            raise FileNotFoundError(
                f"required release file is missing: {relative_path}"
            )
        original = path.read_text(encoding="utf-8")
        updated = original.replace(FOUNDER_MARKER, pseudonym).replace(
            ADDRESS_MARKER, bitcoin_address
        )
        if updated != original:
            path.write_text(updated, encoding="utf-8", newline="\n")
            changed.append(relative_path)

    manifest = canonical_manifest(bitcoin_address)
    identifier = manifest_id(manifest)
    manifest_value = dict(manifest)
    manifest_value["manifest_id"] = identifier
    manifest_path = root / MANIFEST_PATH
    manifest_path.write_text(
        json.dumps(manifest_value, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    changed.append(MANIFEST_PATH)

    for relative_path in (Path("GENESIS_STATEMENT.md"), Path("FUNDING.md")):
        path = root / relative_path
        original = path.read_text(encoding="utf-8")
        updated = original.replace(MANIFEST_ID_MARKER, identifier)
        if updated != original:
            path.write_text(updated, encoding="utf-8", newline="\n")
            if relative_path not in changed:
                changed.append(relative_path)
    return changed


def remaining_markers(root: Path) -> list[Path]:
    remaining: list[Path] = []
    markers = (FOUNDER_MARKER, ADDRESS_MARKER, MANIFEST_ID_MARKER)
    for relative_path in TARGETS + (Path("FUNDING.md"), Path("GENESIS_STATEMENT.md")):
        text = (root / relative_path).read_text(encoding="utf-8")
        if any(marker in text for marker in markers):
            remaining.append(relative_path)
    return sorted(set(remaining))


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Finalise HAP's public pseudonym and signed-release Bitcoin address "
            "without transmitting either value."
        )
    )
    parser.add_argument(
        "--pseudonym", required=True, help="stable public founder pseudonym"
    )
    parser.add_argument(
        "--bitcoin-address",
        required=True,
        help="fresh project-only Bitcoin mainnet native-SegWit address (bc1...)",
    )
    parser.add_argument(
        "--root",
        type=Path,
        default=Path.cwd(),
        help="repository root (defaults to the current directory)",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    root = args.root.resolve()
    try:
        pseudonym = validate_pseudonym(args.pseudonym)
        bitcoin_address = validate_bitcoin_address(args.bitcoin_address)
        changed = replace_markers(root, pseudonym, bitcoin_address)
        remaining = remaining_markers(root)
    except (ValueError, FileNotFoundError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    if remaining:
        print("error: unresolved publication markers remain:", file=sys.stderr)
        for path in remaining:
            print(f"  - {path}", file=sys.stderr)
        return 3

    print("Public pseudonym and genesis funding configuration finalised locally.")
    for path in changed:
        print(f"  updated: {path}")
    print(
        "\nReview the diff, sign GENESIS_STATEMENT.md with a dedicated release key, "
        "commit, recreate v1.0.0, and rebuild the official assets."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
