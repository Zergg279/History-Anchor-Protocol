from __future__ import annotations

from copy import deepcopy
from typing import Any

from .batches import validate_batch
from .codec import canonical_json_bytes, sha256_hex
from .records import validate_record

PACKAGE_SCHEMA = "hap.package"
PACKAGE_VERSION = 1
PACKAGE_FIELDS = {"schema", "version", "batch", "records", "package_id"}


class PackageValidationError(ValueError):
    pass


def package_body(package: dict[str, Any]) -> dict[str, Any]:
    body = deepcopy(package)
    body.pop("package_id", None)
    return body


def calculate_package_id(package: dict[str, Any]) -> str:
    return sha256_hex(canonical_json_bytes(package_body(package)))


def create_package(
    batch: dict[str, Any], records: list[dict[str, Any]]
) -> dict[str, Any]:
    by_id = {record["record_id"]: record for record in records}
    ordered = [by_id[record_id] for record_id in batch["record_ids"]]
    package: dict[str, Any] = {
        "schema": PACKAGE_SCHEMA,
        "version": PACKAGE_VERSION,
        "batch": batch,
        "records": ordered,
    }
    package["package_id"] = calculate_package_id(package)
    validate_package(package)
    return package


def validate_package(package: dict[str, Any]) -> None:
    if not isinstance(package, dict) or set(package) != PACKAGE_FIELDS:
        raise PackageValidationError("package fields do not match the versioned schema")
    if (
        package.get("schema") != PACKAGE_SCHEMA
        or package.get("version") != PACKAGE_VERSION
    ):
        raise PackageValidationError("unsupported package schema or version")
    batch = package.get("batch")
    if not isinstance(batch, dict):
        raise PackageValidationError("package batch is required")
    validate_batch(batch)
    records = package.get("records")
    if not isinstance(records, list) or not records:
        raise PackageValidationError("package records must be a non-empty list")
    if len(records) != batch["record_count"]:
        raise PackageValidationError("package record count does not match batch")
    ids: list[str] = []
    seen: set[str] = set()
    for record in records:
        validate_record(record)
        record_id = record["record_id"]
        if record_id in seen:
            raise PackageValidationError("package contains a duplicate record")
        seen.add(record_id)
        ids.append(record_id)
    if ids != batch["record_ids"]:
        raise PackageValidationError(
            "package records are not in the exact committed batch order"
        )
    if calculate_package_id(package) != package.get("package_id"):
        raise PackageValidationError("package_id does not match package contents")
