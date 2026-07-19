from __future__ import annotations

from copy import deepcopy
from typing import Any

from .anchors import validate_anchor_reference
from .batches import validate_batch
from .codec import canonical_json_bytes, sha256_hex
from .records import validate_record

SNAPSHOT_SCHEMA = "hap.snapshot"
SNAPSHOT_VERSION = 1
SNAPSHOT_FIELDS = {
    "schema",
    "version",
    "created_at",
    "records",
    "batches",
    "anchors",
    "snapshot_id",
}


class SnapshotValidationError(ValueError):
    pass


def snapshot_body(snapshot: dict[str, Any]) -> dict[str, Any]:
    body = deepcopy(snapshot)
    body.pop("snapshot_id", None)
    return body


def calculate_snapshot_id(snapshot: dict[str, Any]) -> str:
    return sha256_hex(canonical_json_bytes(snapshot_body(snapshot)))


def validate_snapshot(snapshot: dict[str, Any]) -> None:
    if not isinstance(snapshot, dict) or set(snapshot) != SNAPSHOT_FIELDS:
        raise SnapshotValidationError(
            "snapshot fields do not match the versioned schema"
        )
    if (
        snapshot.get("schema") != SNAPSHOT_SCHEMA
        or snapshot.get("version") != SNAPSHOT_VERSION
    ):
        raise SnapshotValidationError("unsupported snapshot schema or version")
    created_at = snapshot.get("created_at")
    if (
        not isinstance(created_at, int)
        or isinstance(created_at, bool)
        or created_at < 0
    ):
        raise SnapshotValidationError(
            "snapshot created_at must be a non-negative integer"
        )
    for field in ("records", "batches", "anchors"):
        if not isinstance(snapshot.get(field), list):
            raise SnapshotValidationError(f"{field} must be a list")
    if calculate_snapshot_id(snapshot) != snapshot.get("snapshot_id"):
        raise SnapshotValidationError("snapshot_id does not match snapshot contents")

    record_ids: set[str] = set()
    for record in snapshot["records"]:
        validate_record(record)
        if record["record_id"] in record_ids:
            raise SnapshotValidationError("snapshot contains a duplicate record")
        record_ids.add(record["record_id"])
    for record in snapshot["records"]:
        target = record.get("target_record_id")
        if target and target not in record_ids:
            raise SnapshotValidationError(f"snapshot is missing target record {target}")

    batch_ids: set[str] = set()
    for batch in snapshot["batches"]:
        validate_batch(batch)
        if batch["batch_id"] in batch_ids:
            raise SnapshotValidationError("snapshot contains a duplicate batch")
        if any(record_id not in record_ids for record_id in batch["record_ids"]):
            raise SnapshotValidationError(
                "batch references a record missing from the snapshot"
            )
        batch_ids.add(batch["batch_id"])

    anchor_points: set[tuple[str, int]] = set()
    for anchor in snapshot["anchors"]:
        validate_anchor_reference(anchor)
        point = (anchor["txid"], anchor["vout"])
        if point in anchor_points:
            raise SnapshotValidationError("snapshot contains a duplicate anchor output")
        if anchor["batch_id"] not in batch_ids:
            raise SnapshotValidationError(
                "anchor references a batch missing from the snapshot"
            )
        anchor_points.add(point)
