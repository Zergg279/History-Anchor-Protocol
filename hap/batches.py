from __future__ import annotations

from copy import deepcopy
from typing import Any

from .bitcoin import (
    COMMITMENT_TYPE_BATCH_MANIFEST,
    decode_anchor_payload,
    encode_anchor_payload,
)
from .codec import canonical_json_bytes, sha256_hex
from .merkle import merkle_root

BATCH_SCHEMA = "hap.batch"
BATCH_VERSION = 3
ORDERING_RULE = "record_id_lexicographic_v1"
ALLOWED_NETWORKS = {"mainnet", "signet", "regtest"}
MAX_BATCH_RECORDS = 50_000
BATCH_FIELDS = {
    "schema",
    "version",
    "created_at",
    "network",
    "record_count",
    "record_ordering",
    "record_ids",
    "merkle_root",
    "algorithms",
    "batch_id",
    "payload_hex",
}


class BatchValidationError(ValueError):
    pass


def manifest_body(batch: dict[str, Any]) -> dict[str, Any]:
    body = deepcopy(batch)
    body.pop("batch_id", None)
    body.pop("payload_hex", None)
    return body


def calculate_batch_id(batch: dict[str, Any]) -> str:
    return sha256_hex(canonical_json_bytes(manifest_body(batch)))


def _validate_digest(value: Any, field: str) -> str:
    if not isinstance(value, str) or len(value) != 64:
        raise BatchValidationError(f"{field} must be a 32-byte hexadecimal digest")
    try:
        raw = bytes.fromhex(value)
    except ValueError as exc:
        raise BatchValidationError(f"{field} must be hexadecimal") from exc
    if len(raw) != 32:
        raise BatchValidationError(f"{field} must be a 32-byte hexadecimal digest")
    return value


def create_batch_manifest(
    *, record_ids: list[str], network: str, created_at: int
) -> dict[str, Any]:
    if not record_ids:
        raise BatchValidationError("a batch requires at least one record")
    ordered = sorted(record_ids)
    root = merkle_root(ordered)
    batch: dict[str, Any] = {
        "schema": BATCH_SCHEMA,
        "version": BATCH_VERSION,
        "created_at": created_at,
        "network": network,
        "record_count": len(ordered),
        "record_ordering": ORDERING_RULE,
        "record_ids": ordered,
        "merkle_root": root,
        "algorithms": {
            "record_id": "sha256",
            "batch_id": "sha256",
            "merkle_parent": "sha256(left||right)",
            "canonical_json": "hap-canonical-json-v1",
        },
    }
    batch["batch_id"] = calculate_batch_id(batch)
    batch["payload_hex"] = encode_anchor_payload(manifest_hash=batch["batch_id"])
    validate_batch(batch)
    return batch


def validate_batch(batch: dict[str, Any]) -> None:
    if not isinstance(batch, dict) or set(batch) != BATCH_FIELDS:
        raise BatchValidationError("batch fields do not match the versioned schema")
    if batch.get("schema") != BATCH_SCHEMA or batch.get("version") != BATCH_VERSION:
        raise BatchValidationError("unsupported batch schema or version")
    if batch.get("record_ordering") != ORDERING_RULE:
        raise BatchValidationError("unsupported record ordering rule")
    if batch.get("network") not in ALLOWED_NETWORKS:
        raise BatchValidationError("unsupported Bitcoin network")
    if (
        not isinstance(batch.get("created_at"), int)
        or isinstance(batch.get("created_at"), bool)
        or batch["created_at"] < 0
    ):
        raise BatchValidationError("created_at must be a non-negative integer")
    record_ids = batch.get("record_ids")
    if not isinstance(record_ids, list) or not record_ids:
        raise BatchValidationError("record_ids must be a non-empty list")
    if len(record_ids) > MAX_BATCH_RECORDS:
        raise BatchValidationError(
            f"a batch may contain at most {MAX_BATCH_RECORDS} records"
        )
    for item in record_ids:
        _validate_digest(item, "record_id")
    if record_ids != sorted(record_ids):
        raise BatchValidationError(
            "record_ids are not in canonical lexicographic order"
        )
    if len(set(record_ids)) != len(record_ids):
        raise BatchValidationError("duplicate record_ids are not allowed in a batch")
    if batch.get("record_count") != len(record_ids):
        raise BatchValidationError("record_count does not match record_ids")
    if batch.get("merkle_root") != merkle_root(record_ids):
        raise BatchValidationError("merkle_root does not match record_ids")
    expected_algorithms = {
        "record_id": "sha256",
        "batch_id": "sha256",
        "merkle_parent": "sha256(left||right)",
        "canonical_json": "hap-canonical-json-v1",
    }
    if batch.get("algorithms") != expected_algorithms:
        raise BatchValidationError("unsupported algorithm declaration")
    batch_id = _validate_digest(batch.get("batch_id"), "batch_id")
    if calculate_batch_id(batch) != batch_id:
        raise BatchValidationError("batch_id does not match canonical manifest")
    try:
        payload = decode_anchor_payload(batch.get("payload_hex", ""))
    except Exception as exc:
        raise BatchValidationError(f"invalid anchor payload: {exc}") from exc
    if payload.commitment_type != COMMITMENT_TYPE_BATCH_MANIFEST:
        raise BatchValidationError("unsupported commitment type")
    if payload.manifest_hash != batch_id:
        raise BatchValidationError("anchor payload does not commit to batch_id")
