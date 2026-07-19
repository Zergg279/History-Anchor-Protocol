from __future__ import annotations

from typing import Any

ALLOWED_NETWORKS = {"mainnet", "signet", "regtest"}
ALLOWED_STATUSES = {"unverified", "broadcast", "confirmed", "reorganised", "invalid"}
ANCHOR_FIELDS = {
    "txid",
    "vout",
    "batch_id",
    "network",
    "status",
    "anchored_at",
    "block_hash",
    "block_height",
}


class AnchorValidationError(ValueError):
    pass


def _digest(value: Any, field: str) -> str:
    if not isinstance(value, str) or len(value) != 64:
        raise AnchorValidationError(f"{field} must be a 32-byte hexadecimal digest")
    try:
        raw = bytes.fromhex(value)
    except ValueError as exc:
        raise AnchorValidationError(f"{field} must be hexadecimal") from exc
    if len(raw) != 32:
        raise AnchorValidationError(f"{field} must be a 32-byte hexadecimal digest")
    return value


def validate_anchor_reference(anchor: dict[str, Any]) -> None:
    if not isinstance(anchor, dict) or set(anchor) != ANCHOR_FIELDS:
        raise AnchorValidationError("anchor fields do not match the versioned schema")
    _digest(anchor.get("txid"), "txid")
    vout = anchor.get("vout")
    if not isinstance(vout, int) or isinstance(vout, bool) or vout < 0:
        raise AnchorValidationError("vout must be a non-negative integer")
    _digest(anchor.get("batch_id"), "batch_id")
    if anchor.get("network") not in ALLOWED_NETWORKS:
        raise AnchorValidationError("unsupported anchor network")
    if anchor.get("status") not in ALLOWED_STATUSES:
        raise AnchorValidationError("unsupported anchor status")
    anchored_at = anchor.get("anchored_at")
    if (
        not isinstance(anchored_at, int)
        or isinstance(anchored_at, bool)
        or anchored_at < 0
    ):
        raise AnchorValidationError("anchored_at must be a non-negative integer")
    block_hash = anchor.get("block_hash")
    if block_hash is not None:
        _digest(block_hash, "block_hash")
    block_height = anchor.get("block_height")
    if block_height is not None and (
        not isinstance(block_height, int)
        or isinstance(block_height, bool)
        or block_height < 0
    ):
        raise AnchorValidationError(
            "block_height must be null or a non-negative integer"
        )
