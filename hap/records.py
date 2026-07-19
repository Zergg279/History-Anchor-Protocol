from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone
from typing import Any, Literal

from .codec import canonical_json_bytes, sha256_hex
from .crypto import derive_public_key, public_key_to_author_id, sign, verify

RecordKind = Literal[
    "claim",
    "attestation",
    "dispute",
    "correction",
    "subject_response",
    "person_impact_notice",
    "restriction_notice",
    "withdrawal_notice",
    "legal_adjudication",
    "public_interest_justification",
    "view_decision",
    "provenance_assertion",
]
TARGET_KINDS = {
    "attestation",
    "dispute",
    "correction",
    "subject_response",
    "person_impact_notice",
    "restriction_notice",
    "withdrawal_notice",
    "legal_adjudication",
    "public_interest_justification",
    "view_decision",
    "provenance_assertion",
}
ALLOWED_KINDS = {"claim", *TARGET_KINDS}
MAX_TITLE_CHARS = 240
MAX_STATEMENT_CHARS = 100_000
MAX_SOURCES = 32
MAX_EVIDENCE_ITEMS = 64
MAX_TAGS = 32
RECORD_FIELDS = {
    "schema",
    "version",
    "kind",
    "created_at",
    "event_time",
    "author_id",
    "author_public_key",
    "title",
    "statement",
    "target_record_id",
    "sources",
    "evidence",
    "tags",
    "signature",
    "record_id",
}
SOURCE_FIELDS = {"uri", "label"}
EVIDENCE_FIELDS = {"filename", "size", "mime_type", "sha256", "cid"}


class RecordValidationError(ValueError):
    pass


def utc_now_iso() -> str:
    return (
        datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def signing_body(record: dict[str, Any]) -> dict[str, Any]:
    body = deepcopy(record)
    body.pop("signature", None)
    body.pop("record_id", None)
    return body


def envelope_for_id(record: dict[str, Any]) -> dict[str, Any]:
    envelope = deepcopy(record)
    envelope.pop("record_id", None)
    return envelope


def calculate_record_id(record: dict[str, Any]) -> str:
    return sha256_hex(canonical_json_bytes(envelope_for_id(record)))


def _require_hex_digest(value: Any, field: str) -> str:
    if not isinstance(value, str) or len(value) != 64:
        raise RecordValidationError(f"{field} must be a 32-byte hexadecimal digest")
    try:
        raw = bytes.fromhex(value)
    except ValueError as exc:
        raise RecordValidationError(f"{field} must be hexadecimal") from exc
    if len(raw) != 32:
        raise RecordValidationError(f"{field} must be a 32-byte hexadecimal digest")
    return value


def _validate_created_at(value: str) -> None:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise RecordValidationError("created_at must be RFC 3339 / ISO 8601") from exc
    if parsed.tzinfo is None:
        raise RecordValidationError("created_at must include a timezone")


def normalize_list(value: Any, field: str) -> list[Any]:
    if value is None:
        return []
    if not isinstance(value, list):
        raise RecordValidationError(f"{field} must be a list")
    return value


def validate_record(record: dict[str, Any], *, verify_signature: bool = True) -> None:
    if not isinstance(record, dict) or set(record) != RECORD_FIELDS:
        raise RecordValidationError("record fields do not match the versioned schema")
    if record.get("schema") != "hap.record":
        raise RecordValidationError("unsupported record schema")
    if record.get("version") != 1:
        raise RecordValidationError("unsupported record version")
    kind = record.get("kind")
    if kind not in ALLOWED_KINDS:
        raise RecordValidationError("invalid record kind")

    for field in ("created_at", "author_id", "author_public_key", "title", "statement"):
        if not isinstance(record.get(field), str) or not record[field].strip():
            raise RecordValidationError(f"{field} is required")
    if len(record["created_at"]) > 64:
        raise RecordValidationError("created_at is too long")
    _validate_created_at(record["created_at"])

    event_time = record.get("event_time")
    if event_time is not None and (
        not isinstance(event_time, str) or len(event_time) > 512
    ):
        raise RecordValidationError(
            "event_time must be null or a string of 512 characters or fewer"
        )
    if len(record["title"]) > MAX_TITLE_CHARS:
        raise RecordValidationError(
            f"title must be {MAX_TITLE_CHARS} characters or fewer"
        )
    if len(record["statement"]) > MAX_STATEMENT_CHARS:
        raise RecordValidationError("statement is too large")
    if len(record["author_public_key"]) != 64:
        raise RecordValidationError(
            "author_public_key must be a 32-byte Ed25519 public key"
        )
    try:
        bytes.fromhex(record["author_public_key"])
    except ValueError as exc:
        raise RecordValidationError("author_public_key must be hexadecimal") from exc

    expected_author = public_key_to_author_id(record["author_public_key"])
    if expected_author != record["author_id"]:
        raise RecordValidationError("author_id does not match public key")

    target = record.get("target_record_id")
    if kind in TARGET_KINDS:
        _require_hex_digest(target, "target_record_id")
    elif target is not None:
        raise RecordValidationError("claim records cannot target another record")

    sources = normalize_list(record.get("sources"), "sources")
    evidence = normalize_list(record.get("evidence"), "evidence")
    tags = normalize_list(record.get("tags"), "tags")
    if len(sources) > MAX_SOURCES:
        raise RecordValidationError(
            f"a record may contain at most {MAX_SOURCES} sources"
        )
    if len(evidence) > MAX_EVIDENCE_ITEMS:
        raise RecordValidationError(
            f"a record may contain at most {MAX_EVIDENCE_ITEMS} evidence entries"
        )
    if len(tags) > MAX_TAGS or any(
        not isinstance(tag, str) or not tag or len(tag) > 64 for tag in tags
    ):
        raise RecordValidationError("invalid tags")

    for source in sources:
        if not isinstance(source, dict) or set(source) != SOURCE_FIELDS:
            raise RecordValidationError(
                "source fields do not match the versioned schema"
            )
        if not isinstance(source.get("uri"), str) or not source["uri"]:
            raise RecordValidationError("each source requires a non-empty uri")
        if len(source["uri"]) > 2048:
            raise RecordValidationError("source uri is too long")
        label = source.get("label")
        if label is not None and (not isinstance(label, str) or len(label) > 240):
            raise RecordValidationError("source label is invalid")

    for item in evidence:
        if not isinstance(item, dict) or set(item) != EVIDENCE_FIELDS:
            raise RecordValidationError(
                "evidence fields do not match the versioned schema"
            )
        _require_hex_digest(item.get("sha256"), "evidence sha256")
        filename = item.get("filename")
        if not isinstance(filename, str) or not filename or len(filename) > 255:
            raise RecordValidationError("evidence filename is invalid")
        size = item.get("size")
        if not isinstance(size, int) or isinstance(size, bool) or size < 0:
            raise RecordValidationError("evidence size must be a non-negative integer")
        mime_type = item.get("mime_type")
        if mime_type is not None and (
            not isinstance(mime_type, str) or len(mime_type) > 255
        ):
            raise RecordValidationError("evidence mime_type is invalid")
        cid = item.get("cid")
        if cid is not None and (not isinstance(cid, str) or len(cid) > 512):
            raise RecordValidationError("evidence cid is invalid")

    signature = record.get("signature")
    record_id = record.get("record_id")
    if not isinstance(signature, str) or len(signature) > 256:
        raise RecordValidationError("signature is required")
    _require_hex_digest(record_id, "record_id")
    if calculate_record_id(record) != record_id:
        raise RecordValidationError("record_id does not match record contents")
    if verify_signature and not verify(
        record["author_public_key"],
        signature,
        canonical_json_bytes(signing_body(record)),
    ):
        raise RecordValidationError("invalid record signature")


def create_signed_record(
    *,
    private_key: str,
    kind: RecordKind,
    title: str,
    statement: str,
    event_time: str | None = None,
    target_record_id: str | None = None,
    sources: list[dict[str, Any]] | None = None,
    evidence: list[dict[str, Any]] | None = None,
    tags: list[str] | None = None,
    created_at: str | None = None,
) -> dict[str, Any]:
    public_key = derive_public_key(private_key)
    record: dict[str, Any] = {
        "schema": "hap.record",
        "version": 1,
        "kind": kind,
        "created_at": created_at or utc_now_iso(),
        "event_time": event_time,
        "author_id": public_key_to_author_id(public_key),
        "author_public_key": public_key,
        "title": title.strip(),
        "statement": statement.strip(),
        "target_record_id": target_record_id,
        "sources": sources or [],
        "evidence": evidence or [],
        "tags": tags or [],
    }
    record["signature"] = sign(private_key, canonical_json_bytes(signing_body(record)))
    record["record_id"] = calculate_record_id(record)
    validate_record(record)
    return record
