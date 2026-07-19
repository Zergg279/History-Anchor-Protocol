from __future__ import annotations

import hashlib
from pathlib import PurePath
from typing import Any
from urllib.parse import urlsplit

from .codec import canonical_json_bytes
from .config import Settings
from .responsible import validate_responsible_record

RELAY_POW_DOMAIN = b"HAP-RELAY-POW-V1\x00"
ALLOWED_SOURCE_SCHEMES = {"https", "hap"}
MAX_DECLARED_EVIDENCE_BYTES = 100 * 1024 * 1024 * 1024  # 100 GiB metadata ceiling


class PolicyError(ValueError):
    pass


def _contains_forbidden_controls(value: str) -> bool:
    return any(ord(char) < 32 and char not in "\t\n\r" for char in value)


def _validate_plain_text(
    value: Any, field: str, *, allow_newlines: bool = True
) -> None:
    if not isinstance(value, str):
        raise PolicyError(f"{field} must be text")
    if "\x00" in value or _contains_forbidden_controls(value):
        raise PolicyError(f"{field} contains forbidden control characters")
    if not allow_newlines and any(char in value for char in "\r\n"):
        raise PolicyError(f"{field} must be a single line")


def _validate_source_uri(uri: str) -> None:
    parsed = urlsplit(uri)
    scheme = parsed.scheme.lower()
    if scheme not in ALLOWED_SOURCE_SCHEMES:
        raise PolicyError(
            "safe relay source URIs must use https or a strict hap:record reference"
        )
    if scheme == "hap":
        prefix = "hap:record:"
        digest = uri[len(prefix) :] if uri.startswith(prefix) else ""
        try:
            raw = bytes.fromhex(digest)
        except ValueError as exc:
            raise PolicyError(
                "HAP source references must be hap:record:<32-byte-hex-id>"
            ) from exc
        if len(raw) != 32:
            raise PolicyError(
                "HAP source references must be hap:record:<32-byte-hex-id>"
            )
        return
    if not parsed.hostname:
        raise PolicyError("source URI requires a hostname")
    if parsed.username is not None or parsed.password is not None:
        raise PolicyError("source URI must not contain embedded credentials")


def validate_safe_relay_record(record: dict[str, Any], settings: Settings) -> None:
    """Local relay policy for the safe relay.

    This is deliberately stricter than protocol validity. Other nodes may choose
    different relay policies without changing record validity.
    """
    encoded = canonical_json_bytes(record)
    if len(encoded) > settings.max_record_bytes:
        raise PolicyError(
            f"record exceeds this node's {settings.max_record_bytes}-byte relay limit"
        )

    _validate_plain_text(record.get("title"), "title", allow_newlines=False)
    _validate_plain_text(record.get("statement"), "statement")
    if len(record["statement"]) > settings.max_statement_chars:
        raise PolicyError(
            f"statement exceeds this node's {settings.max_statement_chars}-character safe relay limit"
        )
    event_time = record.get("event_time")
    if event_time is not None:
        _validate_plain_text(event_time, "event_time")

    for tag in record.get("tags", []):
        _validate_plain_text(tag, "tag", allow_newlines=False)

    for source in record.get("sources", []):
        _validate_source_uri(source["uri"])
        label = source.get("label")
        if label is not None:
            _validate_plain_text(label, "source label", allow_newlines=False)

    if settings.responsible_publication_profile:
        validate_responsible_record(record)

    for item in record.get("evidence", []):
        filename = item["filename"]
        _validate_plain_text(filename, "evidence filename", allow_newlines=False)
        if PurePath(filename).name != filename or "/" in filename or "\\" in filename:
            raise PolicyError("evidence filename must not contain a path")
        if item["size"] > MAX_DECLARED_EVIDENCE_BYTES:
            raise PolicyError("declared evidence size exceeds the safe relay ceiling")
        if item.get("cid") not in (None, ""):
            raise PolicyError(
                "safe relay nodes accept evidence hashes and metadata only; retrieval locators are disabled"
            )


def leading_zero_bits(digest: bytes) -> int:
    count = 0
    for byte in digest:
        if byte == 0:
            count += 8
            continue
        count += 8 - byte.bit_length()
        break
    return count


def relay_pow_digest(record_id: str, nonce: str) -> bytes:
    if (
        not isinstance(nonce, str)
        or not nonce
        or len(nonce) > 64
        or not nonce.isdigit()
    ):
        raise PolicyError(
            "relay proof nonce must be a decimal integer of 64 digits or fewer"
        )
    return hashlib.sha256(
        RELAY_POW_DOMAIN + record_id.encode("ascii") + b"\x00" + nonce.encode("ascii")
    ).digest()


def verify_relay_pow(record_id: str, nonce: str | None, required_bits: int) -> bool:
    if required_bits <= 0:
        return True
    if nonce is None:
        return False
    try:
        return leading_zero_bits(relay_pow_digest(record_id, nonce)) >= required_bits
    except PolicyError:
        return False


def mine_relay_pow(
    record_id: str,
    required_bits: int,
    *,
    start: int = 0,
    max_attempts: int | None = None,
) -> str:
    if required_bits <= 0:
        return "0"
    nonce = max(0, start)
    attempts = 0
    while max_attempts is None or attempts < max_attempts:
        text = str(nonce)
        if leading_zero_bits(relay_pow_digest(record_id, text)) >= required_bits:
            return text
        nonce += 1
        attempts += 1
    raise PolicyError("relay proof was not found within max_attempts")
