from __future__ import annotations

import hashlib
import json
from typing import Any


class CanonicalEncodingError(ValueError):
    pass


# Largest integer represented exactly by all common JSON implementations, including JavaScript.
MAX_SAFE_JSON_INTEGER = 9_007_199_254_740_991


def _validate_json_value(value: Any, path: str = "$", depth: int = 0) -> None:
    if depth > 32:
        raise CanonicalEncodingError(
            f"JSON nesting exceeds the protocol limit at {path}"
        )
    if value is None or isinstance(value, (str, bool)):
        return
    if isinstance(value, int):
        if not -MAX_SAFE_JSON_INTEGER <= value <= MAX_SAFE_JSON_INTEGER:
            raise CanonicalEncodingError(
                f"integer exceeds the protocol JSON-safe range at {path}"
            )
        return
    if isinstance(value, float):
        raise CanonicalEncodingError(f"floating-point values are forbidden at {path}")
    if isinstance(value, list):
        for index, item in enumerate(value):
            _validate_json_value(item, f"{path}[{index}]", depth + 1)
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise CanonicalEncodingError(
                    f"JSON object keys must be strings at {path}"
                )
            _validate_json_value(item, f"{path}.{key}", depth + 1)
        return
    raise CanonicalEncodingError(
        f"unsupported JSON value at {path}: {type(value).__name__}"
    )


def canonical_json_bytes(value: Any) -> bytes:
    """Encode the protocol's restricted JSON subset deterministically.

    HAP canonical JSON v1 forbids floats and non-JSON values, sorts object keys, emits UTF-8,
    and removes insignificant whitespace. The exact bytes are consensus-critical.
    """
    _validate_json_value(value)
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def sha256_hex(data: bytes) -> str:
    return sha256(data).hex()
