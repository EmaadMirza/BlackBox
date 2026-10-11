"""BlackBox NFC preprocessing followed by RFC 8785 JCS (spec §5.2)."""

from __future__ import annotations

import json
import unicodedata

import rfc8785

MAX_INTEGER = 2**53 - 1


def normalize(value: object) -> object:
    if value is None or type(value) is bool:
        return value
    if type(value) is int:
        if abs(value) > MAX_INTEGER:
            raise ValueError("integer outside JCS safe range; use a decimal string")
        return value
    if isinstance(value, str):
        value.encode("utf-8", errors="strict")
        return unicodedata.normalize("NFC", value)
    if isinstance(value, list):
        return [normalize(item) for item in value]
    if isinstance(value, dict):
        result = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise ValueError("JSON object keys must be strings")
            normalized = normalize(key)
            if normalized in result:
                raise ValueError("duplicate object key after NFC normalization")
            result[normalized] = normalize(item)
        return result
    raise ValueError("only JSON values with safe integers are accepted; floats are forbidden")


def _pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _reject_number(value: str) -> object:
    raise ValueError("floating-point and non-finite JSON numbers are forbidden")


def loads(data: str | bytes) -> object:
    """Parse at the trust boundary, before duplicate object keys can be lost."""
    if isinstance(data, bytes):
        data = data.decode("utf-8", errors="strict")
    return normalize(
        json.loads(
            data,
            object_pairs_hook=_pairs,
            parse_float=_reject_number,
            parse_constant=_reject_number,
        )
    )


def canonicalize(value: object) -> bytes:
    """Accept JSON values, or UTF-8 JSON bytes; strings are JSON string values."""
    if isinstance(value, bytes):
        value = loads(value)
    return rfc8785.dumps(normalize(value))
