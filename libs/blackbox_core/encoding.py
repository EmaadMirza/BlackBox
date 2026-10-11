"""Strict wire encodings (spec §5.2)."""

from __future__ import annotations

import base64
import re
from datetime import datetime, timezone


def encode_base64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def decode_base64url(value: str) -> bytes:
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9_-]*", value):
        raise ValueError("invalid unpadded base64url")
    try:
        decoded = base64.b64decode(value + "=" * (-len(value) % 4), altchars=b"-_", validate=True)
    except ValueError as exc:
        raise ValueError("invalid base64url") from exc
    if encode_base64url(decoded) != value:
        raise ValueError("non-canonical base64url")
    return decoded


def encode_hash(digest: bytes) -> str:
    if len(digest) != 32:
        raise ValueError("SHA-256 digest must be 32 bytes")
    return "sha256:" + digest.hex()


def decode_hash(value: str) -> bytes:
    if not isinstance(value, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", value):
        raise ValueError("invalid SHA-256 encoding")
    return bytes.fromhex(value[7:])


def format_timestamp(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("timezone required")
    if value.microsecond % 1000:
        raise ValueError("sub-millisecond precision is not supported")
    return value.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def parse_timestamp(value: str) -> datetime:
    if not isinstance(value, str) or not re.fullmatch(
        r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z", value
    ):
        raise ValueError("expected RFC 3339 UTC timestamp with milliseconds")
    return datetime.fromisoformat(value.replace("Z", "+00:00"))
