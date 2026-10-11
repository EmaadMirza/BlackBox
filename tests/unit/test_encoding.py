"""Wire-encoding roundtrips and rejection cases."""

from datetime import datetime, timezone

import pytest

from libs.blackbox_core.encoding import (
    decode_base64url,
    decode_hash,
    encode_base64url,
    encode_hash,
    format_timestamp,
    parse_timestamp,
)


def test_roundtrip() -> None:
    for value in (b"", b"a", bytes(range(256))):
        assert decode_base64url(encode_base64url(value)) == value
    assert decode_hash(encode_hash(bytes(32))) == bytes(32)
    stamp = "2026-01-01T00:00:00.123Z"
    assert format_timestamp(parse_timestamp(stamp)) == stamp


@pytest.mark.parametrize("value", ["YQ==", "Y!", "Y", "YR", "a b", "+/"])
def test_bad_base64(value: str) -> None:
    with pytest.raises(ValueError):
        decode_base64url(value)


@pytest.mark.parametrize(
    "value", ["2026-01-01T00:00:00Z", "2026-01-01T00:00:00.000+00:00", "2026-13-01T00:00:00.000Z"]
)
def test_bad_timestamp(value: str) -> None:
    with pytest.raises(ValueError):
        parse_timestamp(value)


def test_timestamp_no_silent_rounding() -> None:
    with pytest.raises(ValueError):
        format_timestamp(datetime(2026, 1, 1))
    with pytest.raises(ValueError):
        format_timestamp(datetime(2026, 1, 1, microsecond=1, tzinfo=timezone.utc))
    with pytest.raises(ValueError):
        decode_hash("sha256:" + "A" * 64)
