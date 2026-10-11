"""Strict models validate all signed/nested data at trust boundaries."""

import pytest
from pydantic import ValidationError

from libs.blackbox_core.schemas import Action, parse_entry


def action() -> dict[str, object]:
    return dict(
        format_version="4",
        log_id="sha256:" + "1" * 64,
        epoch_id=0,
        seq=0,
        type="action",
        signer_timestamp="2026-01-01T00:00:00.000Z",
        prev_hash="sha256:" + "0" * 64,
        lane="agent",
        epoch_certificate_id="sha256:" + "2" * 64,
        action_name="audit",
        reason="test",
        target_reference="test",
    )


def test_valid_entry() -> None:
    assert isinstance(parse_entry(action()), Action)


@pytest.mark.parametrize(
    "field,value",
    [
        ("extra", 1),
        ("seq", True),
        ("seq", 0.0),
        ("seq", -1),
        ("log_id", "bad"),
        ("signer_timestamp", "now"),
        ("format_version", "3"),
        ("epoch_id", 2**53),
    ],
)
def test_bad_field(field: str, value: object) -> None:
    data = action()
    data[field] = value
    with pytest.raises((ValueError, ValidationError)):
        parse_entry(data)


def test_unknown_type() -> None:
    data = action()
    data["type"] = "unknown"
    with pytest.raises(ValidationError):
        parse_entry(data)
