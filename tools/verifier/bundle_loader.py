"""Offline bounded JSON input with duplicate-key rejection (spec §16.1–2)."""

from pathlib import Path

from libs.blackbox_core.canonical import loads
from libs.blackbox_core.evidence import Bundle, PinnedKeys

MAX_BUNDLE_BYTES = 64 * 1024 * 1024


def read_json(path: Path) -> object:
    with path.open("rb") as stream:
        raw = stream.read(MAX_BUNDLE_BYTES + 1)
    if len(raw) > MAX_BUNDLE_BYTES:
        raise ValueError("input exceeds 64 MiB verification limit")
    return loads(raw)


def load_bundle(path: Path) -> Bundle:
    return Bundle.model_validate(read_json(path))


def load_pinned_keys(path: Path) -> PinnedKeys:
    return PinnedKeys.model_validate(read_json(path))
