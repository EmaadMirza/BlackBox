"""Intent, idempotency and provider-event joins Scaffold only; no runtime behavior."""

from __future__ import annotations

from libs.blackbox_core import schemas

# TODO(spec §15.2): implement and validate before enabling this module.


def join(
    entries: list[schemas.SealedEntry],
    events: list[dict[str, str]],
    now: str,
    grace_seconds: int = 30,
) -> list[tuple[schemas.SealedEntry | None, dict[str, str] | None]]:
    raise NotImplementedError("not built")
