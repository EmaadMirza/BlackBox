"""Six findings; separate from verifier verdicts Scaffold only; no runtime behavior."""

from __future__ import annotations

from libs.blackbox_core import schemas

# TODO(spec §15.3): implement and validate before enabling this module.


def classify(
    entries: list[schemas.SealedEntry], events: list[dict[str, str]], now: str
) -> list[schemas.Finding]:
    raise NotImplementedError("not built")
