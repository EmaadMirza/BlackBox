"""Agent prompt, tool and input lineage Scaffold only; no runtime behavior."""

from __future__ import annotations

from libs.blackbox_core import schemas

# TODO(spec §13.4): implement and validate before enabling this module.


def build_context(
    system_prompt: str,
    tool_definitions: bytes,
    model_identifier: str,
    model_version: str,
    inputs: list[schemas.UntrustedInput],
) -> schemas.Context:
    raise NotImplementedError("not built")
