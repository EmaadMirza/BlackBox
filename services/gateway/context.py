"""Agent prompt, tool and input lineage tracking (spec §13.4)."""

from __future__ import annotations

from libs.blackbox_core import schemas
from libs.blackbox_core.crypto import sha256
from libs.blackbox_core.encoding import encode_hash


def build_context(
    system_prompt: str,
    tool_definitions: bytes,
    model_identifier: str,
    model_version: str,
    inputs: list[schemas.UntrustedInput],
) -> schemas.Context:
    """Build a validated Context structure binding prompt, tools, model, and inputs."""
    sys_hash = encode_hash(sha256(system_prompt.encode("utf-8")))
    tools_hash = encode_hash(sha256(tool_definitions))
    return schemas.Context(
        system_prompt_hash=sys_hash,
        tool_definitions_hash=tools_hash,
        model_identifier=model_identifier,
        model_version=model_version,
        untrusted_inputs=list(inputs),
    )
