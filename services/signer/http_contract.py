"""Signer HTTP declarations only; no routes, authentication, or signing behavior.

Signed wire structures remain owned by core. See docs/signer-http-contract.md
for the runtime requirements that a future HTTP adapter must enforce.
"""

from __future__ import annotations

from typing import Final, Literal

from libs.blackbox_core.schemas import Attestation as Attestation
from libs.blackbox_core.schemas import Checkpoint as Checkpoint
from libs.blackbox_core.schemas import Count, StrictModel
from libs.blackbox_core.schemas import Entry as Entry
from libs.blackbox_core.schemas import SealedEntry as SealedEntry

HEALTH_PATH: Final = "/health"
SEAL_PATH: Final = "/seal"
ATTEST_PATH: Final = "/attest"
CHECKPOINT_PATH: Final = "/checkpoint"
AUTH_HEADER: Final = "Authorization"
AUTH_SCHEME: Final = "Bearer"
AUTH_TOKEN_ENV: Final = "SIGNER_AUTH_TOKEN"


class HealthResponse(StrictModel):
    """Process liveness only, not signer readiness or a security verdict."""

    status: Literal["ok"] = "ok"


class AttestRequest(StrictModel):
    """Only the sealed intent sequence is supplied by the caller."""

    intent_seq: Count


class ErrorDetail(StrictModel):
    """Stable public code and non-sensitive message, never exception details."""

    code: str
    message: str


class ErrorResponse(StrictModel):
    """Common rejection envelope for the signer operations."""

    error: ErrorDetail
