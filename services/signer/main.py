"""Signer service factory, liveness and authenticated seal boundary."""

from __future__ import annotations

from fastapi import Depends, FastAPI, Request

from libs.blackbox_core import schemas
from libs.blackbox_core.canonical import loads
from libs.blackbox_core.errors import SignerRuleError
from libs.blackbox_core.schemas import SealedEntry, parse_entry
from services.signer.auth import SignerHTTPError, install_error_handlers, require_bearer
from services.signer.http_contract import HEALTH_PATH, SEAL_PATH, HealthResponse
from services.signer.sealer import SignerSealer


def create_app(*, sealer: SignerSealer | None = None) -> FastAPI:
    app = FastAPI()
    app.state.sealer = sealer
    install_error_handlers(app)
    app.add_api_route(HEALTH_PATH, health, methods=["GET"], response_model=HealthResponse)
    app.add_api_route(SEAL_PATH, seal_http, methods=["POST"], response_model=SealedEntry)
    return app


async def health() -> dict[str, str]:
    return HealthResponse().model_dump()


async def seal_http(request: Request, _: None = Depends(require_bearer)) -> SealedEntry:
    """Authenticate, validate and delegate one raw candidate to the signer."""

    signer = getattr(request.app.state, "sealer", None)
    if signer is None:
        raise SignerHTTPError(503, "signer_unavailable", "Signer unavailable.")

    try:
        candidate = parse_entry(loads(await request.body()))
    except (RecursionError, TypeError, ValueError, UnicodeDecodeError) as exc:
        raise SignerHTTPError(422, "invalid_request", "Invalid request.") from exc

    try:
        return signer.seal(candidate)
    except SignerRuleError as exc:
        raise SignerHTTPError(409, "rule_conflict", "Request conflicts with signer rules.") from exc
    except (OSError, ValueError) as exc:
        raise SignerHTTPError(503, "signer_unavailable", "Signer unavailable.") from exc
    except Exception as exc:
        raise SignerHTTPError(500, "internal_error", "Internal error.") from exc


async def seal(candidate: schemas.Entry) -> schemas.SealedEntry:
    raise NotImplementedError("not built")


async def attest(intent_seq: int) -> schemas.Attestation:
    raise NotImplementedError("not built")


async def checkpoint(request: schemas.Checkpoint) -> schemas.Checkpoint:
    raise NotImplementedError("not built")
