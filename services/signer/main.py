"""Signer service factory, liveness and authenticated seal boundary."""

from __future__ import annotations

from fastapi import Depends, FastAPI, Request

from libs.blackbox_core import schemas
from libs.blackbox_core.canonical import loads
from libs.blackbox_core.errors import SignerRuleError
from libs.blackbox_core.schemas import SealedEntry, parse_entry
from services.signer.auth import SignerHTTPError, install_error_handlers, require_bearer
from services.signer.epoch_manager import EpochUnavailableError
from services.signer.history import HistoryIntegrityError, HistorySourceError, OutcomeConflictError
from services.signer.http_contract import HEALTH_PATH, SEAL_PATH
from services.signer.sealer import SignerSealer
from services.signer.state import OutcomeIndexError, epoch_metadata_exists


def create_app(*, sealer: SignerSealer | None = None) -> FastAPI:
    app = FastAPI()
    app.state.sealer = sealer
    install_error_handlers(app)
    app.add_api_route(HEALTH_PATH, health, methods=["GET"])
    app.add_api_route(SEAL_PATH, seal_http, methods=["POST"])
    return app


def signer_health(signer: object | None) -> dict[str, str]:
    if signer is None:
        return {"status": "ok"}
    reason = getattr(signer, "health_reason", None)
    if reason is not None:
        return {"status": "degraded", "reason": reason}
    manager = getattr(signer, "_epoch_manager", None)
    if manager is not None and getattr(manager, "degraded", False):
        return {"status": "degraded", "reason": "new_epoch_required"}
    if manager is None and epoch_metadata_exists():
        return {"status": "degraded", "reason": "new_epoch_required"}
    return {"status": "ok"}


async def health(request: Request) -> dict[str, str]:
    return signer_health(getattr(request.app.state, "sealer", None))


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
        if hasattr(signer, "seal_with_rollover"):
            rollover_entries, sealed = signer.seal_with_rollover(candidate)
            response = sealed.model_dump()
            if rollover_entries:
                response["rollover_entries"] = [entry.model_dump() for entry in rollover_entries]
            return response
        return signer.seal(candidate).model_dump()
    except HistorySourceError as exc:
        raise SignerHTTPError(503, "signer_unavailable", "Signer unavailable.") from exc
    except HistoryIntegrityError as exc:
        raise SignerHTTPError(
            409, "history_integrity", "History evidence failed integrity validation."
        ) from exc
    except OutcomeConflictError as exc:
        raise SignerHTTPError(
            409, "outcome_conflict", "The intent already has a conflicting outcome."
        ) from exc
    except OutcomeIndexError as exc:
        raise SignerHTTPError(
            409, "outcome_index_invalid", "Signer outcome state is invalid."
        ) from exc
    except EpochUnavailableError as exc:
        raise SignerHTTPError(503, "new_epoch_required", "A new signer epoch is required.") from exc
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
