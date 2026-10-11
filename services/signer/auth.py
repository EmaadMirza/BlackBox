"""Signer HTTP authentication and stable error handling."""

from __future__ import annotations

import hmac
import os
from collections.abc import Iterable

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from services.signer.http_contract import AUTH_HEADER, AUTH_SCHEME, AUTH_TOKEN_ENV, ErrorResponse

AUTH_REQUIRED_MESSAGE = "Authentication required."
AUTH_UNAVAILABLE_MESSAGE = "Authentication unavailable."


class SignerHTTPError(Exception):
    """Public, sanitized error raised by signer HTTP dependencies."""

    def __init__(
        self, status_code: int, code: str, message: str, *, challenge: bool = False
    ) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.code = code
        self.message = message
        self.challenge = challenge


def _valid_token(value: str | None) -> bool:
    return bool(value) and value.isascii() and not any(character.isspace() for character in value)


def _authorization_values(request: Request) -> Iterable[str]:
    for name, value in request.scope.get("headers", []):
        if name.lower() == AUTH_HEADER.lower().encode("ascii"):
            yield value.decode("latin-1")


def require_bearer(request: Request) -> None:
    """Require the configured exact bearer token for a protected operation."""

    configured = os.environ.get(AUTH_TOKEN_ENV)
    if not _valid_token(configured):
        raise SignerHTTPError(503, "auth_unavailable", AUTH_UNAVAILABLE_MESSAGE)

    values = list(_authorization_values(request))
    if len(values) != 1:
        raise SignerHTTPError(401, "invalid_auth", AUTH_REQUIRED_MESSAGE, challenge=True)

    supplied = values[0]
    parts = supplied.split(" ")
    if len(parts) != 2 or parts[0].lower() != AUTH_SCHEME.lower() or not _valid_token(parts[1]):
        raise SignerHTTPError(401, "invalid_auth", AUTH_REQUIRED_MESSAGE, challenge=True)

    if not hmac.compare_digest(parts[1].encode("ascii"), configured.encode("ascii")):
        raise SignerHTTPError(401, "invalid_auth", AUTH_REQUIRED_MESSAGE, challenge=True)


def _error_response(error: SignerHTTPError) -> JSONResponse:
    body = ErrorResponse.model_validate(
        {"error": {"code": error.code, "message": error.message}}
    ).model_dump(mode="json")
    headers = {"WWW-Authenticate": AUTH_SCHEME} if error.challenge else None
    return JSONResponse(status_code=error.status_code, content=body, headers=headers)


def install_error_handlers(app: FastAPI) -> None:
    """Install the stable signer error envelope on an application."""

    @app.exception_handler(SignerHTTPError)
    async def signer_http_error_handler(_: Request, error: SignerHTTPError) -> JSONResponse:
        return _error_response(error)
