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


def _extract_bearer_token(request: Request) -> str | None:
    values = list(_authorization_values(request))
    if len(values) != 1:
        return None
    parts = values[0].split(" ")
    if len(parts) == 2 and parts[0].lower() == AUTH_SCHEME.lower() and _valid_token(parts[1]):
        return parts[1]
    return None


def get_caller_identity(request: Request) -> str | None:
    """Extract authenticated caller identity from mTLS headers, ASGI TLS scope, or role tokens (§8.2)."""
    # 1. mTLS proxy client certificate common name / SAN / DN headers
    headers = getattr(request, "headers", {})
    if hasattr(headers, "items"):
        for k, v in headers.items():
            if not v:
                continue
            v_str = str(v).strip().strip("'\"")
            k_lower = str(k).lower()
            if k_lower in (
                "x-client-cn",
                "x-client-cert-cn",
                "ssl-client-subject-cn",
                "x-client-identity",
            ):
                if v_str:
                    return v_str.lower().strip()
            elif k_lower in (
                "x-client-dn",
                "x-client-cert-dn",
                "ssl-client-s-dn",
                "ssl-client-subject-dn",
            ):
                if v_str:
                    # Parse CN from DN: e.g. CN=gateway.internal,O=BlackBox...
                    for part in v_str.split(","):
                        part = part.strip()
                        if part.lower().startswith("cn="):
                            return part[3:].strip().strip("'\"").lower()

    # 2. ASGI TLS scope client certificate
    tls_info = (
        request.scope.get("tls")
        if hasattr(request, "scope") and isinstance(request.scope, dict)
        else None
    )
    if isinstance(tls_info, dict) and "client_cert" in tls_info:
        cert = tls_info["client_cert"]
        if isinstance(cert, dict):
            if "common_name" in cert and cert["common_name"]:
                return str(cert["common_name"]).lower().strip().strip("'\"")
            if "subject" in cert:
                subject = cert["subject"]
                if isinstance(subject, (list, tuple)):
                    for rdn in subject:
                        for item in rdn:
                            if isinstance(item, (list, tuple)) and len(item) == 2:
                                attr, val = item
                                if str(attr).lower() in ("commonname", "cn") and val:
                                    return str(val).lower().strip().strip("'\"")

    # 3. Role-specific tokens
    token = _extract_bearer_token(request)
    if token:
        token_bytes = token.encode("ascii")
        gw_token = os.environ.get("SIGNER_GATEWAY_TOKEN")
        if gw_token and hmac.compare_digest(token_bytes, gw_token.encode("ascii")):
            return "gateway"
        ledger_token = os.environ.get("SIGNER_LEDGER_TOKEN")
        if ledger_token and hmac.compare_digest(token_bytes, ledger_token.encode("ascii")):
            return "ledger"
        witness_token = os.environ.get("SIGNER_WITNESS_TOKEN")
        if witness_token and hmac.compare_digest(token_bytes, witness_token.encode("ascii")):
            return "witness"

    return None


GATEWAY_ROLES = {"gateway", "gateway.internal", "blackbox-gateway"}
LEDGER_ROLES = {"ledger", "ledger.internal", "blackbox-ledger"}
INTERNAL_ROLES = {
    "gateway",
    "gateway.internal",
    "blackbox-gateway",
    "ledger",
    "ledger.internal",
    "blackbox-ledger",
    "witness",
    "witness.internal",
    "blackbox-witness",
    "monitor",
    "monitor.internal",
}


def require_directional_caller(allowed_roles: set[str]):
    """Enforce both bearer authentication and directional caller authorization (§8.2)."""

    def dependency(request: Request) -> None:
        token = _extract_bearer_token(request)
        configured_general = os.environ.get(AUTH_TOKEN_ENV)
        configured_gw = os.environ.get("SIGNER_GATEWAY_TOKEN")
        configured_ledger = os.environ.get("SIGNER_LEDGER_TOKEN")
        configured_witness = os.environ.get("SIGNER_WITNESS_TOKEN")

        valid_configs = [
            t
            for t in (configured_general, configured_gw, configured_ledger, configured_witness)
            if _valid_token(t)
        ]
        if not valid_configs:
            raise SignerHTTPError(503, "auth_unavailable", AUTH_UNAVAILABLE_MESSAGE)

        if not token:
            raise SignerHTTPError(401, "invalid_auth", AUTH_REQUIRED_MESSAGE, challenge=True)

        token_bytes = token.encode("ascii")
        matched = False
        matched_role = None

        if configured_general and hmac.compare_digest(
            token_bytes, configured_general.encode("ascii")
        ):
            matched = True
        if configured_gw and hmac.compare_digest(token_bytes, configured_gw.encode("ascii")):
            matched = True
            matched_role = "gateway"
        if configured_ledger and hmac.compare_digest(
            token_bytes, configured_ledger.encode("ascii")
        ):
            matched = True
            matched_role = "ledger"
        if configured_witness and hmac.compare_digest(
            token_bytes, configured_witness.encode("ascii")
        ):
            matched = True
            matched_role = "witness"

        if not matched:
            raise SignerHTTPError(401, "invalid_auth", AUTH_REQUIRED_MESSAGE, challenge=True)

        caller = get_caller_identity(request) or matched_role
        if caller is not None:
            caller_norm = caller.lower().strip()
            is_allowed = any(
                r == caller_norm
                or caller_norm.startswith(f"{r}.")
                or caller_norm.startswith(f"{r}-")
                or f".{r}." in caller_norm
                or caller_norm.endswith(f".{r}")
                for r in allowed_roles
            )
            if not is_allowed:
                raise SignerHTTPError(
                    403,
                    "directional_auth_forbidden",
                    f"Caller identity '{caller_norm}' is not authorized for this operation.",
                )

    return dependency


require_gateway = require_directional_caller(GATEWAY_ROLES)
require_ledger = require_directional_caller(LEDGER_ROLES)
require_internal = require_directional_caller(INTERNAL_ROLES)


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
