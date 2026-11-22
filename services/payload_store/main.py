"""Authenticated, file-backed payload storage for commitment openings."""

from __future__ import annotations

import base64
import hmac
import json
import os
import secrets
from pathlib import Path
from typing import Any

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, Response
from pydantic import BaseModel, ConfigDict, ValidationError

from libs.blackbox_core import schemas
from libs.blackbox_core.commitments import commit, create_salt


def _b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode().rstrip("=")


def _unb64(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


class PayloadRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    value: str


class PayloadStore:
    def __init__(self, state_dir: Path, *, bearer_token: str = "") -> None:
        self.state_dir = state_dir
        self.state_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.bearer_token = bearer_token

    def _path(self, reference: str) -> Path:
        if not reference or any(
            char not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_"
            for char in reference
        ):
            raise ValueError("invalid reference")
        return self.state_dir / f"{reference}.json"

    def put(self, value: bytes, *, salt: bytes | None = None) -> tuple[str, str]:
        if salt is None:
            salt = create_salt()
        reference = secrets.token_urlsafe(18)
        payload = {
            "reference": reference,
            "commitment": commit(value, salt),
            "value": _b64(value),
            "salt": _b64(salt),
        }
        self._path(reference).write_text(
            json.dumps(payload, separators=(",", ":")), encoding="utf-8"
        )
        self._path(reference).chmod(0o600)
        return reference, payload["commitment"]

    def read(self, reference: str) -> tuple[bytes, bytes, str]:
        try:
            payload = json.loads(self._path(reference).read_text(encoding="utf-8"))
            return _unb64(payload["value"]), _unb64(payload["salt"]), payload["commitment"]
        except (OSError, ValueError, KeyError, TypeError) as exc:
            raise FileNotFoundError from exc

    def salt(self, reference: str) -> bytes:
        return self.read(reference)[1]

    def commitment(self, reference: str) -> str:
        try:
            return json.loads(self._path(reference).read_text(encoding="utf-8"))["commitment"]
        except (OSError, ValueError, KeyError, TypeError) as exc:
            raise FileNotFoundError from exc

    def delete(self, reference: str) -> None:
        path = self._path(reference)
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
            path.write_text(
                json.dumps({"reference": reference, "commitment": payload["commitment"]}),
                encoding="utf-8",
            )
            path.chmod(0o600)
        except (OSError, ValueError, KeyError, TypeError) as exc:
            raise FileNotFoundError from exc


def _auth(request: Request, token: str) -> bool:
    return not token or hmac.compare_digest(
        request.headers.get("authorization", ""), f"Bearer {token}"
    )


def create_app(store: PayloadStore | None = None) -> FastAPI:
    if store is None:
        if "PAYLOAD_DATA_DIR" in os.environ:
            state_dir = Path(os.environ["PAYLOAD_DATA_DIR"])
        elif Path("/var/lib/blackbox/payloads").exists() or Path("/var/lib/blackbox").exists():
            state_dir = Path("/var/lib/blackbox/payloads")
        else:
            state_dir = Path("payload-state")
        store = PayloadStore(state_dir)
    app = FastAPI()

    @app.get("/health")
    async def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.post("/v1/payloads")
    async def put_payload(request: Request) -> Response:
        if not _auth(request, store.bearer_token):
            return JSONResponse(
                {"error": {"code": "unauthorized", "message": "Authentication required."}}, 401
            )
        try:
            raw = json.loads(await request.body(), object_pairs_hook=lambda pairs: _unique(pairs))
            value = PayloadRequest.model_validate(raw).value.encode()
        except (ValueError, TypeError, UnicodeDecodeError, ValidationError):
            return JSONResponse(
                {"error": {"code": "malformed", "message": "Malformed request."}}, 422
            )
        reference, commitment = store.put(value)
        return JSONResponse({"reference": reference, "commitment": commitment}, 201)

    @app.get("/v1/payloads/{reference}")
    async def get_payload(reference: str, request: Request) -> Response:
        if not _auth(request, store.bearer_token):
            return JSONResponse(
                {"error": {"code": "unauthorized", "message": "Authentication required."}}, 401
            )
        try:
            value, salt, commitment = store.read(reference)
        except FileNotFoundError:
            return JSONResponse(
                {"error": {"code": "not_found", "message": "Payload unavailable."}}, 404
            )
        return JSONResponse(
            {
                "reference": reference,
                "commitment": commitment,
                "value": value.decode(),
                "salt": _b64(salt),
            }
        )

    @app.delete("/v1/payloads/{reference}")
    async def delete_payload(reference: str, request: Request) -> Response:
        if not _auth(request, store.bearer_token):
            return JSONResponse(
                {"error": {"code": "unauthorized", "message": "Authentication required."}}, 401
            )
        try:
            store.delete(reference)
        except FileNotFoundError:
            return JSONResponse(
                {"error": {"code": "not_found", "message": "Payload unavailable."}}, 404
            )
        return Response(status_code=204)

    return app


async def health() -> dict[str, str]:
    return {"status": "ok"}


async def store_payload(value: bytes, salt: bytes) -> str:
    return commit(value, salt)


async def open_payload(reference: str, authorization: str) -> tuple[bytes, bytes]:
    raise NotImplementedError("use create_app with an authenticated PayloadStore")


async def resolve_action_payload(action: schemas.RequestAction) -> bytes:
    raise NotImplementedError("payload resolution requires an injected PayloadStore")


def _unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result
