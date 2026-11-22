"""Unit tests for Stage 5 Web Lane HMAC authentication and replay defense (services/gateway/auth_web.py)."""

from __future__ import annotations

import asyncio
import time

import pytest
from fastapi.testclient import TestClient

from services.gateway.auth_web import (
    MemoryNonceStore,
    WebAuthError,
    authenticate,
    sign_request,
)
from services.gateway.main import create_app


@pytest.fixture
def web_secret() -> bytes:
    return b"test-shared-secret-key-12345"


def test_web_hmac_valid_signature(web_secret: bytes) -> None:
    """Valid HMAC signature, timestamp, and nonce authenticates successfully."""
    key_id = "client-alpha"
    method = "POST"
    path = "/v1/web"
    body = b'{"event":"customer_checkout","total":4500}'
    now = time.time()

    headers = sign_request(key_id, web_secret, method, path, body, timestamp=now, nonce="nonce-1")
    nonce_store = MemoryNonceStore()

    async def _test() -> None:
        principal = await authenticate(
            method,
            path,
            body,
            headers,
            secret_registry={key_id: web_secret},
            nonce_store=nonce_store,
            clock=lambda: now,
        )
        assert principal.client_key_id == key_id
        assert principal.source_address == "web"

    asyncio.run(_test())


def test_web_hmac_replay_defense(web_secret: bytes) -> None:
    """Duplicate nonce within the TTL window is rejected as a replay."""
    key_id = "client-alpha"
    method = "POST"
    path = "/v1/web"
    body = b'{"event":"payment"}'
    now = time.time()

    headers = sign_request(
        key_id, web_secret, method, path, body, timestamp=now, nonce="unique-nonce-1"
    )
    nonce_store = MemoryNonceStore()

    async def _test() -> None:
        # First call succeeds
        await authenticate(
            method,
            path,
            body,
            headers,
            secret_registry={key_id: web_secret},
            nonce_store=nonce_store,
            clock=lambda: now,
        )

        # Second call with same nonce must raise WebAuthError (replay detected)
        with pytest.raises(WebAuthError, match="Replay detected"):
            await authenticate(
                method,
                path,
                body,
                headers,
                secret_registry={key_id: web_secret},
                nonce_store=nonce_store,
                clock=lambda: now,
            )

    asyncio.run(_test())


def test_web_hmac_timestamp_window_defense(web_secret: bytes) -> None:
    """Requests with timestamp skewed > 60 seconds are rejected."""
    key_id = "client-alpha"
    method = "POST"
    path = "/v1/web"
    body = b"{}"
    now = time.time()

    async def _test() -> None:
        # Request from 90 seconds in past
        old_headers = sign_request(
            key_id, web_secret, method, path, body, timestamp=now - 90, nonce="n-old"
        )
        with pytest.raises(WebAuthError, match="outside acceptable window"):
            await authenticate(
                method,
                path,
                body,
                old_headers,
                secret_registry={key_id: web_secret},
                clock=lambda: now,
            )

        # Request from 90 seconds in future
        future_headers = sign_request(
            key_id, web_secret, method, path, body, timestamp=now + 90, nonce="n-fut"
        )
        with pytest.raises(WebAuthError, match="outside acceptable window"):
            await authenticate(
                method,
                path,
                body,
                future_headers,
                secret_registry={key_id: web_secret},
                clock=lambda: now,
            )

    asyncio.run(_test())


def test_web_hmac_tamper_defense(web_secret: bytes) -> None:
    """Tampering with body or URL parameters breaks signature."""
    key_id = "client-alpha"
    method = "POST"
    path = "/v1/web"
    body = b'{"amount":100}'
    now = time.time()

    headers = sign_request(key_id, web_secret, method, path, body, timestamp=now, nonce="n-tamper")

    async def _test() -> None:
        tampered_body = b'{"amount":1000000}'
        with pytest.raises(WebAuthError, match="Invalid HMAC-SHA256 signature"):
            await authenticate(
                method,
                path,
                tampered_body,
                headers,
                secret_registry={key_id: web_secret},
                clock=lambda: now,
            )

    asyncio.run(_test())


def test_gateway_http_web_endpoint_hmac(web_secret: bytes) -> None:
    """Test Gateway HTTP /v1/web endpoint verifies HMAC headers and rejects replays."""
    key_id = "web-client-1"
    secrets = {key_id: web_secret}
    nonce_store = MemoryNonceStore()

    app = create_app(web_secrets=secrets, nonce_store=nonce_store)
    with TestClient(app) as client:
        body = b'{"action":"webhook"}'
        headers = sign_request(key_id, web_secret, "POST", "/v1/web", body, nonce="web-n-1")

        # 1. Honest authenticated call succeeds
        res = client.post("/v1/web", content=body, headers=headers)
        assert res.status_code == 200
        assert res.json()["status"] == "ok"
        assert res.json()["principal"]["client_key_id"] == key_id

        # 2. Replay with identical headers blocked
        replay_res = client.post("/v1/web", content=body, headers=headers)
        assert replay_res.status_code == 403
        assert replay_res.json()["status"] == "blocked"
        assert "Replay detected" in replay_res.json()["error"]
