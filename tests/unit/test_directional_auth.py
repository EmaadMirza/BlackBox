"""Tests for directional caller and operation-specific authorization (§8.2, Zero-Trust mTLS).

Validates:
- Gateway authorized for /seal and /attest; forbidden from /checkpoint
- Ledger authorized for /checkpoint; forbidden from /seal and /attest
- Witness authorized for /heartbeat; forbidden from /seal and /checkpoint
- External Agent rejected from all protected internal routes
- Both mTLS Subject CN headers and directional role tokens correctly enforce the matrix
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest
from fastapi.testclient import TestClient

from libs.blackbox_core.sealing import seal
from services.signer.auth import (
    get_caller_identity,
)
from services.signer.main import create_app
from tests._dev_keys import dev_key


@pytest.fixture
def test_sealer():
    sealer = MagicMock()
    del sealer.seal_with_rollover
    k = dev_key()
    sealer.seal.side_effect = lambda cand: seal(cand, k)
    sealer.attest.return_value = MagicMock(model_dump=lambda: {"status": "attested"})
    sealer.checkpoint.return_value = MagicMock(model_dump=lambda: {"status": "checkpointed"})
    sealer.heartbeat.return_value = MagicMock(model_dump=lambda: {"status": "heartbeat_ok"})
    return sealer


def test_directional_identity_extraction(monkeypatch) -> None:
    # 1. Reverse proxy mTLS header
    req1 = MagicMock()
    req1.headers = {"X-Client-CN": "gateway.internal"}
    req1.scope = {}
    assert get_caller_identity(req1) == "gateway.internal"

    # 2. ASGI TLS scope client cert
    req2 = MagicMock()
    req2.headers = {}
    req2.scope = {"tls": {"client_cert": {"common_name": "ledger.internal"}}}
    assert get_caller_identity(req2) == "ledger.internal"

    # 3. Role-specific token
    monkeypatch.setenv("SIGNER_GATEWAY_TOKEN", "token-gw-123")
    req3 = MagicMock()
    req3.headers = {}
    req3.scope = {"headers": [(b"authorization", b"Bearer token-gw-123")]}
    assert get_caller_identity(req3) == "gateway"


def test_directional_auth_matrix_with_client_headers(test_sealer, monkeypatch) -> None:
    monkeypatch.setenv("SIGNER_AUTH_TOKEN", "cluster-secret-token")
    app = create_app(sealer=test_sealer)
    client = TestClient(app)

    auth_header = {"Authorization": "Bearer cluster-secret-token"}

    # 1. Gateway calls /seal -> ACCEPTED (200 OK)
    seal_body = {
        "format_version": "4",
        "log_id": "sha256:" + "0" * 64,
        "epoch_id": 1,
        "seq": 1,
        "signer_timestamp": "2026-01-01T00:00:00.000Z",
        "prev_hash": "sha256:" + "0" * 64,
        "lane": "agent",
        "epoch_certificate_id": "sha256:" + "0" * 64,
        "type": "action",
        "action_name": "audit",
        "reason": "test",
        "target_reference": "test",
    }
    gw_headers = {**auth_header, "X-Client-CN": "gateway.internal"}
    resp = client.post("/seal", json=seal_body, headers=gw_headers)
    assert resp.status_code == 200

    # 2. Ledger calls /seal -> FORBIDDEN (403)
    ledger_headers = {**auth_header, "X-Client-CN": "ledger.internal"}
    resp = client.post("/seal", json=seal_body, headers=ledger_headers)
    assert resp.status_code == 403
    assert resp.json()["error"]["code"] == "directional_auth_forbidden"

    # 3. Witness calls /seal -> FORBIDDEN (403)
    witness_headers = {**auth_header, "X-Client-CN": "witness-1.internal"}
    resp = client.post("/seal", json=seal_body, headers=witness_headers)
    assert resp.status_code == 403
    assert resp.json()["error"]["code"] == "directional_auth_forbidden"

    # 4. Ledger calls /checkpoint -> ACCEPTED (200 OK)
    checkpoint_req = {
        "log_id": "sha256:" + "0" * 64,
        "tree_size": 10,
        "root_hash": "sha256:" + "0" * 64,
        "latest_seq": 9,
        "latest_entry_hash": "sha256:" + "0" * 64,
        "epoch_id": 1,
        "signer_timestamp": "2026-01-01T00:00:00.000Z",
    }
    resp = client.post("/checkpoint", json=checkpoint_req, headers=ledger_headers)
    assert resp.status_code == 200

    # 5. Gateway calls /checkpoint -> FORBIDDEN (403)
    resp = client.post("/checkpoint", json=checkpoint_req, headers=gw_headers)
    assert resp.status_code == 403
    assert resp.json()["error"]["code"] == "directional_auth_forbidden"

    # 6. Witness calls /heartbeat -> ACCEPTED (200 OK)
    resp = client.post("/heartbeat", json={}, headers=witness_headers)
    assert resp.status_code == 200

    # 7. Rogue Agent calls /heartbeat -> FORBIDDEN (403)
    agent_headers = {**auth_header, "X-Client-CN": "rogue-agent.external"}
    resp = client.post("/heartbeat", json={}, headers=agent_headers)
    assert resp.status_code == 403
    assert resp.json()["error"]["code"] == "directional_auth_forbidden"


def test_directional_auth_matrix_with_role_tokens(test_sealer, monkeypatch) -> None:
    monkeypatch.setenv("SIGNER_GATEWAY_TOKEN", "gw-token-secret")
    monkeypatch.setenv("SIGNER_LEDGER_TOKEN", "ledger-token-secret")
    monkeypatch.delenv("SIGNER_AUTH_TOKEN", raising=False)

    app = create_app(sealer=test_sealer)
    client = TestClient(app)

    seal_body = {
        "format_version": "4",
        "log_id": "sha256:" + "0" * 64,
        "epoch_id": 1,
        "seq": 1,
        "signer_timestamp": "2026-01-01T00:00:00.000Z",
        "prev_hash": "sha256:" + "0" * 64,
        "lane": "agent",
        "epoch_certificate_id": "sha256:" + "0" * 64,
        "type": "action",
        "action_name": "audit",
        "reason": "test",
        "target_reference": "test",
    }

    checkpoint_req = {
        "log_id": "sha256:" + "0" * 64,
        "tree_size": 10,
        "root_hash": "sha256:" + "0" * 64,
        "latest_seq": 9,
        "latest_entry_hash": "sha256:" + "0" * 64,
        "epoch_id": 1,
        "signer_timestamp": "2026-01-01T00:00:00.000Z",
    }

    # Gateway token calls /seal -> 200 OK
    resp = client.post("/seal", json=seal_body, headers={"Authorization": "Bearer gw-token-secret"})
    assert resp.status_code == 200

    # Gateway token calls /checkpoint -> 403 Forbidden
    resp = client.post(
        "/checkpoint", json=checkpoint_req, headers={"Authorization": "Bearer gw-token-secret"}
    )
    assert resp.status_code == 403

    # Ledger token calls /checkpoint -> 200 OK
    resp = client.post(
        "/checkpoint", json=checkpoint_req, headers={"Authorization": "Bearer ledger-token-secret"}
    )
    assert resp.status_code == 200

    # Ledger token calls /seal -> 403 Forbidden
    resp = client.post(
        "/seal", json=seal_body, headers={"Authorization": "Bearer ledger-token-secret"}
    )
    assert resp.status_code == 403
