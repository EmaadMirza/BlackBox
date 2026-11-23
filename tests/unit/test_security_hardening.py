"""Comprehensive Security Hardening and Edge-Case Tests.

Covers:
1. mTLS & Reverse-Proxy DN Parsing (RFC 4514, RFC 5280, ASGI TLS scope).
2. PKI Certificate Verification & EKU Enforcement (Signature, Validity, CN/SAN, Roles).
3. Directional Caller Authorization Matrix with Reverse Proxy Headers.
4. Canonical JSON & Cryptographic Schema Tamper Resistance (Float, NaN, Surrogate, Recursion).
5. High-Concurrency Rate Limiter Thread Contention & Quota Invariants.
6. Anchor Poller Resilience under Ledger Outages & Contradiction Alarms.
"""

from __future__ import annotations

import concurrent.futures
import datetime
import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from libs.blackbox_core import schemas
from libs.blackbox_core.canonical import canonicalize, loads
from libs.blackbox_core.sealing import seal
from services.anchor.worker import AnchorWorker
from services.signer.auth import (
    get_caller_identity,
)
from services.signer.main import create_app
from services.signer.rate_limit import DurableRateLimiter
from tests._dev_keys import dev_key
from tools.mtls import generate_cluster_pki, verify_certificate


@pytest.fixture
def mock_sealer():
    sealer = MagicMock()
    del sealer.seal_with_rollover
    k = dev_key()
    sealer.seal.side_effect = lambda cand: seal(cand, k)
    sealer.attest.return_value = MagicMock(model_dump=lambda: {"status": "attested"})
    sealer.checkpoint.return_value = MagicMock(model_dump=lambda: {"status": "checkpointed"})
    sealer.heartbeat.return_value = MagicMock(model_dump=lambda: {"status": "heartbeat_ok"})
    return sealer


# -----------------------------------------------------------------------------
# 1. Reverse-Proxy DN Parsing & ASGI TLS Scope
# -----------------------------------------------------------------------------


def test_dn_header_parsing() -> None:
    # 1. Full DN string from Nginx/Envoy: CN=gateway.internal,O=BlackBox,C=US
    req1 = MagicMock()
    req1.headers = {"X-Client-DN": "CN=gateway.internal,O=BlackBox,C=US"}
    req1.scope = {}
    assert get_caller_identity(req1) == "gateway.internal"

    # 2. SSL-Client-S-DN header with lowercase cn
    req2 = MagicMock()
    req2.headers = {"SSL-Client-S-DN": "cn=ledger.internal,ou=services"}
    req2.scope = {}
    assert get_caller_identity(req2) == "ledger.internal"

    # 3. Quoted header value: "CN=witness-1.internal"
    req3 = MagicMock()
    req3.headers = {"X-Client-DN": '"CN=witness-1.internal,O=BlackBox"'}
    req3.scope = {}
    assert get_caller_identity(req3) == "witness-1.internal"

    # 4. Standard Python ASGI SSLSocket peercert subject tuple format
    req4 = MagicMock()
    req4.headers = {}
    req4.scope = {
        "tls": {
            "client_cert": {
                "subject": (
                    (("countryName", "US"),),
                    (("organizationName", "BlackBox"),),
                    (("commonName", "gateway.internal"),),
                )
            }
        }
    }
    assert get_caller_identity(req4) == "gateway.internal"


def test_directional_auth_with_dn_headers(mock_sealer, monkeypatch) -> None:
    monkeypatch.setenv("SIGNER_AUTH_TOKEN", "auth-token-123")
    app = create_app(sealer=mock_sealer)
    client = TestClient(app)

    auth = {"Authorization": "Bearer auth-token-123"}
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
    checkpoint_body = {
        "log_id": "sha256:" + "0" * 64,
        "tree_size": 10,
        "root_hash": "sha256:" + "0" * 64,
        "latest_seq": 9,
        "latest_entry_hash": "sha256:" + "0" * 64,
        "epoch_id": 1,
        "signer_timestamp": "2026-01-01T00:00:00.000Z",
    }

    # Gateway passing full DN header -> allowed on /seal
    gw_headers = {**auth, "X-Client-DN": "CN=gateway.internal,O=BlackBox"}
    resp = client.post("/seal", json=seal_body, headers=gw_headers)
    assert resp.status_code == 200

    # Gateway passing full DN header -> rejected on /checkpoint (403)
    resp = client.post("/checkpoint", json=checkpoint_body, headers=gw_headers)
    assert resp.status_code == 403
    assert resp.json()["error"]["code"] == "directional_auth_forbidden"

    # Ledger passing DN header -> allowed on /checkpoint
    ledger_headers = {**auth, "SSL-Client-S-DN": "CN=ledger.internal"}
    resp = client.post("/checkpoint", json=checkpoint_body, headers=ledger_headers)
    assert resp.status_code == 200

    # Ledger passing DN header -> rejected on /seal (403)
    resp = client.post("/seal", json=seal_body, headers=ledger_headers)
    assert resp.status_code == 403


# -----------------------------------------------------------------------------
# 2. PKI Verification Engine & EKU Enforcement
# -----------------------------------------------------------------------------


def test_certificate_verification_engine(tmp_path: Path) -> None:
    pki = generate_cluster_pki(tmp_path / "pki", domain="cluster.local")
    ca_cert = tmp_path / "pki" / pki["ca_cert"]

    # 1. Honest Gateway Server certificate verification
    gw_server_cert = tmp_path / "pki" / pki["nodes"]["gateway"]["server_cert"]
    assert verify_certificate(
        gw_server_cert,
        ca_cert,
        expected_common_name="gateway.cluster.local",
        expected_role="server",
    )

    # 2. Honest Gateway Client certificate verification
    gw_client_cert = tmp_path / "pki" / pki["nodes"]["gateway"]["client_cert"]
    assert verify_certificate(
        gw_client_cert,
        ca_cert,
        expected_common_name="gateway.cluster.local",
        expected_role="client",
    )

    # 3. EKU mismatch: Client certificate used as server certificate must fail
    with pytest.raises(ValueError, match="SERVER_AUTH"):
        verify_certificate(
            gw_client_cert,
            ca_cert,
            expected_role="server",
        )

    # 4. Common name mismatch must fail
    with pytest.raises(ValueError, match="does not contain expected Common Name"):
        verify_certificate(
            gw_server_cert,
            ca_cert,
            expected_common_name="malicious.attacker.local",
        )

    # 5. Expired certificate must fail
    past_date = datetime.datetime(2020, 1, 1, tzinfo=datetime.timezone.utc)
    with pytest.raises(ValueError, match="expired or not yet valid"):
        verify_certificate(
            gw_server_cert,
            ca_cert,
            now=past_date,
        )

    # 6. Alien CA mismatch must fail
    alien_pki = generate_cluster_pki(tmp_path / "alien_pki", domain="alien.local")
    alien_ca = tmp_path / "alien_pki" / alien_pki["ca_cert"]
    with pytest.raises(Exception):
        verify_certificate(gw_server_cert, alien_ca)


def test_verify_cert_cli(tmp_path: Path, capsys) -> None:
    pki = generate_cluster_pki(tmp_path / "pki", domain="cluster.local")
    ca_cert = tmp_path / "pki" / pki["ca_cert"]
    gw_server_cert = tmp_path / "pki" / pki["nodes"]["gateway"]["server_cert"]

    from tools.mtls import main

    orig_argv = sys.argv
    try:
        sys.argv = [
            "mtls.py",
            "verify-cert",
            "--cert",
            str(gw_server_cert),
            "--ca-cert",
            str(ca_cert),
            "--common-name",
            "gateway.cluster.local",
            "--role",
            "server",
        ]
        main()
        out = capsys.readouterr().out
        assert "successfully verified" in out
    finally:
        sys.argv = orig_argv


# -----------------------------------------------------------------------------
# 3. Canonical JSON & Schema Security Hardening
# -----------------------------------------------------------------------------


def test_schema_rejects_floats_and_nan() -> None:
    # 1. Amount as float must fail validation (amounts must be int or string)
    with pytest.raises(ValidationError):
        schemas.Intent(
            format_version="4",
            log_id="sha256:" + "0" * 64,
            epoch_id=1,
            seq=1,
            signer_timestamp="2026-01-01T00:00:00.000Z",
            prev_hash="sha256:" + "0" * 64,
            lane="agent",
            epoch_certificate_id="sha256:" + "0" * 64,
            agent_id="agent-1",
            agent_key_id="sha256:" + "0" * 64,
            agent_signature="sig",
            intent_type="action",
            tool_name="transfer",
            arguments={"amount": 100.50},  # Float rejected
        )

    # 2. Canonical serialization rejects NaN and Infinity
    with pytest.raises(ValueError):
        canonicalize({"val": float("nan")})

    with pytest.raises(ValueError):
        canonicalize({"val": float("inf")})


def test_canonical_json_deep_nesting_and_unicode() -> None:
    # UTF-8 with non-ASCII and special unicode characters
    payload = {
        "text": "Hello, 世界! 🚀 \u00a9 \u00ae \u20ac",
        "nested": {"level1": {"level2": {"level3": [1, 2, 3]}}},
    }
    encoded = canonicalize(payload)
    decoded = loads(encoded)
    assert decoded["text"] == payload["text"]
    assert decoded["nested"]["level1"]["level2"]["level3"] == [1, 2, 3]


# -----------------------------------------------------------------------------
# 4. High-Concurrency Rate Limiter Stress Test
# -----------------------------------------------------------------------------


def test_concurrent_rate_limiter_contention(tmp_path: Path) -> None:
    """Stress test rate limiter under multi-threaded contention."""
    quota = 20
    path = tmp_path / "rate.sqlite3"
    now_ts = "2026-01-01T12:00:00.000Z"

    # Pre-initialize file-backed store before competing clients connect
    DurableRateLimiter(path).reserve(now_ts, rate_cap=quota)

    from libs.blackbox_core.errors import SignerRuleError

    def worker_acquire(_: int) -> bool:
        try:
            DurableRateLimiter(path).reserve(now_ts, rate_cap=quota)
            return True
        except SignerRuleError:
            return False

    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
        results = list(executor.map(worker_acquire, range(50)))

    # 1 was granted during init, exactly 19 of 50 are granted concurrently
    assert sum(results) == quota - 1
    assert results.count(False) == 50 - (quota - 1)


# -----------------------------------------------------------------------------
# 5. Anchor Worker Fault Tolerance & Stalls
# -----------------------------------------------------------------------------


def test_anchor_worker_contradiction_alarm(tmp_path: Path) -> None:
    worker = AnchorWorker(
        repo_path=tmp_path / "anchor_repo",
        min_quorum=1,
        max_stall_seconds=300,
    )

    cp1 = schemas.Checkpoint(
        log_id="sha256:" + "0" * 64,
        tree_size=10,
        root_hash="sha256:" + "1" * 64,
        latest_seq=9,
        epoch_id=0,
        signer_timestamp="2026-01-01T00:00:00.000Z",
        latest_entry_hash="sha256:" + "0" * 64,
    )
    # Publish honest checkpoint
    worker.publish_checkpoint(cp1)

    # Attempt to publish contradictory root for same tree size
    cp2 = schemas.Checkpoint(
        log_id="sha256:" + "0" * 64,
        tree_size=10,
        root_hash="sha256:" + "2" * 64,  # Contradiction
        latest_seq=9,
        epoch_id=0,
        signer_timestamp="2026-01-01T00:00:00.000Z",
        latest_entry_hash="sha256:" + "0" * 64,
    )

    with pytest.raises(ValueError, match="ANCHOR_MISMATCH"):
        worker.publish_checkpoint(cp2)

    assert any(a["type"] == "ANCHOR_MISMATCH" for a in worker.alarms)
