"""Unit tests for Gateway peripheral modules (broker, queue, payload_client, baseline)."""

from __future__ import annotations

import asyncio
from pathlib import Path

from baseline.plain_log import append as plain_append
from libs.blackbox_core import schemas
from libs.blackbox_core.chain import GENESIS_PREV_HASH
from services.gateway.broker import broker_headers
from services.gateway.queue import GatewayLocalQueue, gap


def test_broker_headers_strips_credentials_and_injects_brokered_token() -> None:
    """Agent credentials are removed and scoped tool token is injected."""
    agent_headers = {
        "Authorization": "Bearer agent-secret-token",
        "Cookie": "session=12345",
        "X-Api-Key": "agent-api-key",
        "X-Request-Id": "req-999",
        "Content-Type": "application/json",
    }

    async def _test() -> None:
        brokered = await broker_headers(
            agent_headers,
            "read_invoice",
            brokered_tokens={"read_invoice": "scoped-invoice-read-token"},
        )
        # Agent credentials stripped
        assert "Cookie" not in brokered
        assert "X-Api-Key" not in brokered
        # Safe headers preserved
        assert brokered["X-Request-Id"] == "req-999"
        assert brokered["Content-Type"] == "application/json"
        # Brokered token injected
        assert brokered["Authorization"] == "Bearer scoped-invoice-read-token"

    asyncio.run(_test())


def test_gateway_local_queue_and_gap_marker(tmp_path: Path) -> None:
    """Queue stores candidates locally and gap marker documents outage."""
    q = GatewayLocalQueue(tmp_path / "queue", max_entries=5)

    entry = schemas.Blocked(
        format_version="4",
        log_id="sha256:" + "0" * 64,
        epoch_id=0,
        seq=0,
        signer_timestamp="2026-01-01T00:00:00.000Z",
        prev_hash=GENESIS_PREV_HASH,
        lane="web",
        epoch_certificate_id="sha256:" + "0" * 64,
        principal=schemas.Principal(
            client_key_id="agent-1",
            source_address="gateway",
            human_identity="agent-1",
            agent_identity="agent-1",
            agent_version="1",
            delegation_chain=["token-1"],
        ),
        action=schemas.RequestAction(
            adapter="http",
            method="POST",
            path="/refund",
            tool_name="refund",
            body_digest="sha256:" + "0" * 64,
            arguments_commitment="sha256:" + "1" * 64,
            idempotency_key="sha256:" + "2" * 64,
            payload_reference="ref-1",
        ),
        policy=schemas.Policy(
            version="dev-1",
            decision="block",
            matching_rule_id="r1",
            severity="high",
            approval_receipt_id=None,
        ),
        context=None,
        claimed_time="2026-01-01T00:00:00.000Z",
        type="blocked",
        reason="rate_limit",
    )

    path = q.enqueue(entry)
    assert path.exists()

    drained = q.drain()
    assert len(drained) == 1
    assert not path.exists()

    g = gap("2026-01-01T00:00:00.000Z", "2026-01-01T00:05:00.000Z", 1)
    assert isinstance(g, schemas.Gap)
    assert g.queued_entries == 1


def test_plain_log_baseline(tmp_path: Path) -> None:
    """Plain file log appends unauthenticated bytes."""
    log_file = tmp_path / "plain.log"
    plain_append(log_file, b'{"event":"test_line_1"}')
    plain_append(log_file, b'{"event":"test_line_2"}')

    lines = log_file.read_bytes().splitlines()
    assert len(lines) == 2
    assert lines[0] == b'{"event":"test_line_1"}'
    assert lines[1] == b'{"event":"test_line_2"}'
