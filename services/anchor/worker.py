"""Anchor poller worker with ANCHOR_STALL and ANCHOR_MISMATCH telemetry (spec §12)."""

from __future__ import annotations

import asyncio
import os
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import httpx

from libs.blackbox_core import schemas
from services.anchor.git_backend import GitAnchorBackend
from services.anchor.ots_backend import OpenTimestampsAdapter


class AnchorWorker:
    """Polls latest witnessed checkpoints, publishes anchors, and detects stalls/mismatches."""

    def __init__(
        self,
        *,
        ledger_url: str = "http://ledger:8000",
        bearer_token: str | None = None,
        git_backend: GitAnchorBackend | None = None,
        ots_backend: OpenTimestampsAdapter | None = None,
        alarm_collector: Any = None,
        alarm_url: str | None = None,
        repo_path: Path | None = None,
        poll_interval_seconds: int = 300,
        max_stall_seconds: int = 600,
        min_quorum: int = 2,
    ) -> None:
        self.ledger_url = ledger_url.rstrip("/")
        self.bearer_token = (
            bearer_token if bearer_token is not None else os.environ.get("LEDGER_BEARER_TOKEN", "")
        )
        self.bearer_token = (
            bearer_token if bearer_token is not None else os.environ.get("LEDGER_BEARER_TOKEN", "")
        )
        self.git_backend = git_backend or GitAnchorBackend(
            repo_path or Path("/tmp/blackbox_anchors_git")
        )
        self.ots_backend = ots_backend or OpenTimestampsAdapter()
        self.alarm_collector = alarm_collector
        self.alarm_url = alarm_url
        self.poll_interval = poll_interval_seconds
        self.max_stall = max_stall_seconds
        self.min_quorum = min_quorum

        self.last_anchored_tree_size: int = 0
        self.last_anchored_time: float = time.time()
        self.alarms: list[dict[str, Any]] = []
        self._running: bool = False

    def emit_alarm(self, alarm_type: str, evidence: str, severity: str = "low") -> dict[str, Any]:
        """Record alarm locally and dispatch to alerting collector."""
        now_iso = datetime.now(timezone.utc).isoformat()
        alarm = {
            "type": alarm_type,
            "source": "anchor-service",
            "severity": severity,
            "evidence_reference": evidence,
            "time": now_iso,
        }
        # Prevent runaway local duplicates of the exact same alarm state
        if not any(
            a["type"] == alarm_type and a["evidence_reference"] == evidence for a in self.alarms
        ):
            self.alarms.append(alarm)

        # 1. In-process collector dispatch
        if self.alarm_collector is not None and hasattr(self.alarm_collector, "collect"):
            self.alarm_collector.collect(
                alarm_type=alarm_type,
                source="anchor-service",
                evidence_reference=evidence,
                severity=severity,
                timestamp=now_iso,
            )

        # 2. HTTP Alerting service dispatch
        if self.alarm_url:
            try:
                httpx.post(f"{self.alarm_url.rstrip('/')}/alarms", json=alarm, timeout=2.0)
            except Exception:
                pass

        return alarm

    def _auth_headers(self) -> dict[str, str]:
        if self.bearer_token:
            return {"Authorization": f"Bearer {self.bearer_token}"}
        return {}

    async def fetch_latest_checkpoint(
        self, client: httpx.AsyncClient | None = None
    ) -> schemas.Checkpoint | None:
        """Fetch latest witnessed checkpoint from ledger service."""
        headers = self._auth_headers()
        try:
            if client is not None:
                res = await client.get(f"{self.ledger_url}/checkpoints/latest", headers=headers)
                if res.status_code == 200:
                    return schemas.Checkpoint.model_validate(res.json())
                res2 = await client.get(f"{self.ledger_url}/checkpoint/latest", headers=headers)
                if res2.status_code == 200:
                    return schemas.Checkpoint.model_validate(res2.json())
                return None

            async with httpx.AsyncClient(timeout=5.0) as http_client:
                res = await http_client.get(
                    f"{self.ledger_url}/checkpoints/latest", headers=headers
                )
                if res.status_code == 200:
                    return schemas.Checkpoint.model_validate(res.json())
                res2 = await http_client.get(
                    f"{self.ledger_url}/checkpoint/latest", headers=headers
                )
                if res2.status_code == 200:
                    return schemas.Checkpoint.model_validate(res2.json())
        except Exception:
            pass
        return None

    async def fetch_latest_witnessed(
        self, client: httpx.AsyncClient | None = None
    ) -> tuple[schemas.Checkpoint | None, list[Any] | None]:
        """Fetch latest witnessed checkpoint with its cosignatures from ledger service."""
        headers = self._auth_headers()
        try:
            url = f"{self.ledger_url}/checkpoint/witnessed"
            if client is not None:
                res = await client.get(url, headers=headers)
                if res.status_code == 200:
                    items = res.json()
                    if items and isinstance(items, list):
                        latest = items[-1]
                        cp = schemas.Checkpoint.model_validate(latest["checkpoint"])
                        cosigs = latest.get("cosignatures", [])
                        return cp, cosigs
                # Fallback to single checkpoint endpoint
                cp = await self.fetch_latest_checkpoint(client=client)
                return cp, None

            async with httpx.AsyncClient(timeout=5.0) as http_client:
                res = await http_client.get(url, headers=headers)
                if res.status_code == 200:
                    items = res.json()
                    if items and isinstance(items, list):
                        latest = items[-1]
                        cp = schemas.Checkpoint.model_validate(latest["checkpoint"])
                        cosigs = latest.get("cosignatures", [])
                        return cp, cosigs
                cp = await self.fetch_latest_checkpoint()
                return cp, None
        except Exception:
            pass
        return None, None

    def publish_checkpoint(
        self,
        checkpoint: schemas.Checkpoint,
        cosignatures: list[Any] | None = None,
    ) -> dict[str, Any]:
        """Publish a witnessed checkpoint to Git repository and OpenTimestamps."""
        # 1. Verification against previous published anchors for same tree size
        existing = self.git_backend.get_anchor_for_tree_size(checkpoint.tree_size)
        if existing is not None:
            if existing.get("root_hash") != checkpoint.root_hash:
                # Root hash contradiction: ANCHOR_MISMATCH!
                evidence = (
                    f"tree_size={checkpoint.tree_size} "
                    f"published_root={existing.get('root_hash')} "
                    f"checkpoint_root={checkpoint.root_hash}"
                )
                self.emit_alarm("ANCHOR_MISMATCH", evidence, severity="high")
                raise ValueError(f"ANCHOR_MISMATCH detected: {evidence}")

        # 2. Append to Git log & commit
        git_record = self.git_backend.append_checkpoint(checkpoint, cosignatures=cosignatures)

        # 3. Publish to OpenTimestamps / Bitcoin
        ots_receipt = self.ots_backend.anchor_checkpoint(checkpoint)

        # Update tracking
        self.last_anchored_tree_size = max(self.last_anchored_tree_size, checkpoint.tree_size)
        self.last_anchored_time = time.time()

        return {
            "status": "published",
            "tree_size": checkpoint.tree_size,
            "root_hash": checkpoint.root_hash,
            "git_commit": git_record.get("git_commit"),
            "ots": ots_receipt,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    def verify_checkpoint(self, checkpoint: schemas.Checkpoint) -> dict[str, Any]:
        """Verify a local witnessed checkpoint against external published anchors."""
        existing = self.git_backend.get_anchor_for_tree_size(checkpoint.tree_size)
        if existing is None:
            return {"verdict": "UNANCHORED", "tree_size": checkpoint.tree_size}

        if existing.get("root_hash") != checkpoint.root_hash:
            evidence = (
                f"tree_size={checkpoint.tree_size} "
                f"published_root={existing.get('root_hash')} "
                f"checkpoint_root={checkpoint.root_hash}"
            )
            self.emit_alarm("ANCHOR_MISMATCH", evidence, severity="high")
            return {
                "verdict": "MISMATCH",
                "published_root": existing.get("root_hash"),
                "checkpoint_root": checkpoint.root_hash,
                "evidence": evidence,
            }

        return {
            "verdict": "VERIFIED",
            "tree_size": checkpoint.tree_size,
            "root_hash": checkpoint.root_hash,
            "git_commit": existing.get("git_commit"),
        }

    async def poll_once(
        self,
        checkpoint: schemas.Checkpoint | None = None,
        cosignatures: list[Any] | None = None,
        client: httpx.AsyncClient | None = None,
    ) -> dict[str, Any] | None:
        """Execute a single polling and anchoring cycle."""
        if checkpoint is None:
            cp, fetched_cosigs = await self.fetch_latest_witnessed(client=client)
            if cosignatures is None:
                cosignatures = fetched_cosigs
        else:
            cp = checkpoint

        now = time.time()

        if cp is None:
            # Check for stall if ledger cannot be reached or has no checkpoints
            if now - self.last_anchored_time > self.max_stall:
                self.emit_alarm(
                    "ANCHOR_STALL",
                    f"tree_size={self.last_anchored_tree_size} stall_tolerance_seconds={self.max_stall} reason=checkpoint_unavailable",
                    severity="low",
                )
            return None

        # Check witness quorum if cosignatures provided
        if cosignatures is not None and len(cosignatures) < self.min_quorum:
            if now - self.last_anchored_time > self.max_stall:
                self.emit_alarm(
                    "ANCHOR_STALL",
                    f"tree_size={self.last_anchored_tree_size} stall_tolerance_seconds={self.max_stall} reason=insufficient_witness_quorum",
                    severity="low",
                )
            return None

        # Check for ANCHOR_MISMATCH if we already anchored this tree size
        existing = self.git_backend.get_anchor_for_tree_size(cp.tree_size)
        if existing and existing.get("root_hash") != cp.root_hash:
            evidence = (
                f"tree_size={cp.tree_size} "
                f"published_root={existing.get('root_hash')} "
                f"checkpoint_root={cp.root_hash}"
            )
            self.emit_alarm("ANCHOR_MISMATCH", evidence, severity="high")
            return {"status": "mismatch", "error": "ANCHOR_MISMATCH", "evidence": evidence}

        # Check if new tree size requires anchoring
        if cp.tree_size > self.last_anchored_tree_size:
            result = self.publish_checkpoint(cp, cosignatures=cosignatures)
            return result

        # Check stall if ledger has not advanced or time exceeded tolerance
        if now - self.last_anchored_time > self.max_stall:
            self.emit_alarm(
                "ANCHOR_STALL",
                f"tree_size={self.last_anchored_tree_size} stall_tolerance_seconds={self.max_stall} last_anchored_epoch={int(self.last_anchored_time)}",
                severity="low",
            )

        return {"status": "up_to_date", "tree_size": self.last_anchored_tree_size}

    async def run_loop(self) -> None:
        """Run continuous periodic polling loop."""
        self._running = True
        while self._running:
            try:
                await self.poll_once()
            except Exception:
                pass
            await asyncio.sleep(self.poll_interval)

    def stop(self) -> None:
        """Stop background worker loop."""
        self._running = False
