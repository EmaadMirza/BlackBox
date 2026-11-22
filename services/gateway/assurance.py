"""Witness coverage and fail-closed wait (spec §13.6)."""

from __future__ import annotations

import asyncio
import os

import httpx

from libs.blackbox_core import schemas


async def wait_for_coverage(
    intent_seq: int,
    timeout_seconds: int = 10,
    *,
    ledger_url: str | None = None,
    poll_interval: float = 0.5,
) -> schemas.Checkpoint:
    """Poll ledger for a witnessed checkpoint covering intent_seq up to timeout."""
    url = (ledger_url or os.environ.get("LEDGER_URL", "http://ledger:8000")).rstrip("/")
    loop = asyncio.get_event_loop()
    start_time = loop.time()

    async with httpx.AsyncClient(timeout=poll_interval) as client:
        while loop.time() - start_time < timeout_seconds:
            try:
                res = await client.get(f"{url}/v1/checkpoints/latest")
                if res.status_code == 200:
                    data = res.json()
                    cp = schemas.Checkpoint.model_validate(data)
                    # Check tree size covers intent_seq and quorum is present
                    if cp.tree_size > intent_seq and len(cp.witness_cosignatures) >= 2:
                        return cp
            except Exception:
                pass
            await asyncio.sleep(poll_interval)

    raise TimeoutError(
        f"High-risk intent seq {intent_seq} not covered within {timeout_seconds}s timeout"
    )
