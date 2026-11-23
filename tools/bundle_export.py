"""Evidence bundle export CLI helper (spec §17.3)."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

import httpx


def export_bundle_from_ledger(
    ledger_url: str,
    start_seq: int = 0,
    end_seq: int | None = None,
    bearer_token: str | None = None,
) -> dict[str, Any]:
    """Fetch an evidence bundle from a running ledger service."""
    headers = {"Authorization": f"Bearer {bearer_token}"} if bearer_token else {}
    with httpx.Client(base_url=ledger_url.rstrip("/"), headers=headers, timeout=10.0) as client:
        if end_seq is None:
            resp = client.get("/checkpoint/latest")
            if resp.status_code == 200:
                ckpt = resp.json()
                end_seq = ckpt.get("latest_seq", max(0, ckpt.get("tree_size", 1) - 1))
            else:
                end_seq = start_seq

        res = client.get("/bundle", params={"from": start_seq, "to": end_seq})
        if res.status_code != 200:
            raise RuntimeError(f"Ledger bundle export failed (HTTP {res.status_code}): {res.text}")
        return res.json()


def export_bundle_from_db(
    dsn: str,
    start_seq: int = 0,
    end_seq: int | None = None,
    log_name: str = "",
    log_id: str | None = None,
    witness_set: Any | None = None,
) -> dict[str, Any]:
    """Assemble an evidence bundle directly from a PostgreSQL database."""
    from services.ledger import bundle_export, db

    pool = db.connect(dsn)
    try:
        if end_seq is None:
            with pool.connection() as conn:
                row = conn.execute("SELECT COALESCE(MAX(seq), 0) FROM blackbox.entries").fetchone()
                end_seq = row[0] if row else start_seq

        bundle = bundle_export.build_bundle(
            pool,
            start_seq,
            end_seq,
            log_name=log_name,
            witness_set=witness_set,
            log_id=log_id,
        )
        return bundle.model_dump(mode="json")
    finally:
        pool.close()


def export_bundle(
    *,
    start_seq: int = 0,
    end_seq: int | None = None,
    output: Path | None = None,
    ledger_url: str | None = None,
    bearer_token: str | None = None,
    dsn: str | None = None,
    log_name: str = "",
    log_id: str | None = None,
    witness_set: Any | None = None,
) -> dict[str, Any]:
    """Export evidence bundle from ledger HTTP endpoint or PostgreSQL database."""
    dsn = dsn or os.environ.get("LEDGER_DATABASE_URL")
    ledger_url = ledger_url or os.environ.get("LEDGER_URL")
    token = bearer_token or os.environ.get("LEDGER_BEARER_TOKEN", "test-token")

    if ledger_url:
        data = export_bundle_from_ledger(ledger_url, start_seq, end_seq, token)
    elif dsn:
        data = export_bundle_from_db(
            dsn,
            start_seq,
            end_seq,
            log_name=log_name,
            log_id=log_id,
            witness_set=witness_set,
        )
    else:
        # Default to local ledger port
        default_url = "http://localhost:8002"
        data = export_bundle_from_ledger(default_url, start_seq, end_seq, token)

    if output is not None:
        output.parent.mkdir(parents=True, exist_ok=True)
        with open(output, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)

    return data
