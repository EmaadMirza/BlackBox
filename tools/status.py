"""System and component status reporting CLI helper (spec §17.3)."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

import httpx

from libs.blackbox_core.canonical import loads


def inspect_signer_dir(state_dir: Path) -> dict[str, Any]:
    """Inspect local signer state directory without networking."""
    state_file = state_dir / "state.json"
    if not state_file.exists():
        return {"status": "uninitialized", "path": str(state_dir)}

    try:
        raw_state = loads(state_file.read_bytes())
    except Exception as exc:
        return {"status": "corrupt", "error": str(exc), "path": str(state_dir)}

    quarantine_file = state_dir / "state.json.quarantine.json"
    is_quarantined = quarantine_file.exists()
    quarantine_reason = None
    if is_quarantined:
        try:
            quarantine_reason = json.loads(quarantine_file.read_text()).get("reason")
        except Exception:
            quarantine_reason = "quarantine file present"

    recovery_file = state_dir / "state.json.recovery.json"
    recovery_anchor = None
    if recovery_file.exists():
        try:
            recovery_anchor = json.loads(recovery_file.read_text())
        except Exception:
            pass

    journal_file = state_dir / "state.json.journal.log"
    journal_entries_count = 0
    if journal_file.exists():
        try:
            journal_entries_count = len(journal_file.read_text().strip().splitlines())
        except Exception:
            pass

    outbox_file = state_dir / "state.json.outbox.json"
    outbox_depth = 0
    if outbox_file.exists():
        try:
            outbox_depth = len(json.loads(outbox_file.read_text()).get("entries", []))
        except Exception:
            pass

    status_str = "quarantined" if is_quarantined else "ok"
    return {
        "status": status_str,
        "log_id": raw_state.get("log_id"),
        "seq": raw_state.get("seq"),
        "epoch_id": raw_state.get("epoch_id"),
        "latest_entry_hash": raw_state.get("latest_entry_hash"),
        "signer_timestamp": raw_state.get("signer_timestamp"),
        "quarantined": is_quarantined,
        "quarantine_reason": quarantine_reason,
        "recovery_anchor": recovery_anchor,
        "journal_entries": journal_entries_count,
        "outbox_depth": outbox_depth,
    }


def query_http_status(
    signer_url: str | None = None,
    ledger_url: str | None = None,
    witness_urls: list[str] | None = None,
    token: str | None = None,
    timeout: float = 3.0,
) -> dict[str, Any]:
    """Query live HTTP status from signer, ledger, and witness services."""
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    report: dict[str, Any] = {"signer": None, "ledger": None, "witnesses": []}

    # 1. Signer
    if signer_url:
        try:
            with httpx.Client(
                base_url=signer_url.rstrip("/"), headers=headers, timeout=timeout
            ) as c:
                res = c.get("/health")
                report["signer"] = (
                    res.json()
                    if res.status_code == 200
                    else {"status": f"HTTP {res.status_code}", "detail": res.text}
                )
        except Exception as exc:
            report["signer"] = {"status": "unreachable", "error": str(exc)}

    # 2. Ledger
    if ledger_url:
        try:
            with httpx.Client(
                base_url=ledger_url.rstrip("/"), headers=headers, timeout=timeout
            ) as c:
                health_res = c.get("/health")
                ckpt_res = c.get("/checkpoint/latest")
                witnessed_res = c.get("/checkpoint/witnessed")

                ledger_info: dict[str, Any] = {
                    "health": health_res.json()
                    if health_res.status_code == 200
                    else {"status": f"HTTP {health_res.status_code}"},
                    "latest_checkpoint": ckpt_res.json() if ckpt_res.status_code == 200 else None,
                    "latest_witnessed": witnessed_res.json()
                    if witnessed_res.status_code == 200
                    else None,
                }
                report["ledger"] = ledger_info
        except Exception as exc:
            report["ledger"] = {"status": "unreachable", "error": str(exc)}

    # 3. Witnesses
    if witness_urls:
        for w_url in witness_urls:
            try:
                with httpx.Client(
                    base_url=w_url.rstrip("/"), headers=headers, timeout=timeout
                ) as c:
                    w_health = c.get("/health")
                    w_latest = c.get("/v1/latest")
                    w_alarms = c.get("/v1/alarms")
                    report["witnesses"].append(
                        {
                            "url": w_url,
                            "health": w_health.json()
                            if w_health.status_code == 200
                            else f"HTTP {w_health.status_code}",
                            "latest": w_latest.json() if w_latest.status_code == 200 else None,
                            "alarms": w_alarms.json() if w_alarms.status_code == 200 else [],
                        }
                    )
            except Exception as exc:
                report["witnesses"].append(
                    {"url": w_url, "status": "unreachable", "error": str(exc)}
                )

    return report


def get_status(
    *,
    signer_url: str | None = None,
    ledger_url: str | None = None,
    witness_urls: list[str] | str | None = None,
    signer_state_dir: Path | None = None,
    token: str | None = None,
    output: Path | None = None,
) -> dict[str, Any]:
    """Compile and return comprehensive status of BlackBox components."""
    status_data: dict[str, Any] = {"status": "ok"}

    if signer_state_dir is not None:
        status_data["signer_offline"] = inspect_signer_dir(signer_state_dir)
        if status_data["signer_offline"].get("status") != "ok":
            status_data["status"] = "degraded"

    token = token or os.environ.get("BEARER_TOKEN", "test-token")
    signer_url = signer_url or os.environ.get("SIGNER_URL")
    ledger_url = ledger_url or os.environ.get("LEDGER_URL")

    w_urls: list[str] = []
    if isinstance(witness_urls, str):
        w_urls = [u.strip() for u in witness_urls.split(",") if u.strip()]
    elif isinstance(witness_urls, list):
        w_urls = witness_urls
    elif os.environ.get("WITNESS_URLS"):
        w_urls = [u.strip() for u in os.environ["WITNESS_URLS"].split(",") if u.strip()]

    if signer_url or ledger_url or w_urls:
        online_info = query_http_status(signer_url, ledger_url, w_urls, token)
        status_data.update(online_info)

    if output is not None:
        output.parent.mkdir(parents=True, exist_ok=True)
        with open(output, "w", encoding="utf-8") as f:
            json.dump(status_data, f, indent=2)

    return status_data
