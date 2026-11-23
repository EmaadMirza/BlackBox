"""Reconciler findings reporting CLI helper (spec §17.3)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import httpx

from libs.blackbox_core import schemas
from services.reconciler.findings_store import FindingsStore


def get_findings_from_store(store_path: Path) -> list[schemas.Finding]:
    """Load findings from a local FindingsStore JSON file."""
    if not store_path.exists():
        return []
    store = FindingsStore(store_path)
    return store.list_findings()


def get_findings_from_service(
    reconciler_url: str, token: str | None = None
) -> list[schemas.Finding]:
    """Query findings from a live Reconciler HTTP service."""
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    with httpx.Client(base_url=reconciler_url.rstrip("/"), headers=headers, timeout=5.0) as client:
        resp = client.get("/v1/findings")
        resp.raise_for_status()
        raw = resp.json()
        return [schemas.Finding.model_validate(item) for item in raw]


def generate_reconcile_report(
    *,
    store_path: Path | None = None,
    reconciler_url: str | None = None,
    token: str | None = None,
    output: Path | None = None,
) -> dict[str, Any]:
    """Assemble a consolidated reconciliation report from store or service."""
    findings: list[schemas.Finding] = []

    if reconciler_url:
        findings = get_findings_from_service(reconciler_url, token)
    elif store_path:
        findings = get_findings_from_store(store_path)
    else:
        # Check standard default paths
        for default_name in ("findings-store.json", "findings.json"):
            candidate = Path(default_name)
            if candidate.exists():
                findings = get_findings_from_store(candidate)
                break

    by_type: dict[str, int] = {}
    for f in findings:
        by_type[f.finding_type] = by_type.get(f.finding_type, 0) + 1

    report = {
        "total_findings": len(findings),
        "by_type": by_type,
        "findings": [f.model_dump() for f in findings],
    }

    if output is not None:
        output.parent.mkdir(parents=True, exist_ok=True)
        with open(output, "w", encoding="utf-8") as out_f:
            json.dump(report, out_f, indent=2)

    return report
