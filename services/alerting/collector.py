"""Alarm collector service Scaffold only; no runtime behavior."""

from __future__ import annotations

from fastapi import FastAPI

from libs.blackbox_core import schemas

# TODO(spec §17.1): implement and validate before enabling this module.


def create_app() -> FastAPI:
    raise NotImplementedError("not built")


async def health() -> dict[str, str]:
    raise NotImplementedError("not built")


async def collect(alarm_type: str, source: str, evidence_reference: str) -> None:
    raise NotImplementedError("not built")


async def collect_finding(finding: schemas.Finding) -> None:
    raise NotImplementedError("not built")
