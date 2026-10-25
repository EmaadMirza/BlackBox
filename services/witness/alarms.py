"""Durable, deduplicated witness refusal alarms."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

from libs.blackbox_core.canonical import canonicalize


class AlarmStore:
    def __init__(self, directory: Path) -> None:
        self.directory = directory
        self.directory.mkdir(mode=0o700, parents=True, exist_ok=True)

    def path(self, log_id: str) -> Path:
        return self.directory / f"{log_id}.alarms.jsonl"

    def record(self, log_id: str, alarm_type: str, evidence_reference: str, timestamp: str) -> None:
        path = self.path(log_id)
        existing = self.list(log_id)
        identity = hashlib.sha256(
            canonicalize({"alarm_type": alarm_type, "evidence_reference": evidence_reference})
        ).hexdigest()
        if any(item.get("alarm_id") == identity for item in existing):
            return
        record = {
            "format_version": "1",
            "alarm_id": identity,
            "alarm_type": alarm_type,
            "evidence_reference": evidence_reference,
            "raised_at": timestamp,
        }
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        with os.fdopen(fd, "ab") as stream:
            stream.write(canonicalize(record) + b"\n")
            stream.flush()
            os.fsync(stream.fileno())

    def list(self, log_id: str) -> list[dict[str, object]]:
        path = self.path(log_id)
        if not path.exists():
            return []
        return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]


def emit(
    alarm_type: str, evidence_reference: str, *, store: AlarmStore, log_id: str, timestamp: str
) -> None:
    store.record(log_id, alarm_type, evidence_reference, timestamp)
