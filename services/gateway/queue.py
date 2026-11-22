"""Bounded disk queue and outage gap marker (spec §10.5, §13.7)."""

from __future__ import annotations

import json
from pathlib import Path

from libs.blackbox_core import schemas
from libs.blackbox_core.canonical import canonicalize
from libs.blackbox_core.chain import GENESIS_PREV_HASH


class GatewayLocalQueue:
    """Bounded local queue for low-risk actions during signer outages."""

    def __init__(self, queue_dir: Path, max_entries: int = 1000) -> None:
        self.queue_dir = Path(queue_dir)
        self.max_entries = max_entries
        self.queue_dir.mkdir(parents=True, exist_ok=True)

    def enqueue(self, candidate: schemas.Entry) -> Path:
        entries = list(self.queue_dir.glob("entry-*.json"))
        if len(entries) >= self.max_entries:
            raise OverflowError("Gateway local queue capacity exceeded")
        idx = len(entries)
        file_path = self.queue_dir / f"entry-{idx:08d}.json"
        data = candidate.model_dump(mode="json")
        file_path.write_bytes(canonicalize(data))
        return file_path

    def drain(self) -> list[schemas.Entry]:
        files = sorted(self.queue_dir.glob("entry-*.json"))
        items = []
        for f in files:
            data = json.loads(f.read_text(encoding="utf-8"))
            entry = schemas.parse_entry(data)
            items.append(entry)
            f.unlink()
        return items


def enqueue(candidate: schemas.Entry, queue_dir: Path | None = None) -> Path:
    q = GatewayLocalQueue(queue_dir or Path("/tmp/gateway_queue"))
    return q.enqueue(candidate)


async def drain(queue_dir: Path | None = None) -> list[schemas.Entry]:
    q = GatewayLocalQueue(queue_dir or Path("/tmp/gateway_queue"))
    return q.drain()


def gap(
    outage_start: str,
    outage_end: str,
    queued_entries: int,
    *,
    log_id: str = "sha256:" + "0" * 64,
    epoch_id: int = 0,
    seq: int = 0,
) -> schemas.Gap:
    """Construct an outage gap marker."""
    return schemas.Gap(
        format_version="4",
        log_id=log_id,
        epoch_id=epoch_id,
        seq=seq,
        signer_timestamp=outage_end,
        prev_hash=GENESIS_PREV_HASH,
        lane="web",
        epoch_certificate_id="sha256:" + "0" * 64,
        type="gap",
        outage_start=outage_start,
        outage_end=outage_end,
        queued_entries=queued_entries,
    )
