"""Versioned durable witness state and append-only refusal evidence."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

from libs.blackbox_core.canonical import canonicalize
from libs.blackbox_core.schemas import Checkpoint, Cosignature

FORMAT_VERSION = "1"


class WitnessStoreError(ValueError):
    pass


class WitnessStore:
    format_version = FORMAT_VERSION

    def __init__(self, state_dir: Path, evidence_dir: Path) -> None:
        self.state_dir = state_dir
        self.evidence_dir = evidence_dir
        self.state_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.evidence_dir.mkdir(mode=0o700, parents=True, exist_ok=True)

    def state_path(self, log_id: str) -> Path:
        return self.state_dir / f"{log_id}.json"

    def initialized_path(self, log_id: str) -> Path:
        return self.state_dir / f"{log_id}.initialized"

    def evidence_path(self, log_id: str) -> Path:
        return self.evidence_dir / f"{log_id}.jsonl"

    def read(self, log_id: str) -> dict[str, object] | None:
        path = self.state_path(log_id)
        if not path.exists():
            if self.initialized_path(log_id).exists():
                raise WitnessStoreError("witness state is missing")
            return None
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            raise WitnessStoreError("witness state is corrupt") from exc
        if not isinstance(raw, dict) or raw.get("format_version") != FORMAT_VERSION:
            raise WitnessStoreError("witness state version is unsupported")
        return raw

    def commit(self, checkpoint: Checkpoint, cosignature: Cosignature) -> None:
        payload = {
            "format_version": FORMAT_VERSION,
            "log_id": checkpoint.log_id,
            "tree_size": checkpoint.tree_size,
            "root_hash": checkpoint.root_hash,
            "epoch_id": checkpoint.epoch_id,
            "checkpoint": checkpoint.model_dump(mode="json"),
            "cosignature": cosignature.model_dump(mode="json"),
        }
        self._atomic_write(self.state_path(checkpoint.log_id), canonicalize(payload))
        self._atomic_write(self.initialized_path(checkpoint.log_id), b"1\n")

    def append_refusal(self, log_id: str, code: str, checkpoint: object) -> None:
        path = self.evidence_path(log_id)
        previous = "sha256:" + "0" * 64
        if path.exists():
            try:
                last = json.loads(path.read_text(encoding="utf-8").splitlines()[-1])
                previous = last["record_hash"]
            except (OSError, ValueError, KeyError) as exc:
                raise WitnessStoreError("witness evidence is corrupt") from exc
        record = {
            "format_version": FORMAT_VERSION,
            "code": code,
            "checkpoint": checkpoint,
            "prev_hash": previous,
        }
        record_hash = "sha256:" + hashlib.sha256(canonicalize(record)).hexdigest()
        line = canonicalize({**record, "record_hash": record_hash}) + b"\n"
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        with os.fdopen(fd, "ab") as stream:
            stream.write(line)
            stream.flush()
            os.fsync(stream.fileno())

    @staticmethod
    def _atomic_write(path: Path, data: bytes) -> None:
        temporary = path.with_name(f".{path.name}.tmp")
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        directory_fd = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)


def last_checkpoint(log_id: str, *, store: WitnessStore) -> Checkpoint | None:
    raw = store.read(log_id)
    return None if raw is None else Checkpoint.model_validate(raw["checkpoint"])


def append_and_fsync(
    checkpoint: Checkpoint, cosignature: Cosignature, *, store: WitnessStore
) -> None:
    store.commit(checkpoint, cosignature)


def record_refusal(checkpoint: Checkpoint, reason: str, *, store: WitnessStore) -> None:
    store.append_refusal(checkpoint.log_id, reason, checkpoint.model_dump(mode="json"))
