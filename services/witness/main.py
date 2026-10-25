"""Independent, file-backed witness service."""

from __future__ import annotations

import hmac
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from libs.blackbox_core.checkpoint import build_cosignature, verify_checkpoint
from libs.blackbox_core.encoding import decode_base64url, decode_hash, format_timestamp
from libs.blackbox_core.epochs import validate_contiguity, verify_epoch_certificate
from libs.blackbox_core.heartbeat import heartbeat_matches_checkpoint, verify_heartbeat
from libs.blackbox_core.merkle import verify_consistency
from libs.blackbox_core.schemas import (
    Checkpoint,
    Cosignature,
    EpochCertificate,
    Heartbeat,
    IntermediateCertificate,
    WitnessSet,
)
from libs.blackbox_core.signing import structure_hash
from libs.blackbox_core.witness_set import verify_witness_set
from services.witness.alarms import AlarmStore, emit
from services.witness.store import WitnessStore, WitnessStoreError

MAX_BODY = 2 * 1024 * 1024


class CheckpointSubmission(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    log_id: str
    checkpoint: Checkpoint
    from_size: int = Field(ge=0)
    consistency_proof: list[str]


@dataclass(frozen=True)
class WitnessConfig:
    root_public_key: str
    witness_set: WitnessSet
    intermediates: list[IntermediateCertificate]
    epochs: list[EpochCertificate]
    witness_id: str
    witness_key_path: Path
    state_dir: Path
    evidence_dir: Path
    alarm_dir: Path | None = None
    bearer_token: str = ""
    clock: Any = None
    heartbeat_interval_seconds: int = 5
    heartbeat_tolerance: int = 3


class WitnessKey:
    def __init__(self, operation: Ed25519PrivateKey) -> None:
        self.operation = operation

    @classmethod
    def load(cls, path: Path) -> "WitnessKey":
        if path.stat().st_mode & 0o077:
            raise ValueError("witness key must have 0600 permissions")
        data = path.read_bytes()
        if len(data) != 32:
            raise ValueError("witness key is invalid")
        return cls(Ed25519PrivateKey.from_private_bytes(data))


class WitnessRefusal(Exception):
    def __init__(self, code: str) -> None:
        self.code = code


def create_app(config: WitnessConfig | None = None, **legacy: Any) -> FastAPI:
    if config is None:
        key = legacy.pop("witness_key", None)
        if key is None:
            raise TypeError("witness configuration is required")
        state_dir = legacy.pop("state_dir", Path("witness-state"))
        key_path = legacy.pop("key_path", state_dir / "w0.raw")
        key_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        key_path.write_bytes(key.private_bytes_raw())
        key_path.chmod(0o600)
        config = WitnessConfig(
            root_public_key=legacy.pop("root_public_key"),
            witness_set=legacy.pop("witness_set"),
            intermediates=legacy.pop("intermediates"),
            epochs=legacy.pop("epochs"),
            witness_id=legacy.pop("witness_id"),
            witness_key_path=key_path,
            state_dir=state_dir,
            evidence_dir=legacy.pop("evidence_dir", Path("witness-evidence")),
            clock=legacy.pop("clock", None),
        )
    if legacy:
        raise TypeError(f"unexpected witness configuration: {next(iter(legacy))}")
    root = decode_base64url(config.root_public_key)
    if not verify_witness_set(config.witness_set, root):
        raise ValueError("invalid witness set")
    member = next(
        (item for item in config.witness_set.witnesses if item.witness_id == config.witness_id),
        None,
    )
    if member is None:
        raise ValueError("witness is not in witness set")
    witness_key = WitnessKey.load(config.witness_key_path)
    if witness_key.operation.public_key().public_bytes_raw() != decode_base64url(member.public_key):
        raise ValueError("witness key does not match witness set")
    store = WitnessStore(config.state_dir, config.evidence_dir)
    alarm_store = AlarmStore(config.alarm_dir or config.evidence_dir)
    epochs = {item.epoch_id: item for item in config.epochs}
    intermediates = {item.intermediate_id: item for item in config.intermediates}
    app = FastAPI()
    app.state.store = store
    app.state.alarm_store = alarm_store

    @app.exception_handler(WitnessRefusal)
    async def refusal(_: Request, exc: WitnessRefusal) -> JSONResponse:
        status = 401 if exc.code == "witness_unavailable" else 409
        return JSONResponse({"error": {"code": exc.code, "message": "Checkpoint refused."}}, status)

    @app.get("/health")
    async def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/v1/state")
    async def state(request: Request) -> dict[str, object]:
        _auth(request, config.bearer_token)
        log_id = request.query_params.get("log_id")
        if log_id != config.witness_set.log_id:
            raise WitnessRefusal("wrong_log")
        raw = app.state.store.read(log_id)
        if raw is None:
            return {"log_id": log_id, "tree_size": 0, "root_hash": None, "epoch_id": None}
        return {key: raw[key] for key in ("log_id", "tree_size", "root_hash", "epoch_id")}

    @app.get("/v1/alarms")
    async def alarms(request: Request) -> list[dict[str, object]]:
        _auth(request, config.bearer_token)
        log_id = request.query_params.get("log_id")
        if log_id != config.witness_set.log_id:
            raise WitnessRefusal("wrong_log")
        return app.state.alarm_store.list(log_id)

    @app.post("/v1/heartbeat")
    async def heartbeat(request: Request) -> dict[str, str]:
        _auth(request, config.bearer_token)
        try:
            value = Heartbeat.model_validate(
                json.loads(await request.body(), object_pairs_hook=_no_duplicates)
            )
        except (ValueError, TypeError, ValidationError, UnicodeDecodeError):
            return JSONResponse(
                {"error": {"code": "malformed", "message": "Malformed request."}}, 422
            )
        if value.log_id != config.witness_set.log_id:
            raise WitnessRefusal("wrong_log")
        epoch = epochs.get(value.epoch_id)
        intermediate = intermediates.get(epoch.intermediate_id) if epoch else None
        if (
            epoch is None
            or intermediate is None
            or not verify_epoch_certificate(epoch, intermediate, root, value.signer_timestamp)
        ):
            raise WitnessRefusal("bad_cert_chain")
        if not verify_heartbeat(
            value,
            decode_base64url(epoch.epoch_public_key),
            _now(config),
            epoch.valid_from,
            epoch.valid_until,
        ):
            raise WitnessRefusal("bad_signature")
        checkpoint_raw = app.state.store.read(value.log_id)
        checkpoint = (
            Checkpoint.model_validate(checkpoint_raw["checkpoint"]) if checkpoint_raw else None
        )
        if checkpoint is not None and not heartbeat_matches_checkpoint(value, checkpoint):
            emit(
                "HEARTBEAT_MISMATCH",
                structure_hash(value),
                store=app.state.alarm_store,
                log_id=value.log_id,
                timestamp=_now(config),
            )
        app.state.last_heartbeat = value
        return {"status": "accepted"}

    @app.post("/v1/monitor")
    async def monitor(request: Request) -> dict[str, object]:
        _auth(request, config.bearer_token)
        now = request.query_params.get("now") or _now(config)
        last = getattr(app.state, "last_heartbeat", None)
        if last is None:
            emit(
                "HEARTBEAT_STALL",
                "none",
                store=app.state.alarm_store,
                log_id=config.witness_set.log_id,
                timestamp=now,
            )
            return {"alarms": ["HEARTBEAT_STALL"]}
        return {"alarms": []}

    @app.post("/v1/checkpoint")
    async def checkpoint(request: Request) -> dict[str, object]:
        _auth(request, config.bearer_token)
        raw = await request.body()
        if len(raw) > MAX_BODY:
            return JSONResponse(
                {"error": {"code": "malformed", "message": "Malformed request."}}, 413
            )
        try:
            document = json.loads(raw, object_pairs_hook=_no_duplicates)
            submission = CheckpointSubmission.model_validate(document)
        except (ValueError, TypeError, ValidationError, UnicodeDecodeError):
            return JSONResponse(
                {"error": {"code": "malformed", "message": "Malformed request."}}, 422
            )
        try:
            cosignature = _process(
                submission, app.state.store, root, config, epochs, intermediates, witness_key
            )
        except WitnessRefusal as exc:
            if exc.code != "malformed":
                app.state.store.append_refusal(
                    submission.log_id, exc.code, submission.checkpoint.model_dump(mode="json")
                )
                emit(
                    "WITNESS_REFUSAL",
                    structure_hash(submission.checkpoint),
                    store=app.state.alarm_store,
                    log_id=submission.log_id,
                    timestamp=_now(config),
                )
            raise
        return cosignature.model_dump(mode="json")

    return app


def _auth(request: Request, expected: str) -> None:
    if not expected:
        return
    value = request.headers.get("authorization", "")
    if (
        not expected
        or not value.startswith("Bearer ")
        or not hmac.compare_digest(value[7:], expected)
    ):
        raise WitnessRefusal("witness_unavailable")


def _now(config: WitnessConfig) -> str:
    return (config.clock or (lambda: format_timestamp(datetime.now(timezone.utc))))()


def _no_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _process(submission, store, root, config, epochs, intermediates, witness_key):
    checkpoint = submission.checkpoint
    if (
        submission.log_id != config.witness_set.log_id
        or checkpoint.log_id != config.witness_set.log_id
    ):
        raise WitnessRefusal("wrong_log")
    epoch = epochs.get(checkpoint.epoch_id)
    intermediate = intermediates.get(epoch.intermediate_id) if epoch else None
    if (
        epoch is None
        or intermediate is None
        or not verify_epoch_certificate(epoch, intermediate, root, checkpoint.signer_timestamp)
    ):
        raise WitnessRefusal("bad_cert_chain")
    if not verify_checkpoint(checkpoint, decode_base64url(epoch.epoch_public_key)):
        raise WitnessRefusal("bad_signature")
    try:
        raw = store.read(checkpoint.log_id)
    except WitnessStoreError as exc:
        raise WitnessRefusal("witness_unavailable") from exc
    if raw is not None:
        previous = Checkpoint.model_validate(raw["checkpoint"])
        if checkpoint.tree_size < previous.tree_size:
            raise WitnessRefusal("rollback")
        if checkpoint.tree_size == previous.tree_size:
            if checkpoint.root_hash != previous.root_hash or structure_hash(
                checkpoint
            ) != structure_hash(previous):
                raise WitnessRefusal("root_mismatch")
            return Cosignature.model_validate(raw["cosignature"])
        if submission.from_size != previous.tree_size:
            raise WitnessRefusal("proof_required")
        try:
            valid = verify_consistency(
                previous.tree_size,
                checkpoint.tree_size,
                decode_hash(previous.root_hash),
                decode_hash(checkpoint.root_hash),
                [decode_hash(item) for item in submission.consistency_proof],
            )
        except (TypeError, ValueError):
            valid = False
        if not valid:
            raise WitnessRefusal("bad_proof")
        previous_epoch = epochs.get(previous.epoch_id)
        if previous_epoch is None or checkpoint.epoch_id < previous.epoch_id:
            raise WitnessRefusal("epoch_regression")
        if checkpoint.epoch_id != previous.epoch_id:
            try:
                validate_contiguity(previous_epoch, epoch)
            except ValueError as exc:
                raise WitnessRefusal("epoch_regression") from exc
    timestamp = (config.clock or (lambda: format_timestamp(datetime.now(timezone.utc))))()
    cosignature = build_cosignature(
        structure_hash(checkpoint),
        config.witness_id,
        timestamp,
        witness_key.operation,
        log_id=checkpoint.log_id,
    )
    store.commit(checkpoint, cosignature)
    return cosignature
