"""R1/R2 persisted epoch metadata and degraded readiness tests."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from libs.blackbox_core.encoding import encode_base64url
from libs.blackbox_core.epochs import build_epoch_certificate
from services.signer import state
from services.signer.main import create_app
from tests._dev_keys import dev_key

LOG_ID = "sha256:" + "1" * 64


def metadata() -> dict[str, object]:
    intermediate = dev_key(2)
    cert = build_epoch_certificate(
        1,
        encode_base64url(dev_key(3).public_key().public_bytes_raw()),
        "2026-01-01T00:05:00.000Z",
        "2026-01-01T00:10:00.000Z",
        "intermediate-0",
        log_id=LOG_ID,
        signing_operation=intermediate,
    )
    return {
        "format_version": state.EPOCH_METADATA_FORMAT_VERSION,
        "log_id": LOG_ID,
        "epoch_id": cert.epoch_id,
        "epoch_certificate": cert.model_dump(),
        "valid_from": cert.valid_from,
        "valid_until": cert.valid_until,
    }


def test_epoch_metadata_round_trip_and_never_persists_private_key(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    path = tmp_path / "state.json"
    monkeypatch.setenv("SIGNER_STATE_PATH", str(path))

    state.persist_state(2, "sha256:" + "a" * 64, 1, LOG_ID, {}, metadata())

    loaded = state.load_epoch_metadata(LOG_ID)
    assert loaded["epoch_id"] == 1
    for file in tmp_path.iterdir():
        assert b"PRIVATE" not in file.read_bytes()
        assert b"private" not in file.read_bytes().lower()


def test_old_epoch_metadata_version_fails_closed(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    path = tmp_path / "state.json"
    monkeypatch.setenv("SIGNER_STATE_PATH", str(path))
    state.persist_state(0, "sha256:" + "a" * 64, 0, LOG_ID, {})
    metadata_path = tmp_path / "state.json.epoch.json"
    metadata_path.write_text(json.dumps({"format_version": "0"}), encoding="utf-8")

    with pytest.raises(ValueError, match="epoch metadata"):
        state.load_epoch_metadata(LOG_ID)


def test_degraded_health_has_stable_public_reason(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "services.signer.main.signer_health",
        lambda _signer: {"status": "degraded", "reason": "new_epoch_required"},
    )
    response = TestClient(create_app(sealer=object())).get("/health")

    assert response.status_code == 200
    assert response.json() == {"status": "degraded", "reason": "new_epoch_required"}
