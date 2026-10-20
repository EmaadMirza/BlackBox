"""S2 degraded health and intermediate-failure boundary tests."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from libs.blackbox_core.encoding import encode_base64url
from libs.blackbox_core.epochs import build_intermediate_certificate
from services.signer.epoch_manager import DirectoryIntermediateSigner, InMemoryIntermediateSigner
from services.signer.main import create_app
from tests._dev_keys import dev_key


@pytest.mark.parametrize(
    "reason",
    ["no_epoch_key", "intermediate_expired", "intermediate_unavailable", "uncertain_commit"],
)
def test_health_degraded_reasons_are_stable_and_sanitized(reason: str) -> None:
    class Degraded:
        health_reason = reason

    response = TestClient(create_app(sealer=Degraded())).get("/health")

    assert response.status_code == 200
    assert response.json() == {"status": "degraded", "reason": reason}
    assert "/" not in response.text
    assert "Traceback" not in response.text


def test_healthy_health_response_is_unchanged() -> None:
    response = TestClient(create_app()).get("/health")

    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_directory_intermediate_missing_directory_fails_closed(tmp_path: Path) -> None:
    with pytest.raises((FileNotFoundError, OSError)):
        DirectoryIntermediateSigner(tmp_path / "missing", b"0" * 32)


def test_directory_intermediate_corrupt_certificate_fails_closed(tmp_path: Path) -> None:
    tmp_path.joinpath("intermediate.json").write_text("{", encoding="utf-8")
    tmp_path.joinpath("intermediate.dev-private.pem").write_bytes(b"not-a-key")

    with pytest.raises((ValueError, OSError)):
        DirectoryIntermediateSigner(tmp_path, b"0" * 32)


def test_directory_intermediate_wrong_log_fails_closed(tmp_path: Path) -> None:
    key = dev_key(2)
    root = dev_key(1)
    certificate = build_intermediate_certificate(
        "sha256:" + "f" * 64,
        "intermediate-0",
        encode_base64url(key.public_key().public_bytes_raw()),
        "2026-01-01T00:00:00.000Z",
        "2026-02-01T00:00:00.000Z",
        root,
    )
    tmp_path.joinpath("intermediate.json").write_text(
        json.dumps(certificate.model_dump()), encoding="utf-8"
    )
    tmp_path.joinpath("intermediate.dev-private.pem").write_bytes(b"not-a-key")

    with pytest.raises(ValueError, match="log"):
        DirectoryIntermediateSigner(
            tmp_path, root.public_key().public_bytes_raw(), "sha256:" + "1" * 64
        )


def test_expired_intermediate_rejects_new_epoch_certificate() -> None:
    root = dev_key(1)
    intermediate = dev_key(2)
    certificate = build_intermediate_certificate(
        "sha256:" + "1" * 64,
        "intermediate-0",
        encode_base64url(intermediate.public_key().public_bytes_raw()),
        "2026-01-01T00:00:00.000Z",
        "2026-01-01T00:05:00.000Z",
        root,
    )
    signer = InMemoryIntermediateSigner(
        certificate, intermediate, root.public_key().public_bytes_raw()
    )
    candidate = build_intermediate_certificate(
        "sha256:" + "1" * 64,
        "intermediate-0",
        encode_base64url(dev_key(3).public_key().public_bytes_raw()),
        "2026-01-01T00:05:00.000Z",
        "2026-01-01T00:10:00.000Z",
        root,
    )

    with pytest.raises(ValueError, match="expired"):
        signer.sign_epoch_certificate(candidate)
