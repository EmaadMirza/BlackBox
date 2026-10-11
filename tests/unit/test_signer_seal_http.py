"""Authenticated /seal route tests for the signer service boundary."""

from __future__ import annotations

import json
from pathlib import Path

from fastapi.testclient import TestClient

from libs.blackbox_core.chain import GENESIS_PREV_HASH
from libs.blackbox_core.sealing import verify_entry
from services.signer.main import create_app
from services.signer.sealer import SignerSealer
from tests._dev_keys import dev_key
from tests.unit.test_schemas import action

NOW = "2026-01-01T00:01:00.000Z"
VALID_FROM = "2026-01-01T00:00:00.000Z"
VALID_UNTIL = "2026-01-01T00:05:00.000Z"
CERTIFICATE_ID = "sha256:" + "2" * 64
LOG_ID = "sha256:" + "1" * 64


def candidate(**updates: object) -> dict[str, object]:
    value = action()
    value.update(
        log_id=LOG_ID,
        epoch_id=0,
        epoch_certificate_id=CERTIFICATE_ID,
        seq=0,
        prev_hash=GENESIS_PREV_HASH,
        signer_timestamp=NOW,
    )
    value.update(updates)
    return value


def configured_client(monkeypatch, tmp_path: Path) -> tuple[TestClient, object]:
    monkeypatch.setenv("SIGNER_AUTH_TOKEN", "signer-secret")
    monkeypatch.setenv("SIGNER_STATE_PATH", str(tmp_path / "state.json"))
    key = dev_key()
    signer = SignerSealer(
        log_id=LOG_ID,
        epoch_id=0,
        epoch_certificate_id=CERTIFICATE_ID,
        valid_from=VALID_FROM,
        valid_until=VALID_UNTIL,
        clock=lambda: NOW,
        signing_operation=key,
    )
    return TestClient(create_app(sealer=signer)), key


def post_seal(client: TestClient, payload: object, **headers: str):
    return client.post(
        "/seal",
        json=payload if not isinstance(payload, bytes) else None,
        content=payload if isinstance(payload, bytes) else None,
        headers={"Authorization": "Bearer signer-secret", **headers},
    )


def test_valid_candidate_returns_verified_sealed_entry(monkeypatch, tmp_path: Path) -> None:
    client, key = configured_client(monkeypatch, tmp_path)

    response = post_seal(client, candidate())

    assert response.status_code == 200
    body = response.json()
    assert body["body"]["seq"] == 0
    assert verify_entry(body, key.public_key().public_bytes_raw())


def test_missing_auth_wins_over_malformed_body(monkeypatch, tmp_path: Path) -> None:
    client, _ = configured_client(monkeypatch, tmp_path)

    response = client.post("/seal", content=b"{", headers={"content-type": "application/json"})

    assert response.status_code == 401
    assert response.json() == {
        "error": {"code": "invalid_auth", "message": "Authentication required."}
    }


def test_malformed_json_and_unknown_fields_are_422(monkeypatch, tmp_path: Path) -> None:
    client, _ = configured_client(monkeypatch, tmp_path)

    malformed = client.post(
        "/seal",
        content=b"{",
        headers={"Authorization": "Bearer signer-secret", "content-type": "application/json"},
    )
    unknown = post_seal(client, {**candidate(), "unknown": "rejected"})

    for response in (malformed, unknown):
        assert response.status_code == 422
        assert response.json() == {
            "error": {"code": "invalid_request", "message": "Invalid request."}
        }


def test_rule_conflict_is_409_and_does_not_sign(monkeypatch, tmp_path: Path) -> None:
    client, _ = configured_client(monkeypatch, tmp_path)

    response = post_seal(client, candidate(seq=1))

    assert response.status_code == 409
    assert response.json() == {
        "error": {"code": "rule_conflict", "message": "Request conflicts with signer rules."}
    }


def test_missing_runtime_sealer_fails_closed(monkeypatch) -> None:
    monkeypatch.setenv("SIGNER_AUTH_TOKEN", "signer-secret")
    response = post_seal(TestClient(create_app()), candidate())

    assert response.status_code == 503
    assert response.json() == {
        "error": {"code": "signer_unavailable", "message": "Signer unavailable."}
    }


def test_sealer_storage_failure_is_sanitized_as_503(monkeypatch) -> None:
    monkeypatch.setenv("SIGNER_AUTH_TOKEN", "signer-secret")

    class UnavailableSealer:
        def seal(self, _candidate: object) -> None:
            raise OSError("private storage detail")

    response = post_seal(TestClient(create_app(sealer=UnavailableSealer())), candidate())

    assert response.status_code == 503
    assert response.json() == {
        "error": {"code": "signer_unavailable", "message": "Signer unavailable."}
    }
    assert "private storage detail" not in response.text


def test_unexpected_sealer_failure_is_sanitized_as_500(monkeypatch) -> None:
    monkeypatch.setenv("SIGNER_AUTH_TOKEN", "signer-secret")

    class BrokenSealer:
        def seal(self, _candidate: object) -> None:
            raise RuntimeError("internal signing detail")

    response = post_seal(TestClient(create_app(sealer=BrokenSealer())), candidate())

    assert response.status_code == 500
    assert response.json() == {"error": {"code": "internal_error", "message": "Internal error."}}
    assert "internal signing detail" not in response.text


def test_duplicate_json_keys_are_rejected_before_signing(monkeypatch, tmp_path: Path) -> None:
    client, _ = configured_client(monkeypatch, tmp_path)
    raw = json.dumps(candidate())
    raw = '{"seq":999,' + raw[1:]
    response = client.post(
        "/seal",
        content=raw,
        headers={"Authorization": "Bearer signer-secret", "Content-Type": "application/json"},
    )
    assert response.status_code == 422
    assert not (tmp_path / "state.json").exists()
