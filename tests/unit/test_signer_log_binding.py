"""Configured log identity binding at the signer service boundary."""

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from libs.blackbox_core.chain import GENESIS_PREV_HASH, entry_hash
from libs.blackbox_core.crypto import SigningOperation
from libs.blackbox_core.errors import SignerRuleError
from libs.blackbox_core.sealing import verify_entry
from services.signer import rate_limit, state
from services.signer.main import create_app
from services.signer.sealer import SignerSealer
from tests._dev_keys import dev_key
from tests.unit.test_signer_seal_http import post_seal
from tests.unit.test_signer_sealer import (
    CERTIFICATE_ID,
    LOG_ID,
    NOW,
    VALID_FROM,
    VALID_UNTIL,
    candidate,
    configure_state,
    make_sealer,
)

OTHER_LOG_ID = "sha256:" + "a" * 64


def test_wrong_log_regression(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    configure_state(monkeypatch, tmp_path / "state.json")

    with pytest.raises(SignerRuleError, match="^wrong log identity$"):
        make_sealer(dev_key()).seal(candidate(log_id=OTHER_LOG_ID))


def configured_sealer(log_id: str, signing_operation: SigningOperation) -> SignerSealer:
    return SignerSealer(
        log_id=log_id,
        epoch_id=0,
        epoch_certificate_id=CERTIFICATE_ID,
        valid_from=VALID_FROM,
        valid_until=VALID_UNTIL,
        clock=lambda: NOW,
        signing_operation=signing_operation,
        rate_cap=1,
    )


@pytest.mark.parametrize("existing_entry", [False, True])
def test_wrong_log_never_signs_reserves_or_persists(
    existing_entry: bool, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    configure_state(monkeypatch, tmp_path / "state.json")
    key = dev_key()
    operation = make_sealer(key)
    data = candidate(log_id=OTHER_LOG_ID)
    if existing_entry:
        first = operation.seal(candidate())
        data = candidate(log_id=OTHER_LOG_ID, seq=1, prev_hash=entry_hash(first.body))
    previous = state.load_state()
    stored_files = {path.name: path.read_bytes() for path in tmp_path.iterdir()}
    signed = []
    reserved = []
    persisted = []

    def sign(message: bytes) -> bytes:
        signed.append(message)
        return key.sign(message)

    original_reserve = rate_limit.DurableRateLimiter.reserve
    original_persist = state.persist_state

    def reserve(self, now: str, rate_cap: int) -> None:
        reserved.append((now, rate_cap))
        original_reserve(self, now, rate_cap)

    def persist(seq: int, body_hash: str, epoch_id: int, log_id: str) -> None:
        persisted.append((seq, body_hash, epoch_id, log_id))
        original_persist(seq, body_hash, epoch_id, log_id)

    monkeypatch.setattr(rate_limit.DurableRateLimiter, "reserve", reserve)
    monkeypatch.setattr(state, "persist_state", persist)

    with pytest.raises(SignerRuleError, match="^wrong log identity$"):
        configured_sealer(LOG_ID, sign).seal(data)

    assert signed == reserved == persisted == []
    assert state.load_state() == previous
    assert {path.name: path.read_bytes() for path in tmp_path.iterdir()} == stored_files


@pytest.mark.parametrize("configured_log_id", [LOG_ID, OTHER_LOG_ID])
def test_correct_configured_log_is_signed_and_verifies(
    configured_log_id: str, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    configure_state(monkeypatch, tmp_path / "state.json")
    key = dev_key()
    operation = configured_sealer(configured_log_id, key)
    other_log_id = OTHER_LOG_ID if configured_log_id == LOG_ID else LOG_ID

    with pytest.raises(SignerRuleError, match="^wrong log identity$"):
        operation.seal(candidate(log_id=other_log_id))
    sealed = operation.seal(candidate(log_id=configured_log_id))

    assert sealed.body.log_id == configured_log_id
    assert verify_entry(sealed, key.public_key().public_bytes_raw())
    assert state.load_state() == (0, entry_hash(sealed.body), 0)


def test_wrong_log_http_is_sanitized_and_does_not_spend_quota(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    configure_state(monkeypatch, tmp_path / "state.json")
    monkeypatch.setenv("SIGNER_AUTH_TOKEN", "signer-secret")
    key = dev_key()
    with TestClient(create_app(sealer=configured_sealer(LOG_ID, key))) as client:
        rejected = post_seal(client, candidate(log_id=OTHER_LOG_ID))

        assert rejected.status_code == 409
        assert rejected.json() == {
            "error": {"code": "rule_conflict", "message": "Request conflicts with signer rules."}
        }
        assert OTHER_LOG_ID not in rejected.text
        assert "wrong log identity" not in rejected.text
        assert state.load_state() == (-1, GENESIS_PREV_HASH, 0)
        assert list(tmp_path.iterdir()) == []

        accepted = post_seal(client, candidate())

    assert accepted.status_code == 200
    assert accepted.json()["body"]["log_id"] == LOG_ID
    assert verify_entry(accepted.json(), key.public_key().public_bytes_raw())


def test_configured_identity_is_required(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    configure_state(monkeypatch, tmp_path / "state.json")

    with pytest.raises(TypeError, match="log_id"):
        SignerSealer(
            epoch_id=0,
            epoch_certificate_id=CERTIFICATE_ID,
            valid_from=VALID_FROM,
            valid_until=VALID_UNTIL,
            clock=lambda: NOW,
            signing_operation=dev_key(),
        )

    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize(
    "bad_log_id",
    [None, 42, "", "sha256:" + "A" * 64, "sha256:" + "a" * 63, "sha256:" + "g" * 64],
)
def test_malformed_configured_identity_fails_before_storage_or_signing(
    bad_log_id: object, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    configure_state(monkeypatch, tmp_path / "state.json")
    signed = []
    reserved = []
    persisted = []
    key = dev_key()

    def sign(message: bytes) -> bytes:
        signed.append(message)
        return key.sign(message)

    monkeypatch.setattr(
        rate_limit.DurableRateLimiter, "reserve", lambda *args: reserved.append(args)
    )
    monkeypatch.setattr(state, "persist_state", lambda *args: persisted.append(args))

    with pytest.raises(ValueError, match="invalid SHA-256 encoding"):
        configured_sealer(bad_log_id, sign)  # type: ignore[arg-type]

    assert signed == reserved == persisted == []
    assert state.load_state() == (-1, GENESIS_PREV_HASH, 0)
    assert list(tmp_path.iterdir()) == []
