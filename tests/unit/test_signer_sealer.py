"""Focused tests for the in-process signer seal operation."""

from __future__ import annotations

from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from libs.blackbox_core.chain import GENESIS_PREV_HASH, entry_hash
from libs.blackbox_core.errors import SignerRuleError
from libs.blackbox_core.sealing import verify_entry
from services.signer import sealer, state
from tests._dev_keys import dev_key
from tests.unit.test_schemas import action

NOW = "2026-01-01T00:01:00.000Z"
VALID_FROM = "2026-01-01T00:00:00.000Z"
VALID_UNTIL = "2026-01-01T00:05:00.000Z"
CERTIFICATE_ID = "sha256:" + "2" * 64
LOG_ID = "sha256:" + "1" * 64


def configure_state(monkeypatch: pytest.MonkeyPatch, path: Path) -> None:
    monkeypatch.setenv("SIGNER_STATE_PATH", str(path))


def candidate(*, seq: int = 0, prev_hash: str = GENESIS_PREV_HASH, **updates: object) -> dict:
    value = action()
    value.update(
        log_id=LOG_ID,
        epoch_id=0,
        epoch_certificate_id=CERTIFICATE_ID,
        seq=seq,
        prev_hash=prev_hash,
        signer_timestamp=NOW,
    )
    value.update(updates)
    return value


def make_sealer(
    key: Ed25519PrivateKey,
    *,
    rate_cap: int = 1000,
) -> sealer.SignerSealer:
    return sealer.SignerSealer(
        log_id=LOG_ID,
        epoch_id=0,
        epoch_certificate_id=CERTIFICATE_ID,
        valid_from=VALID_FROM,
        valid_until=VALID_UNTIL,
        clock=lambda: NOW,
        rate_cap=rate_cap,
        signing_operation=key,
    )


def test_success_verifies_and_persists_state(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    configure_state(monkeypatch, tmp_path / "state.json")
    key = dev_key()

    sealed = make_sealer(key).seal(candidate())

    assert sealed.body.seq == 0
    assert verify_entry(sealed, key.public_key().public_bytes_raw())
    assert state.load_state(LOG_ID) == (0, entry_hash(sealed.body), 0)


def test_second_instance_continues_sequence_after_restart(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    configure_state(monkeypatch, tmp_path / "state.json")
    key = dev_key()
    first = make_sealer(key).seal(candidate())

    second = make_sealer(key).seal(
        candidate(seq=1, prev_hash=entry_hash(first.body), action_name="second")
    )

    assert second.body.seq == 1
    assert state.load_state(LOG_ID) == (1, entry_hash(second.body), 0)


@pytest.mark.parametrize(
    ("updates", "message"),
    [
        ({"seq": 1}, "sequence"),
        ({"prev_hash": "sha256:" + "a" * 64}, "previous hash"),
        ({"epoch_id": 1}, "wrong epoch identity"),
        ({"epoch_certificate_id": "sha256:" + "a" * 64}, "wrong epoch identity"),
        ({"signer_timestamp": "2026-01-01T00:02:00.000Z"}, "timestamp"),
        ({"unknown": 1}, "schema invalid"),
    ],
)
def test_invalid_request_leaves_durable_state_unchanged(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    updates: dict[str, object],
    message: str,
) -> None:
    configure_state(monkeypatch, tmp_path / "state.json")
    key = dev_key()
    initial = state.load_state()

    with pytest.raises(SignerRuleError, match=message):
        make_sealer(key).seal(candidate(**updates))

    assert state.load_state() == initial


def test_expired_epoch_is_rejected(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    configure_state(monkeypatch, tmp_path / "state.json")
    key = dev_key()
    expired = sealer.SignerSealer(
        log_id=LOG_ID,
        epoch_id=0,
        epoch_certificate_id=CERTIFICATE_ID,
        valid_from=VALID_FROM,
        valid_until=NOW,
        clock=lambda: NOW,
        signing_operation=key,
    )

    with pytest.raises(SignerRuleError, match="expired epoch"):
        expired.seal(candidate())
    assert state.load_state() == (-1, GENESIS_PREV_HASH, 0)


def test_rate_cap_is_enforced_without_persisting_a_second_entry(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    configure_state(monkeypatch, tmp_path / "state.json")
    key = dev_key()
    operation = make_sealer(key, rate_cap=1)
    first = operation.seal(candidate())
    previous = state.load_state()

    with pytest.raises(SignerRuleError, match="rate cap"):
        operation.seal(candidate(seq=1, prev_hash=entry_hash(first.body)))

    assert state.load_state() == previous


@pytest.mark.parametrize("entry_type", ["epoch_start", "epoch_end"])
def test_gateway_cannot_seal_signer_only_epoch_entries(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, entry_type: str
) -> None:
    configure_state(monkeypatch, tmp_path / "state.json")
    key = dev_key()
    data = candidate()
    for field in ("action_name", "reason", "target_reference"):
        data.pop(field)
    data["type"] = entry_type
    if entry_type == "epoch_start":
        data["certificate"] = {
            "epoch_id": 0,
            "log_id": LOG_ID,
            "epoch_public_key": "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8",
            "valid_from": VALID_FROM,
            "valid_until": VALID_UNTIL,
            "intermediate_id": "i0",
            "signature": "",
        }

    with pytest.raises(SignerRuleError, match="signer-only"):
        make_sealer(key).seal(data)
    assert state.load_state() == (-1, GENESIS_PREV_HASH, 0)


def test_signing_failure_leaves_state_unchanged(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    configure_state(monkeypatch, tmp_path / "state.json")

    def fail(_: bytes) -> bytes:
        raise RuntimeError("signing failed")

    with pytest.raises(RuntimeError, match="signing failed"):
        make_sealer(fail).seal(candidate())  # type: ignore[arg-type]
    assert state.load_state() == (-1, GENESIS_PREV_HASH, 0)


def test_persistence_failure_returns_no_result_and_leaves_state_unchanged(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    configure_state(monkeypatch, tmp_path / "state.json")
    key = dev_key()
    previous = state.load_state()

    def fail_persist(_: int, __: str, ___: int, ____: str) -> None:
        raise OSError("persistence failed")

    monkeypatch.setattr(state, "persist_state", fail_persist)
    with pytest.raises(OSError, match="persistence failed"):
        make_sealer(key).seal(candidate())

    assert state.load_state() == previous


def test_invalid_schema_is_reported_as_signer_rule_error(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    configure_state(monkeypatch, tmp_path / "state.json")
    data = candidate()
    data["seq"] = 0.0

    with pytest.raises(SignerRuleError, match="schema invalid"):
        make_sealer(dev_key()).seal(data)


def test_sealer_does_not_generate_or_persist_key_material() -> None:
    key = dev_key()
    operation = make_sealer(key)

    assert operation._signing_operation is key
    assert not hasattr(operation, "private_key")
