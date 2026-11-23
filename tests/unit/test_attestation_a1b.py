"""A1b provenance, integration, and state immutability tests."""

import os
from dataclasses import dataclass
from pathlib import Path
from tempfile import TemporaryDirectory

import pytest
from fastapi.testclient import TestClient
from hypothesis import given, settings
from hypothesis import strategies as st

from libs.blackbox_core.attestation import verify_attestation
from libs.blackbox_core.epochs import certificate_id
from libs.blackbox_core.errors import SignerRuleError
from services.signer.history import HistoryEntryEvidence, HistoryRecord
from services.signer.main import create_app
from services.signer.sealer import SignerSealer
from tests.unit.test_epochs_rules import certificates, request_pair


@dataclass
class Source:
    record: HistoryRecord

    def get_intent(self, log_id: str, intent_seq: int) -> HistoryRecord:
        return self.record

    def get_outcome(self, log_id: str, intent_seq: int, outcome_hash: str) -> HistoryRecord:
        raise RuntimeError("not used")


def setup_history() -> tuple:
    root, _inter, epoch_key, intermediate, epoch = certificates()
    _, intent, _ = request_pair()
    intent = intent.model_copy(
        update={
            "log_id": epoch.log_id,
            "policy": intent.policy.model_copy(update={"severity": "low"}),
        }
    )
    sealed = __import__("libs.blackbox_core.sealing", fromlist=["seal"]).seal(intent, epoch_key)
    evidence = HistoryEntryEvidence(
        entry=sealed,
        epoch_certificate=epoch,
        intermediate_certificate=intermediate,
        root_public_key=root.public_key().public_bytes_raw(),
    )
    return root, epoch_key, epoch, intent, sealed, Source(HistoryRecord((evidence,), 0))


def make_sealer(
    tmp_path: Path, source: Source, key, epoch, clock=lambda: "2026-01-01T00:01:00.000Z"
):
    path = tmp_path / "state.json"
    sealer = SignerSealer(
        log_id=epoch.log_id,
        epoch_id=epoch.epoch_id,
        epoch_certificate_id=certificate_id(epoch),
        valid_from=epoch.valid_from,
        valid_until=epoch.valid_until,
        clock=clock,
        signing_operation=key,
        history_source=source,
    )
    return sealer, path


def snapshot(path: Path) -> dict[str, bytes | None]:
    return {
        name: (path.with_name(name).read_bytes() if path.with_name(name).exists() else None)
        for name in (path.name, f"{path.name}.outcomes.json", f"{path.name}.rate.sqlite3")
    }


def test_attest_uses_authenticated_history_and_rejects_tampering(
    tmp_path: Path, monkeypatch
) -> None:
    root, key, epoch, intent, sealed, source = setup_history()
    path = tmp_path / "state.json"
    monkeypatch.setenv("SIGNER_STATE_PATH", str(path))
    sealer, path = make_sealer(tmp_path, source, key, epoch)
    source.record = HistoryRecord(
        entries=(
            source.record.entries[0].__class__(
                entry=sealed.model_copy(update={"signature": ""}),
                epoch_certificate=source.record.entries[0].epoch_certificate,
                intermediate_certificate=source.record.entries[0].intermediate_certificate,
                root_public_key=source.record.entries[0].root_public_key,
            ),
        ),
        target_seq=0,
    )
    with pytest.raises(SignerRuleError):
        sealer.attest(intent.seq)
    assert root.public_key().public_bytes_raw()


def test_attest_does_not_change_state_files_and_http_verifies(tmp_path: Path, monkeypatch) -> None:
    root, key, epoch, intent, sealed, source = setup_history()
    path = tmp_path / "state.json"
    monkeypatch.setenv("SIGNER_STATE_PATH", str(path))
    sealer, path = make_sealer(tmp_path, source, key, epoch)
    intent = intent.model_copy(update={"signer_timestamp": "2026-01-01T00:01:00.000Z"})
    sealed = sealer.seal(intent)
    evidence = source.record.entries[0]
    source.record = HistoryRecord(
        entries=(
            evidence.__class__(
                entry=sealed,
                epoch_certificate=evidence.epoch_certificate,
                intermediate_certificate=evidence.intermediate_certificate,
                root_public_key=evidence.root_public_key,
            ),
        ),
        target_seq=0,
    )
    before = snapshot(path)
    monkeypatch.setenv("SIGNER_AUTH_TOKEN", "secret")
    response = TestClient(create_app(sealer=sealer)).post(
        "/attest", headers={"Authorization": "Bearer secret"}, json={"intent_seq": 0}
    )
    assert response.status_code == 200, response.text
    attestation = response.json()
    assert attestation["body_digest"] == intent.action.body_digest
    assert verify_attestation(
        __import__(
            "libs.blackbox_core.schemas", fromlist=["Attestation"]
        ).Attestation.model_validate(attestation),
        key.public_key().public_bytes_raw(),
        "2026-01-01T00:01:01.000Z",
    )
    assert snapshot(path) == before


def test_unknown_or_other_log_intent_is_rejected(tmp_path: Path, monkeypatch) -> None:
    _, key, epoch, intent, sealed, source = setup_history()
    sealer, path = make_sealer(tmp_path, source, key, epoch)
    monkeypatch.setenv("SIGNER_STATE_PATH", str(path))
    with pytest.raises(SignerRuleError):
        sealer.attest(99)
    with pytest.raises(SignerRuleError):
        sealer.attest(intent.seq)
    other = intent.model_copy(update={"log_id": "sha256:" + "f" * 64})
    source.record = source.record.__class__(
        entries=(
            source.record.entries[0].__class__(
                entry=sealed.model_copy(update={"body": other}),
                epoch_certificate=source.record.entries[0].epoch_certificate,
                intermediate_certificate=source.record.entries[0].intermediate_certificate,
                root_public_key=source.record.entries[0].root_public_key,
            ),
        ),
        target_seq=0,
    )
    with pytest.raises(SignerRuleError):
        sealer.attest(other.seq)


def test_rejected_attestations_leave_state_files_unchanged(tmp_path: Path, monkeypatch) -> None:
    _, key, epoch, intent, _, source = setup_history()
    path = tmp_path / "state.json"
    monkeypatch.setenv("SIGNER_STATE_PATH", str(path))
    sealer, path = make_sealer(tmp_path, source, key, epoch)
    before = snapshot(path)
    with pytest.raises(SignerRuleError):
        sealer.attest(0)
    assert snapshot(path) == before


def test_same_intent_can_be_re_attested_but_digest_cannot_change(
    tmp_path: Path, monkeypatch
) -> None:
    _, key, epoch, intent, _, source = setup_history()
    path = tmp_path / "state.json"
    monkeypatch.setenv("SIGNER_STATE_PATH", str(path))
    sealer, path = make_sealer(tmp_path, source, key, epoch)
    intent = intent.model_copy(update={"signer_timestamp": "2026-01-01T00:01:00.000Z"})
    sealed = sealer.seal(intent)
    evidence = source.record.entries[0]
    source.record = HistoryRecord(
        entries=(
            evidence.__class__(
                entry=sealed,
                epoch_certificate=evidence.epoch_certificate,
                intermediate_certificate=evidence.intermediate_certificate,
                root_public_key=evidence.root_public_key,
            ),
        ),
        target_seq=0,
    )
    first = sealer.attest(0)
    second = sealer.attest(0)
    assert first.body_digest == second.body_digest == intent.action.body_digest
    with pytest.raises(SignerRuleError):
        sealer.attest(0, "sha256:" + "f" * 64)


@settings(max_examples=8, derandomize=True, database=None)
@given(calls=st.lists(st.booleans(), min_size=1, max_size=4))
def test_attestation_invariant_over_repeated_calls(calls: list[bool]) -> None:
    _, key, epoch, intent, _, source = setup_history()
    with TemporaryDirectory() as directory:
        path = Path(directory) / "state.json"
        old_path = os.environ.get("SIGNER_STATE_PATH")
        os.environ["SIGNER_STATE_PATH"] = str(path)
        sealer, _ = make_sealer(Path(directory), source, key, epoch)
        intent = intent.model_copy(update={"signer_timestamp": "2026-01-01T00:01:00.000Z"})
        sealed = sealer.seal(intent)
        evidence = source.record.entries[0]
        source.record = HistoryRecord(
            entries=(
                evidence.__class__(
                    entry=sealed,
                    epoch_certificate=evidence.epoch_certificate,
                    intermediate_certificate=evidence.intermediate_certificate,
                    root_public_key=evidence.root_public_key,
                ),
            ),
            target_seq=0,
        )
        issued = [sealer.attest(0) for _ in calls]
        assert {item.body_digest for item in issued} == {intent.action.body_digest}
        if old_path is None:
            os.environ.pop("SIGNER_STATE_PATH", None)
        else:
            os.environ["SIGNER_STATE_PATH"] = old_path
