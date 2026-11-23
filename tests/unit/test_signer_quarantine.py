"""Unit tests for durable signer quarantine (Task E)."""

from __future__ import annotations

from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

from libs.blackbox_core.schemas import parse_entry
from services.signer import quarantine, state
from services.signer.main import create_app
from services.signer.sealer import SignerSealer
from tests.unit.test_signer_seal_http import candidate as make_candidate

LOG_ID = "sha256:" + "b" * 64
KEY = Ed25519PrivateKey.generate()


def test_quarantine_entry_and_lift(tmp_path: Path) -> None:
    q_file = tmp_path / "state.json.quarantine.json"

    assert not quarantine.is_quarantined(path=q_file)
    assert quarantine.get_quarantine_reason(path=q_file) is None

    rec = quarantine.enter_quarantine(
        log_id=LOG_ID,
        reason="operator_maintenance",
        details="Routine check",
        last_known_seq=10,
        last_known_hash="sha256:" + "1" * 64,
        recovery_generation=1,
        path=q_file,
    )

    assert rec.status == "quarantined"
    assert rec.reason == "operator_maintenance"
    assert quarantine.is_quarantined(path=q_file)
    assert quarantine.get_quarantine_reason(path=q_file) == "operator_maintenance"

    # Lift quarantine
    lifted = quarantine.lift_quarantine(
        recovery_receipt={"recovered": True, "frontier": 10},
        path=q_file,
    )
    assert lifted.status == "recovered"
    assert lifted.recovery_generation == 2
    assert not quarantine.is_quarantined(path=q_file)


def test_commit_marker_causes_quarantine_active(tmp_path: Path) -> None:
    state_file = tmp_path / "state.json"
    marker = tmp_path / ".state.json.commit"
    marker.write_text("{}", encoding="utf-8")

    assert quarantine.is_quarantined(path=state_file)
    assert quarantine.get_quarantine_reason(path=state_file) == "marker_detected"


def test_sealer_refuses_when_quarantined(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    state_file = tmp_path / "state.json"
    q_file = tmp_path / "state.json.quarantine.json"
    monkeypatch.setenv("SIGNER_STATE_PATH", str(state_file))
    monkeypatch.setenv("SIGNER_QUARANTINE_PATH", str(q_file))

    state.persist_state(0, "sha256:" + "0" * 64, 0, LOG_ID, {})

    quarantine.enter_quarantine(
        log_id=LOG_ID,
        reason="history_integrity",
        details="Compromised history",
        path=q_file,
    )

    sealer = SignerSealer(
        log_id=LOG_ID,
        epoch_id=0,
        epoch_certificate_id="sha256:" + "2" * 64,
        valid_from="2026-01-01T00:00:00.000Z",
        valid_until="2027-01-01T00:00:00.000Z",
        clock=lambda: "2026-01-01T00:01:00.000Z",
        signing_operation=KEY.sign,
    )

    cand_dict = make_candidate(seq=1, prev_hash="sha256:" + "0" * 64, log_id=LOG_ID)
    cand = parse_entry(cand_dict)

    with pytest.raises(quarantine.QuarantineActiveError, match="Signer is quarantined"):
        sealer.seal(cand)


def test_http_routes_fail_closed_when_quarantined(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    state_file = tmp_path / "state.json"
    q_file = tmp_path / "state.json.quarantine.json"
    monkeypatch.setenv("SIGNER_STATE_PATH", str(state_file))
    monkeypatch.setenv("SIGNER_QUARANTINE_PATH", str(q_file))
    monkeypatch.setenv("SIGNER_AUTH_TOKEN", "test-token")

    state.persist_state(0, "sha256:" + "0" * 64, 0, LOG_ID, {})
    quarantine.enter_quarantine(
        log_id=LOG_ID,
        reason="uncertain_commit",
        details="Crash during commit",
        path=q_file,
    )

    sealer = SignerSealer(
        log_id=LOG_ID,
        epoch_id=0,
        epoch_certificate_id="sha256:" + "2" * 64,
        valid_from="2026-01-01T00:00:00.000Z",
        valid_until="2027-01-01T00:00:00.000Z",
        clock=lambda: "2026-01-01T00:01:00.000Z",
        signing_operation=KEY.sign,
    )

    app = create_app(sealer=sealer)
    client = TestClient(app)

    # 1. /health reports degraded
    h_res = client.get("/health")
    assert h_res.status_code == 200
    assert h_res.json() == {"status": "degraded", "reason": "uncertain_commit"}

    # 2. /seal returns 503 quarantined
    cand_dict = make_candidate(seq=1, prev_hash="sha256:" + "0" * 64, log_id=LOG_ID)
    s_res = client.post(
        "/seal",
        json=cand_dict,
        headers={"Authorization": "Bearer test-token"},
    )
    assert s_res.status_code == 503
    assert s_res.json() == {
        "error": {
            "code": "quarantined",
            "message": "Signer is quarantined; recovery is required.",
        }
    }

    # 3. /attest returns 503 quarantined
    a_res = client.post(
        "/attest",
        json={"intent_seq": 1},
        headers={"Authorization": "Bearer test-token"},
    )
    assert a_res.status_code == 503
    assert a_res.json() == {
        "error": {
            "code": "quarantined",
            "message": "Signer is quarantined; recovery is required.",
        }
    }
