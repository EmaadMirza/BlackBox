"""Offline honest verification, trust failures and CLI behavior."""

import json
import subprocess
import sys
from pathlib import Path

import pytest

from libs.blackbox_core.evidence import Bundle
from tests._dev_keys import dev_key
from tools.attack_suite.fixture import build_demo
from tools.verifier.verify import verify_evidence


def demo() -> tuple:
    keys = [dev_key(i) for i in range(1, 8)]
    return build_demo([(key, key.public_key().public_bytes_raw()) for key in keys])


def test_honest_and_live_epoch() -> None:
    bundle, pins = demo()
    report = verify_evidence(bundle, pins)
    assert report.verdict == "VERIFIED", report.to_dict()
    assert len(report.entries) == 10


@pytest.mark.parametrize(
    "attack",
    ["root", "witness", "checkpoint", "proof", "consistency", "epoch", "schema", "missing_proof"],
)
def test_invalid_evidence(attack: str) -> None:
    bundle, pins = demo()
    data = bundle.model_dump()
    if attack == "root":
        pins = pins.model_copy(update={"root_public_key": pins.witness_public_keys["w0"]})
    elif attack == "witness":
        data["witness_set"]["quorum"] = 1
    elif attack == "checkpoint":
        data["checkpoints"][-1]["checkpoint"]["root_hash"] = "sha256:" + "f" * 64
    elif attack == "proof":
        data["inclusion_proofs"][-1]["proof"][0] = "sha256:" + "f" * 64
    elif attack == "consistency":
        data["consistency_proofs"][0]["proof"][0] = "sha256:" + "f" * 64
    elif attack == "epoch":
        data["epochs"][0]["epoch_public_key"] = data["epochs"][1]["epoch_public_key"]
    elif attack == "schema":
        data["entries"][5]["body"]["unexpected"] = "evil"
    else:
        data["inclusion_proofs"] = []
    report = verify_evidence(Bundle.model_validate(data), pins)
    assert report.verdict in ("TAMPERED", "MISSING")
    assert all(e.reasons for e in report.entries if e.verdict != "VERIFIED")


def test_no_quorum_is_unverified() -> None:
    bundle, pins = demo()
    data = bundle.model_dump()
    for evidence in data["checkpoints"]:
        evidence["cosignatures"] = evidence["cosignatures"][:1]
    report = verify_evidence(Bundle.model_validate(data), pins)
    assert report.verdict == "UNVERIFIED"


def test_cli_and_duplicate_json(tmp_path: Path) -> None:
    bundle, pins = demo()
    b = tmp_path / "bundle.json"
    p = tmp_path / "pins.json"
    b.write_text(bundle.model_dump_json())
    p.write_text(pins.model_dump_json())
    cmd = [sys.executable, "-m", "tools.cli", "verify", str(b), "--pinned-keys", str(p)]
    result = subprocess.run(cmd, capture_output=True, text=True)
    assert result.returncode == 0, result.stdout + result.stderr
    assert json.loads(result.stdout)["verdict"] == "VERIFIED"
    b.write_text('{"a":1,"a":2}')
    result = subprocess.run(cmd, capture_output=True, text=True)
    assert result.returncode == 2 and "duplicate" in result.stdout


def test_ceremony_permissions(tmp_path: Path) -> None:
    from tools.ceremony import prepare_ceremony

    output = prepare_ceremony("test", tmp_path / "ceremony")
    assert (output / "root.dev-private.pem").stat().st_mode & 0o777 == 0o600
    with pytest.raises(FileExistsError):
        prepare_ceremony("test", output)


def test_bad_cosignature_is_tampered_not_just_unverified() -> None:
    bundle, pins = demo()
    data = bundle.model_dump()
    data["checkpoints"][-1]["cosignatures"][0]["witness_signature"] = ""
    assert verify_evidence(Bundle.model_validate(data), pins).verdict == "TAMPERED"


def test_revocation_is_verified_and_applied_at_effective_time() -> None:
    from libs.blackbox_core.schemas import Revocation
    from libs.blackbox_core.signing import sign_structure

    bundle, pins = demo()
    notice = sign_structure(
        Revocation(
            log_id=pins.log_id,
            intermediate_id="intermediate-0",
            effective_time="2026-01-01T00:05:00.000Z",
        ),
        dev_key(1),
        "revocation",
    )
    report = verify_evidence(bundle, pins.model_copy(update={"revocations": [notice]}))
    assert report.verdict == "TAMPERED"
    assert any("revocation" in reason for entry in report.entries for reason in entry.reasons)
    future = sign_structure(
        notice.model_copy(update={"effective_time": "2026-01-01T01:00:00.000Z"}),
        dev_key(1),
        "revocation",
    )
    assert (
        verify_evidence(bundle, pins.model_copy(update={"revocations": [future]})).verdict
        == "VERIFIED"
    )


def test_pin_minimum_size_detects_stripped_tail_evidence() -> None:
    bundle, pins = demo()
    data = bundle.model_dump()
    data["entries"] = data["entries"][:3]
    data["checkpoints"] = data["checkpoints"][:1]
    data["inclusion_proofs"] = [p for p in data["inclusion_proofs"] if p["tree_size"] == 3]
    data["consistency_proofs"] = []
    report = verify_evidence(Bundle.model_validate(data), pins)
    assert report.verdict == "MISSING"
    assert [e.seq for e in report.entries if e.verdict == "MISSING"] == list(range(3, 10))


def test_exact_tamper_localization() -> None:
    from tools.attack_suite.tamper_battery import variants

    bundle, pins = demo()
    report = verify_evidence(variants(bundle)["edit_and_rehash"], pins)
    assert [entry.seq for entry in report.entries if entry.verdict == "TAMPERED"] == list(
        range(5, 10)
    )
    assert report.entries[5].reasons[0] == "entry signature failure"


def test_verification_never_opens_a_socket(monkeypatch: pytest.MonkeyPatch) -> None:
    import socket

    def forbidden(*args: object, **kwargs: object) -> None:
        raise AssertionError("offline verifier attempted networking")

    bundle, pins = demo()
    monkeypatch.setattr(socket, "socket", forbidden)
    assert verify_evidence(bundle, pins).verdict == "VERIFIED"


def test_commitment_openings_and_verdict_precedence() -> None:
    from libs.blackbox_core.commitments import commit, verify_opening
    from tools.verifier.verdicts import resolve

    salt = b"s" * 32
    value = b"private payload"
    digest = commit(value, salt)
    assert verify_opening(digest, value, salt)
    assert not verify_opening(digest, b"changed", salt)
    assert not verify_opening(digest, value, b"short")
    assert resolve(["VERIFIED", "UNVERIFIED", "MISSING", "TAMPERED"]) == "TAMPERED"
    assert resolve(["UNVERIFIED", "MISSING"]) == "MISSING"
