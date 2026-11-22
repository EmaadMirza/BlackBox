"""E11: Key compromise and rogue epochs."""

from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

from libs.blackbox_core import schemas
from libs.blackbox_core.checkpoint import build_checkpoint, sign_checkpoint
from libs.blackbox_core.crypto import sha256
from libs.blackbox_core.encoding import (
    decode_base64url,
    encode_base64url,
    encode_hash,
)
from libs.blackbox_core.epochs import (
    build_epoch_certificate,
    certificate_id,
    verify_epoch_certificate,
)
from libs.blackbox_core.merkle import MerkleTree
from libs.blackbox_core.schemas import Revocation, parse_entry
from libs.blackbox_core.sealing import seal, sealed_bytes
from libs.blackbox_core.signing import sign_structure
from services.witness.main import WitnessConfig, create_app
from tests._dev_keys import dev_key
from tools.attack_suite.fixture import build_demo
from tools.verifier.verify import verify_evidence


def test_e11(tmp_path: Path) -> None:
    """E11: Key compromise and rogue epochs (software keys).

    Proves:
    1. Key stolen from epoch N cannot sign entries accepted in epoch N+1's window.
    2. Half-open window boundary [from, until): rejected at until, accepted one tick before.
    3. Rogue epoch not signed by a pinned intermediate is rejected with cert chain failure.
    4. Revoked intermediate cert: entries before revocation point verify; entries after fail.
    5. Attacker with stolen key cannot force witness cosignature without valid consistency proof.
    """
    keys = [(dev_key(i), dev_key(i).public_key().public_bytes_raw()) for i in range(1, 8)]
    bundle, pins = build_demo(keys)
    baseline_report = verify_evidence(bundle, pins)
    assert baseline_report.verdict == "VERIFIED", "Honest baseline must verify"

    root_key = keys[0]
    stolen_epoch0_key = keys[2]  # epoch 0 valid: 00:00:00.000Z to 00:05:00.000Z
    epoch1_key = keys[3]  # epoch 1 valid: 00:05:00.000Z to 00:10:00.000Z

    cert0 = bundle.epochs[0]
    cert1 = bundle.epochs[1]
    intermediate0 = bundle.intermediates[0]

    # =========================================================================
    # Case 1: Key stolen from epoch 0 signs entry in epoch 1's window
    # =========================================================================
    # Attacker crafts an entry using stolen epoch 0 key, but timestamped in epoch 1
    forged_body_1 = dict(
        format_version="4",
        log_id=bundle.log_id,
        epoch_id=0,
        seq=2,
        signer_timestamp="2026-01-01T00:06:00.000Z",  # In epoch 1 window
        prev_hash=bundle.entries[1]["body"]["prev_hash"],
        lane="agent",
        epoch_certificate_id=certificate_id(cert0),
        type="action",
        action_name="forged_transfer",
        reason="stolen key exploit",
        target_reference="target-1",
    )
    forged_entry_1 = seal(parse_entry(forged_body_1), stolen_epoch0_key[0])

    mutated_entries_1 = [e.copy() for e in bundle.entries]
    mutated_entries_1[2] = forged_entry_1.model_dump(mode="json")
    case1_bundle = bundle.model_copy(update={"entries": mutated_entries_1})

    report_1 = verify_evidence(case1_bundle, pins)
    assert report_1.verdict == "TAMPERED", "Expired epoch signature must yield TAMPERED verdict"
    entry_report_1 = next(e for e in report_1.entries if e.seq == 2)
    assert entry_report_1.verdict == "TAMPERED"
    assert "certificate chain, epoch validity or revocation failed" in entry_report_1.reasons, (
        "Must specifically report epoch validity failure"
    )

    # =========================================================================
    # Case 2: Half-open semantics [from, until)
    # At exact valid_until boundary -> rejected
    # One millisecond before valid_until -> accepted
    # =========================================================================
    until_stamp = cert0.valid_until  # "2026-01-01T00:05:00.000Z"
    just_before_stamp = "2026-01-01T00:04:59.999Z"

    root_pub_bytes = decode_base64url(pins.root_public_key)

    # Boundary verification via core epoch verification rules
    assert (
        verify_epoch_certificate(cert0, intermediate0, root_pub_bytes, just_before_stamp) is True
    ), "One tick before valid_until must be within half-open window [from, until)"
    assert verify_epoch_certificate(cert0, intermediate0, root_pub_bytes, until_stamp) is False, (
        "Exact valid_until boundary must be outside half-open window [from, until)"
    )

    # Boundary verification in bundle evidence
    forged_body_boundary = dict(
        format_version="4",
        log_id=bundle.log_id,
        epoch_id=0,
        seq=2,
        signer_timestamp=until_stamp,
        prev_hash=bundle.entries[1]["body"]["prev_hash"],
        lane="agent",
        epoch_certificate_id=certificate_id(cert0),
        type="action",
        action_name="boundary_test",
        reason="boundary exploit",
        target_reference="target-boundary",
    )
    forged_boundary_entry = seal(parse_entry(forged_body_boundary), stolen_epoch0_key[0])
    mutated_entries_boundary = [e.copy() for e in bundle.entries]
    mutated_entries_boundary[2] = forged_boundary_entry.model_dump(mode="json")
    boundary_bundle = bundle.model_copy(update={"entries": mutated_entries_boundary})

    report_boundary = verify_evidence(boundary_bundle, pins)
    assert report_boundary.verdict == "TAMPERED"
    entry_report_boundary = next(e for e in report_boundary.entries if e.seq == 2)
    assert "certificate chain, epoch validity or revocation failed" in entry_report_boundary.reasons

    # =========================================================================
    # Case 3: Rogue epoch: attacker generates own epoch key and cert
    # Not signed by pinned intermediate
    # =========================================================================
    rogue_private_key = Ed25519PrivateKey.generate()
    rogue_pub_b64 = encode_base64url(rogue_private_key.public_key().public_bytes_raw())

    # Self-signed or unsigned by pinned intermediate
    rogue_cert = build_epoch_certificate(
        99,
        rogue_pub_b64,
        "2026-01-01T00:00:00.000Z",
        "2026-01-01T00:05:00.000Z",
        intermediate_id="intermediate-0",
        log_id=bundle.log_id,
        signing_operation=rogue_private_key,  # Rogue key signs the cert, not intermediate-0
    )

    rogue_body = dict(
        format_version="4",
        log_id=bundle.log_id,
        epoch_id=99,
        seq=2,
        signer_timestamp="2026-01-01T00:02:00.000Z",
        prev_hash=bundle.entries[1]["body"]["prev_hash"],
        lane="agent",
        epoch_certificate_id=certificate_id(rogue_cert),
        type="action",
        action_name="rogue_action",
        reason="rogue epoch test",
        target_reference="target-rogue",
    )
    rogue_entry = seal(parse_entry(rogue_body), rogue_private_key)

    mutated_entries_3 = [e.copy() for e in bundle.entries]
    mutated_entries_3[2] = rogue_entry.model_dump(mode="json")
    case3_bundle = bundle.model_copy(
        update={
            "entries": mutated_entries_3,
            "epochs": bundle.epochs + [rogue_cert],
        }
    )

    report_3 = verify_evidence(case3_bundle, pins)
    assert report_3.verdict == "TAMPERED", "Rogue epoch must yield TAMPERED verdict"
    entry_report_3 = next(e for e in report_3.entries if e.seq == 2)
    assert "certificate chain, epoch validity or revocation failed" in entry_report_3.reasons, (
        "Must specifically report certificate chain failure"
    )

    # =========================================================================
    # Case 4: Revoked epoch cert: entries after revocation rejected; before still verified
    # =========================================================================
    revocation_time = "2026-01-01T00:05:00.000Z"
    revocation_notice = sign_structure(
        Revocation(
            log_id=pins.log_id,
            intermediate_id="intermediate-0",
            effective_time=revocation_time,
        ),
        root_key[0],
        "revocation",
    )

    pins_with_revocation = pins.model_copy(update={"revocations": [revocation_notice]})
    report_4 = verify_evidence(bundle, pins_with_revocation)
    assert report_4.verdict == "TAMPERED"

    # Entries 0..3 were signed in epoch 0 before revocation_time (00:00 to 00:04:59.999) -> VERIFIED
    for s in range(4):
        e_report = next(e for e in report_4.entries if e.seq == s)
        assert "certificate chain, epoch validity or revocation failed" not in e_report.reasons, (
            f"Entry seq {s} before revocation must not fail certificate verification"
        )

    # Entries 4..9 were signed at or after revocation_time (00:05:00.000Z onwards) -> TAMPERED
    for s in range(4, 10):
        e_report = next(e for e in report_4.entries if e.seq == s)
        assert e_report.verdict == "TAMPERED"
        assert "certificate chain, epoch validity or revocation failed" in e_report.reasons, (
            f"Entry seq {s} after revocation must fail certificate verification"
        )

    # =========================================================================
    # Case 5: Attacker with stolen key appends forged entries to already-witnessed log
    # Witness refuses cosignature without valid consistency proof (bad_proof)
    # =========================================================================
    first_checkpoint = bundle.checkpoints[-1].checkpoint
    assert first_checkpoint.tree_size == 10

    # Attacker appends forged entry seq 10 signed with stolen epoch1 key
    forged_body_10 = dict(
        format_version="4",
        log_id=bundle.log_id,
        epoch_id=1,
        seq=10,
        signer_timestamp="2026-01-01T00:09:59.000Z",
        prev_hash=bundle.entries[-1]["body"]["prev_hash"],
        lane="agent",
        epoch_certificate_id=certificate_id(cert1),
        type="action",
        action_name="forged_append",
        reason="stolen key append",
        target_reference="target-10",
    )
    forged_entry_10 = seal(parse_entry(forged_body_10), epoch1_key[0])
    extended_entries = [schemas.SealedEntry.model_validate(e) for e in bundle.entries] + [
        forged_entry_10
    ]
    extended_tree = MerkleTree([sealed_bytes(e) for e in extended_entries])

    forged_checkpoint = sign_checkpoint(
        build_checkpoint(
            bundle.log_id,
            11,
            encode_hash(extended_tree.root()),
            10,
            1,
            "2026-01-01T00:09:59.000Z",
            latest_entry_hash=encode_hash(sha256(sealed_bytes(forged_entry_10))),
        ),
        epoch1_key[0],
    )

    # Setup witness client
    w_key = keys[4]
    key_path = tmp_path / "w0_e11.raw"
    key_path.write_bytes(w_key[0].private_bytes_raw())
    key_path.chmod(0o600)
    witness_config = WitnessConfig(
        root_public_key=pins.root_public_key,
        witness_set=bundle.witness_set,
        intermediates=bundle.intermediates,
        epochs=bundle.epochs,
        witness_id="w0",
        witness_key_path=key_path,
        state_dir=tmp_path / "witness_state",
        evidence_dir=tmp_path / "witness_evidence",
        bearer_token="token-e11",
        clock=lambda: "2026-01-01T01:00:00.000Z",
    )
    client = TestClient(create_app(witness_config))
    headers = {"Authorization": "Bearer token-e11"}

    # Initial checkpoint at tree_size 10 is accepted
    res_init = client.post(
        "/v1/checkpoint",
        json={
            "log_id": bundle.log_id,
            "checkpoint": first_checkpoint.model_dump(mode="json"),
            "from_size": 0,
            "consistency_proof": [],
        },
        headers=headers,
    )
    assert res_init.status_code == 200, "Witness must accept initial legitimate checkpoint"

    # Attacker submits forged checkpoint at tree_size 11 without valid consistency proof
    res_forged = client.post(
        "/v1/checkpoint",
        json={
            "log_id": bundle.log_id,
            "checkpoint": forged_checkpoint.model_dump(mode="json"),
            "from_size": 10,
            "consistency_proof": [],  # Empty or invalid consistency proof
        },
        headers=headers,
    )
    assert res_forged.status_code == 409, (
        "Witness must refuse checkpoint lacking valid consistency proof"
    )
    assert res_forged.json()["error"]["code"] == "bad_proof", (
        "Refusal error code must specifically be bad_proof"
    )

    # Verify witness recorded the refusal alarm
    alarms = client.get("/v1/alarms", params={"log_id": bundle.log_id}, headers=headers).json()
    assert any(a.get("alarm_type") == "WITNESS_REFUSAL" for a in alarms), (
        "Witness must record WITNESS_REFUSAL alarm"
    )
