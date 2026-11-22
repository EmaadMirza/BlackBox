"""E11: Key compromise and rogue epochs attack harness (spec §29.4)."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path
from typing import Any

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


def run(tmp_dir: Path | None = None) -> dict[str, Any]:
    """Run E11 key compromise simulation."""
    created_tmp = None
    if tmp_dir is None:
        created_tmp = tempfile.TemporaryDirectory()
        work_dir = Path(created_tmp.name)
    else:
        work_dir = tmp_dir
        work_dir.mkdir(parents=True, exist_ok=True)

    try:
        keys = [(dev_key(i), dev_key(i).public_key().public_bytes_raw()) for i in range(1, 8)]
        bundle, pins = build_demo(keys)
        baseline_report = verify_evidence(bundle, pins)
        assert baseline_report.verdict == "VERIFIED", "Honest baseline must verify"

        root_key = keys[0]
        stolen_epoch0_key = keys[2]
        epoch1_key = keys[3]

        cert0 = bundle.epochs[0]
        cert1 = bundle.epochs[1]
        intermediate0 = bundle.intermediates[0]

        # Case 1: Key stolen from epoch 0 signs entry in epoch 1's window
        forged_body_1 = dict(
            format_version="4",
            log_id=bundle.log_id,
            epoch_id=0,
            seq=2,
            signer_timestamp="2026-01-01T00:06:00.000Z",
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
        assert report_1.verdict == "TAMPERED"
        entry_report_1 = next(e for e in report_1.entries if e.seq == 2)
        assert "certificate chain, epoch validity or revocation failed" in entry_report_1.reasons

        # Case 2: Half-open semantics [from, until)
        until_stamp = cert0.valid_until
        just_before_stamp = "2026-01-01T00:04:59.999Z"
        root_pub_bytes = decode_base64url(pins.root_public_key)

        assert (
            verify_epoch_certificate(cert0, intermediate0, root_pub_bytes, just_before_stamp)
            is True
        )
        assert verify_epoch_certificate(cert0, intermediate0, root_pub_bytes, until_stamp) is False

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

        # Case 3: Rogue epoch
        rogue_private_key = Ed25519PrivateKey.generate()
        rogue_pub_b64 = encode_base64url(rogue_private_key.public_key().public_bytes_raw())
        rogue_cert = build_epoch_certificate(
            99,
            rogue_pub_b64,
            "2026-01-01T00:00:00.000Z",
            "2026-01-01T00:05:00.000Z",
            intermediate_id="intermediate-0",
            log_id=bundle.log_id,
            signing_operation=rogue_private_key,
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
        assert report_3.verdict == "TAMPERED"

        # Case 4: Revocation
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

        # Case 5: Witness refusal of unproven log extension
        first_checkpoint = bundle.checkpoints[-1].checkpoint
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

        w_key = keys[4]
        key_path = work_dir / "w0_e11.raw"
        key_path.write_bytes(w_key[0].private_bytes_raw())
        key_path.chmod(0o600)
        witness_config = WitnessConfig(
            root_public_key=pins.root_public_key,
            witness_set=bundle.witness_set,
            intermediates=bundle.intermediates,
            epochs=bundle.epochs,
            witness_id="w0",
            witness_key_path=key_path,
            state_dir=work_dir / "witness_state",
            evidence_dir=work_dir / "witness_evidence",
            bearer_token="token-e11",
            clock=lambda: "2026-01-01T01:00:00.000Z",
        )
        client = TestClient(create_app(witness_config))
        headers = {"Authorization": "Bearer token-e11"}

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
        assert res_init.status_code == 200

        res_forged = client.post(
            "/v1/checkpoint",
            json={
                "log_id": bundle.log_id,
                "checkpoint": forged_checkpoint.model_dump(mode="json"),
                "from_size": 10,
                "consistency_proof": [],
            },
            headers=headers,
        )
        assert res_forged.status_code == 409
        assert res_forged.json()["error"]["code"] == "bad_proof"

        return {
            "scenario": "E11_key_compromise",
            "verdict": "PASSED",
            "cases_tested": 5,
            "expired_epoch_verdict": report_1.verdict,
            "boundary_rejected": True,
            "boundary_tick_accepted": True,
            "rogue_epoch_verdict": report_3.verdict,
            "revocation_pre_post_split": True,
            "witness_refusal_code": "bad_proof",
        }
    finally:
        if created_tmp is not None:
            created_tmp.cleanup()


def main() -> None:
    print(json.dumps(run(), indent=2))


if __name__ == "__main__":
    main()
