"""L4b real-Postgres evidence-bundle export integration tests."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import psycopg
import pytest
from fastapi.testclient import TestClient
from psycopg.types.json import Jsonb

from libs.blackbox_core.checkpoint import build_cosignature
from libs.blackbox_core.evidence import Bundle, PinnedKeys
from libs.blackbox_core.schemas import Checkpoint
from libs.blackbox_core.signing import structure_hash
from services.ledger.main import create_app
from services.signer import delivery
from tests._dev_keys import dev_key
from tests.integration.support import get_test_dsn
from tests.integration.test_l2_delivery_e2e import InProcessPostgresTransport, _drain, _setup
from tests.integration.test_l3c_checkpointer import _checkpoint_app
from tools.verifier.verify import verify_evidence

pytestmark = pytest.mark.integration

AUTH = {"Authorization": "Bearer ledger-token"}
PROJECT = Path(__file__).resolve().parents[2]


def test_bundle_export_contains_complete_evidence_and_cli_verifies(monkeypatch, tmp_path) -> None:
    material, _, ledger_client, signer = _setup(monkeypatch, tmp_path)
    _, _, _, log_id, intermediate_cert, epoch_cert, witness_set, pins = material
    _drain(
        delivery.DeliveryWorker(
            signer,
            InProcessPostgresTransport(ledger_client),
            bearer_token="ledger-token",
        ),
        1,
    )
    checkpoint_app, signer_client, _ = _checkpoint_app(material, signer)
    try:
        with TestClient(checkpoint_app) as checkpoint_client:
            checkpoint_response = checkpoint_client.post("/checkpoint/now", headers=AUTH)
            assert checkpoint_response.status_code == 200, checkpoint_response.text

        checkpoint = json.loads(checkpoint_response.text)
        checkpoint_model = Checkpoint.model_validate(checkpoint)
        witness_key = dev_key(4)
        cosignature = build_cosignature(
            structure_hash(checkpoint_model),
            "w0",
            checkpoint["signer_timestamp"],
            witness_key,
            log_id=log_id,
        )
        with psycopg.connect(get_test_dsn()) as connection:
            connection.execute(
                "INSERT INTO blackbox.cosignatures(checkpoint_hash, witness_id, cosignature) VALUES (%s, %s, %s)",
                (
                    structure_hash(checkpoint_model),
                    "w0",
                    Jsonb(cosignature.model_dump(mode="json")),
                ),
            )

        export_app = create_app(
            bundle_log_name=pins.log_name,
            bundle_witness_set=witness_set,
        )
        with TestClient(export_app) as client:
            response = client.get("/bundle", params={"from": 0, "to": 0}, headers=AUTH)
            assert response.status_code == 200, response.text
            bundle = Bundle.model_validate(response.json())

        assert bundle.log_id == log_id
        assert len(bundle.entries) == 1
        assert bundle.checkpoints[0].checkpoint.tree_size == 1
        assert len(bundle.checkpoints[0].cosignatures) == 1
        assert bundle.inclusion_proofs[0].seq == 0
        assert bundle.epochs == [epoch_cert]
        assert bundle.intermediates == [intermediate_cert]
        assert bundle.witness_set == witness_set

        pins_path = tmp_path / "pinned-keys.json"
        bundle_path = tmp_path / "bundle.json"
        pins_path.write_text(pins.model_dump_json(), encoding="utf-8")
        bundle_path.write_text(bundle.model_dump_json(), encoding="utf-8")
        report = verify_evidence(bundle, PinnedKeys.model_validate_json(pins_path.read_bytes()))
        assert report.verdict == "VERIFIED", report.to_dict()

        cli = subprocess.run(
            [
                sys.executable,
                "-m",
                "tools.cli",
                "verify",
                str(bundle_path),
                "--pinned-keys",
                str(pins_path),
            ],
            cwd=PROJECT,
            capture_output=True,
            text=True,
            env={"PATH": "/usr/bin:/bin", "PYTHONPATH": str(PROJECT)},
        )
        assert cli.returncode == 0, cli.stdout + cli.stderr
        assert json.loads(cli.stdout)["verdict"] == "VERIFIED"
    finally:
        signer_client.close()
        ledger_client.close()


@pytest.mark.parametrize(
    "params",
    [
        {"from": 1, "to": 1},
        {"from": 0, "to": 100},
        {"from": 0, "to": -1},
    ],
)
def test_bundle_export_rejects_non_prefix_or_unavailable_ranges(
    monkeypatch, tmp_path, params
) -> None:
    material, _, ledger_client, signer = _setup(monkeypatch, tmp_path)
    _, _, _, _, _, _, witness_set, pins = material
    _drain(
        delivery.DeliveryWorker(
            signer,
            InProcessPostgresTransport(ledger_client),
            bearer_token="ledger-token",
        ),
        1,
    )
    app = create_app(bundle_log_name=pins.log_name, bundle_witness_set=witness_set)
    try:
        with TestClient(app) as client:
            response = client.get("/bundle", params=params, headers=AUTH)
        assert response.status_code == 422
        assert response.json()["error"]["code"] in {
            "invalid_bundle_range",
            "bundle_unavailable",
        }
    finally:
        ledger_client.close()
