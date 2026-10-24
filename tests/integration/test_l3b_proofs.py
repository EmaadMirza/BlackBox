"""L3b real-Postgres proof endpoint integration tests."""

from __future__ import annotations

import os

import psycopg
import pytest
from fastapi.testclient import TestClient
from psycopg.types.json import Jsonb

from libs.blackbox_core import merkle
from libs.blackbox_core.encoding import decode_hash, encode_hash
from libs.blackbox_core.sealing import sealed_bytes
from services.ledger.main import create_app
from tests.integration.support import get_test_dsn, reset_database
from tests.integration.test_l3_merkle import LOG_ID, populate

pytestmark = pytest.mark.integration

AUTH = {"Authorization": "Bearer ledger-token"}


def _client() -> TestClient:
    os.environ["LEDGER_DATABASE_URL"] = get_test_dsn()
    os.environ["LEDGER_AUTH_TOKEN"] = "ledger-token"
    return TestClient(create_app(), raise_server_exceptions=False)


def _stored_leaves() -> list[bytes]:
    with psycopg.connect(get_test_dsn()) as connection:
        rows = connection.execute(
            "SELECT sealed_entry FROM blackbox.entries WHERE log_id=%s ORDER BY seq",
            (LOG_ID,),
        ).fetchall()
    from libs.blackbox_core.schemas import SealedEntry

    return [sealed_bytes(SealedEntry.model_validate(row[0])) for row in rows]


def test_inclusion_proofs_match_core_for_all_sizes_1_to_100() -> None:
    reset_database()
    with psycopg.connect(get_test_dsn()) as connection:
        with connection.transaction():
            populate(connection, 100)
    leaves = _stored_leaves()

    with _client() as client:
        for tree_size in range(1, 101):
            expected_root = merkle.root(leaves[:tree_size])
            for seq in range(tree_size):
                response = client.get(
                    "/proof/inclusion",
                    params={"seq": seq, "tree_size": tree_size},
                    headers=AUTH,
                )
                assert response.status_code == 200, response.text
                payload = response.json()
                expected = merkle.inclusion_proof(seq, tree_size, leaves[:tree_size])
                proof = [decode_hash(item) for item in payload["proof"]]
                assert payload == {
                    "seq": seq,
                    "tree_size": tree_size,
                    "proof": [encode_hash(item) for item in expected],
                }
                assert merkle.verify_inclusion(
                    merkle.leaf_hash(leaves[seq]), seq, tree_size, proof, expected_root
                )


def test_consistency_proofs_match_core_for_all_pairs_1_to_100() -> None:
    reset_database()
    with psycopg.connect(get_test_dsn()) as connection:
        with connection.transaction():
            populate(connection, 100)
    leaves = _stored_leaves()

    with _client() as client:
        for old_size in range(1, 100):
            for new_size in range(old_size + 1, 101):
                response = client.get(
                    "/proof/consistency",
                    params={"from": old_size, "to": new_size},
                    headers=AUTH,
                )
                assert response.status_code == 200, response.text
                payload = response.json()
                expected = merkle.consistency_proof(old_size, new_size, leaves[:new_size])
                proof = [decode_hash(item) for item in payload["proof"]]
                assert payload == {
                    "old_size": old_size,
                    "new_size": new_size,
                    "proof": [encode_hash(item) for item in expected],
                }
                assert merkle.verify_consistency(
                    old_size,
                    new_size,
                    merkle.root(leaves[:old_size]),
                    merkle.root(leaves[:new_size]),
                    proof,
                )


@pytest.mark.parametrize(
    ("path", "params", "code"),
    [
        ("/proof/inclusion", {"seq": "0", "tree_size": "0"}, "invalid_proof_range"),
        ("/proof/inclusion", {"seq": "-1", "tree_size": "1"}, "invalid_query"),
        ("/proof/inclusion", {"seq": "1", "tree_size": "1"}, "invalid_proof_range"),
        ("/proof/inclusion", {"seq": "0", "tree_size": "101"}, "invalid_proof_range"),
        ("/proof/inclusion", {"seq": "0", "tree_size": "1.0"}, "invalid_query"),
        ("/proof/consistency", {"from": "0", "to": "1"}, "invalid_proof_range"),
        ("/proof/consistency", {"from": "2", "to": "1"}, "invalid_proof_range"),
        ("/proof/consistency", {"from": "1", "to": "1"}, "invalid_proof_range"),
        ("/proof/consistency", {"from": "1", "to": "0"}, "invalid_proof_range"),
        ("/proof/consistency", {"from": "1", "to": "101"}, "invalid_proof_range"),
        ("/proof/consistency", {"from": "1.0", "to": "2"}, "invalid_query"),
    ],
)
def test_invalid_zero_future_reversed_and_non_integer_ranges_are_rejected(
    path: str, params: dict[str, str], code: str
) -> None:
    reset_database()
    with psycopg.connect(get_test_dsn()) as connection:
        with connection.transaction():
            populate(connection, 3)

    with _client() as client:
        response = client.get(path, params=params, headers=AUTH)
    assert response.status_code == 422
    assert response.json()["error"]["code"] == code
    assert "Traceback" not in response.text


def test_strict_query_keys_and_duplicate_parameters_are_rejected() -> None:
    reset_database()
    with psycopg.connect(get_test_dsn()) as connection:
        with connection.transaction():
            populate(connection, 3)

    with _client() as client:
        unknown = client.get(
            "/proof/inclusion",
            params={"seq": "0", "tree_size": "1", "extra": "1"},
            headers=AUTH,
        )
        duplicate = client.get(
            "/proof/inclusion",
            params=[("seq", "0"), ("seq", "0"), ("tree_size", "1")],
            headers=AUTH,
        )
    assert unknown.status_code == 422
    assert duplicate.status_code == 422
    assert unknown.json()["error"]["code"] == "invalid_query"
    assert duplicate.json()["error"]["code"] == "invalid_query"


def test_future_ranges_are_rejected_against_current_tree_size() -> None:
    reset_database()
    with psycopg.connect(get_test_dsn()) as connection:
        with connection.transaction():
            populate(connection, 3)

    with _client() as client:
        inclusion = client.get("/proof/inclusion", params={"seq": 3, "tree_size": 4}, headers=AUTH)
        consistency = client.get("/proof/consistency", params={"from": 2, "to": 4}, headers=AUTH)
    assert inclusion.status_code == 422
    assert consistency.status_code == 422
    assert inclusion.json()["error"]["code"] == "invalid_proof_range"
    assert consistency.json()["error"]["code"] == "invalid_proof_range"


def test_tampered_stored_row_proof_fails_against_signed_checkpoint_root() -> None:
    reset_database()
    with psycopg.connect(get_test_dsn()) as connection:
        with connection.transaction():
            entries = populate(connection, 3)
    signed_root = merkle.root([sealed_bytes(entry) for entry in entries])

    with psycopg.connect(get_test_dsn()) as connection:
        connection.execute("ALTER TABLE blackbox.entries DISABLE TRIGGER entries_no_mutation")
        payload = entries[1].model_dump(mode="json")
        payload["body"]["reason"] = "tampered-after-checkpoint"
        connection.execute(
            "UPDATE blackbox.entries SET sealed_entry=%s WHERE log_id=%s AND seq=%s",
            (Jsonb(payload), LOG_ID, 1),
        )
        connection.execute("ALTER TABLE blackbox.entries ENABLE TRIGGER entries_no_mutation")

    with _client() as client:
        response = client.get("/proof/inclusion", params={"seq": 1, "tree_size": 3}, headers=AUTH)
    assert response.status_code == 200
    proof = [decode_hash(item) for item in response.json()["proof"]]
    tampered_leaf = merkle.leaf_hash(_stored_leaves()[1])
    assert not merkle.verify_inclusion(tampered_leaf, 1, 3, proof, signed_root)


def test_proofs_remain_correct_after_ledger_restart() -> None:
    reset_database()
    with psycopg.connect(get_test_dsn()) as connection:
        with connection.transaction():
            populate(connection, 8)
    leaves = _stored_leaves()

    with _client() as first_client:
        first_inclusion = first_client.get(
            "/proof/inclusion", params={"seq": 5, "tree_size": 8}, headers=AUTH
        )
        first_consistency = first_client.get(
            "/proof/consistency", params={"from": 3, "to": 8}, headers=AUTH
        )

    with _client() as restarted_client:
        second_inclusion = restarted_client.get(
            "/proof/inclusion", params={"seq": 5, "tree_size": 8}, headers=AUTH
        )
        second_consistency = restarted_client.get(
            "/proof/consistency", params={"from": 3, "to": 8}, headers=AUTH
        )

    assert first_inclusion.status_code == second_inclusion.status_code == 200
    assert first_consistency.status_code == second_consistency.status_code == 200
    assert first_inclusion.json() == second_inclusion.json()
    assert first_consistency.json() == second_consistency.json()
    assert merkle.verify_inclusion(
        merkle.leaf_hash(leaves[5]),
        5,
        8,
        [decode_hash(item) for item in second_inclusion.json()["proof"]],
        merkle.root(leaves),
    )
