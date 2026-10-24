"""L3a real-Postgres Merkle frontier integration tests."""

from __future__ import annotations

import psycopg
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient
from hypothesis import given, settings
from hypothesis import strategies as st
from psycopg.types.json import Jsonb

from libs.blackbox_core import merkle
from libs.blackbox_core.chain import GENESIS_PREV_HASH, entry_hash
from libs.blackbox_core.schemas import SealedEntry, parse_entry
from libs.blackbox_core.sealing import seal, sealed_bytes
from services.ledger import merkle_store
from services.ledger.main import create_app
from tests._dev_keys import dev_key
from tests.integration.support import execute, get_test_dsn, reset_database
from tests.unit.test_schemas import action

pytestmark = pytest.mark.integration

LOG_ID = "sha256:" + "2" * 64
CERTIFICATE_ID = "sha256:" + "3" * 64
NOW = "2026-01-01T00:01:00.000Z"


def make_entry(seq: int, previous: str, key: Ed25519PrivateKey) -> SealedEntry:
    body = action()
    body.update(
        log_id=LOG_ID,
        epoch_id=0,
        seq=seq,
        prev_hash=previous,
        epoch_certificate_id=CERTIFICATE_ID,
        signer_timestamp=NOW,
    )
    return seal(parse_entry(body), key)


def insert_with_frontier(connection, entry: SealedEntry) -> None:
    connection.execute(
        """INSERT INTO blackbox.entries
        (log_id, seq, sealed_entry, entry_hash, prev_hash, epoch_id, type)
        VALUES (%s,%s,%s,%s,%s,%s,%s)""",
        (
            LOG_ID,
            entry.body.seq,
            Jsonb(entry.model_dump(mode="json")),
            entry_hash(entry.body),
            entry.body.prev_hash,
            entry.body.epoch_id,
            entry.body.type,
        ),
    )
    merkle_store.append_in_transaction(connection, entry)


def populate(connection, count: int) -> list[SealedEntry]:
    key = dev_key(6)
    entries: list[SealedEntry] = []
    previous = GENESIS_PREV_HASH
    for seq in range(count):
        entry = make_entry(seq, previous, key)
        insert_with_frontier(connection, entry)
        entries.append(entry)
        previous = entry_hash(entry.body)
    return entries


def test_frontier_root_matches_core_for_every_size_1_to_200() -> None:
    reset_database()
    with psycopg.connect(get_test_dsn()) as connection:
        with connection.transaction():
            leaves: list[bytes] = []
            previous = GENESIS_PREV_HASH
            key = dev_key(6)
            for size in range(1, 201):
                entry = make_entry(size - 1, previous, key)
                insert_with_frontier(connection, entry)
                leaves.append(sealed_bytes(entry))
                previous = entry_hash(entry.body)
                assert merkle_store.current_root(connection, LOG_ID) == merkle.root(leaves)
                tree_size, _ = merkle_store.load_frontier(connection, LOG_ID)
                assert tree_size == size


@settings(max_examples=4, deadline=None)
@given(st.lists(st.binary(min_size=1, max_size=32), min_size=1, max_size=24))
def test_hypothesis_frontier_matches_reference_and_reloads(leaves: list[bytes]) -> None:
    reset_database()
    with psycopg.connect(get_test_dsn()) as connection:
        with connection.transaction():
            for leaf in leaves:
                merkle_store.append_leaf_in_transaction(connection, LOG_ID, leaf)
            assert merkle_store.current_root(connection, LOG_ID) == merkle.root(leaves)
            expected_size, expected_frontier = merkle_store.load_frontier(connection, LOG_ID)
    with psycopg.connect(get_test_dsn()) as connection:
        actual_size, actual_frontier = merkle_store.load_frontier(connection, LOG_ID)
        assert (actual_size, actual_frontier) == (expected_size, expected_frontier)


def test_insert_and_frontier_are_one_transaction(monkeypatch: pytest.MonkeyPatch) -> None:
    reset_database()
    entry = make_entry(0, GENESIS_PREV_HASH, dev_key(7))

    def fail_after_entry(*_args, **_kwargs):
        raise OSError("frontier write failed")

    monkeypatch.setattr(merkle_store, "append_in_transaction", fail_after_entry)
    with pytest.raises(OSError, match="frontier write failed"):
        with psycopg.connect(get_test_dsn()) as connection:
            with connection.transaction():
                insert_with_frontier(connection, entry)
    assert execute("SELECT count(*) FROM blackbox.entries")[0][0] == 0
    assert execute("SELECT count(*) FROM blackbox.merkle_frontiers")[0][0] == 0


def test_restart_mismatch_blocks_checkpoints_but_not_reads(monkeypatch: pytest.MonkeyPatch) -> None:
    reset_database()
    with psycopg.connect(get_test_dsn()) as connection:
        with connection.transaction():
            populate(connection, 2)
        connection.execute(
            "ALTER TABLE blackbox.merkle_frontiers DISABLE TRIGGER merkle_frontiers_no_mutation"
        )
        connection.execute(
            "UPDATE blackbox.merkle_frontiers SET root_hash=%s WHERE log_id=%s",
            ("sha256:" + "f" * 64, LOG_ID),
        )
        connection.execute(
            "ALTER TABLE blackbox.merkle_frontiers ENABLE TRIGGER merkle_frontiers_no_mutation"
        )

    monkeypatch.setenv("LEDGER_DATABASE_URL", get_test_dsn())
    monkeypatch.setenv("LEDGER_AUTH_TOKEN", "ledger-token")
    client = TestClient(create_app(), raise_server_exceptions=False)
    headers = {"Authorization": "Bearer ledger-token"}
    checkpoint = client.get("/checkpoints/latest", headers=headers)
    assert checkpoint.status_code == 503
    assert checkpoint.json()["error"]["code"] == merkle_store.MERKLE_FRONTIER_MISMATCH
    reads = client.get("/entries?from=0&to=0", headers=headers)
    assert reads.status_code == 200


def test_ledger_app_cannot_mutate_frontier() -> None:
    reset_database()
    with psycopg.connect(get_test_dsn(), autocommit=True) as connection:
        with connection.transaction():
            merkle_store.append_leaf_in_transaction(connection, LOG_ID, b"leaf")
        connection.execute("SET ROLE ledger_app")
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            with connection.transaction():
                connection.execute("UPDATE blackbox.merkle_frontiers SET root_hash=root_hash")
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            with connection.transaction():
                connection.execute("DELETE FROM blackbox.merkle_frontiers")
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            with connection.transaction():
                connection.execute("TRUNCATE blackbox.merkle_frontiers")
