"""L1b ledger append/read integration coverage."""

from __future__ import annotations

import os

import psycopg
import pytest
from fastapi.testclient import TestClient

from services.ledger.main import create_app
from tests.integration.support import get_test_dsn

pytestmark = pytest.mark.integration


def test_ledger_health_and_bounded_reads() -> None:
    os.environ["LEDGER_DATABASE_URL"] = get_test_dsn()
    os.environ["LEDGER_AUTH_TOKEN"] = "test-ledger-token"
    client = TestClient(create_app())
    assert client.get("/health").json() == {"status": "ok"}
    response = client.get(
        "/entries?from=0&to=1001", headers={"authorization": "Bearer test-ledger-token"}
    )
    assert response.status_code == 422


def test_conflicts_table_is_available() -> None:
    with psycopg.connect(get_test_dsn()) as connection:
        assert connection.execute("SELECT to_regclass('blackbox.conflicts')").fetchone() == (
            "blackbox.conflicts",
        )
