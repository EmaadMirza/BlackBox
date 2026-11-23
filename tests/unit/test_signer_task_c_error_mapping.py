"""Named Task C /seal failures have stable, sanitized public envelopes."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from services.signer.history import HistoryIntegrityError, HistorySourceError, OutcomeConflictError
from services.signer.main import create_app
from services.signer.state import OutcomeIndexError
from tests.unit.test_signer_seal_http import candidate


@pytest.mark.parametrize(
    ("failure", "status", "code"),
    [
        (HistorySourceError("source detail"), 503, "signer_unavailable"),
        (HistoryIntegrityError("history detail"), 409, "history_integrity"),
        (OutcomeConflictError("conflict detail"), 409, "outcome_conflict"),
        (OutcomeIndexError("index detail"), 409, "outcome_index_invalid"),
    ],
)
def test_named_task_c_failures_are_sanitized(
    monkeypatch: pytest.MonkeyPatch, failure: Exception, status: int, code: str
) -> None:
    monkeypatch.setenv("SIGNER_AUTH_TOKEN", "signer-secret")

    class FailingSealer:
        def seal(self, _candidate: object) -> None:
            raise failure

    response = TestClient(create_app(sealer=FailingSealer())).post(
        "/seal",
        json=candidate(),
        headers={"Authorization": "Bearer signer-secret"},
    )

    assert response.status_code == status
    assert response.json() == {
        "error": {
            "code": code,
            "message": {
                "signer_unavailable": "Signer unavailable.",
                "history_integrity": "History evidence failed integrity validation.",
                "outcome_conflict": "The intent already has a conflicting outcome.",
                "outcome_index_invalid": "Signer outcome state is invalid.",
            }[code],
        }
    }
    assert "detail" not in response.text
