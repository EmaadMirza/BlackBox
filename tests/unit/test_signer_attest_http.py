"""A1 HTTP boundary tests."""

from fastapi.testclient import TestClient

from services.signer.main import create_app


def test_attest_requires_exact_request_shape(monkeypatch) -> None:
    monkeypatch.setenv("SIGNER_AUTH_TOKEN", "secret")
    client = TestClient(create_app(sealer=object()))
    response = client.post(
        "/attest",
        headers={"Authorization": "Bearer secret"},
        json={"intent_seq": 1, "body_digest": "sha256:" + "a" * 64},
    )
    assert response.status_code == 422
    assert response.json() == {"error": {"code": "invalid_request", "message": "Invalid request."}}


def test_attest_sanitizes_unavailable_signer(monkeypatch) -> None:
    monkeypatch.setenv("SIGNER_AUTH_TOKEN", "secret")
    response = TestClient(create_app()).post(
        "/attest",
        headers={"Authorization": "Bearer secret"},
        json={"intent_seq": 1},
    )
    assert response.status_code == 503
    assert response.json() == {
        "error": {"code": "signer_unavailable", "message": "Signer unavailable."}
    }
