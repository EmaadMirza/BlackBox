"""Runtime tests for signer liveness and transport authentication only."""

from __future__ import annotations

from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient

from services.signer.auth import install_error_handlers, require_bearer
from services.signer.main import create_app


def protected_app() -> FastAPI:
    app = FastAPI()
    install_error_handlers(app)

    @app.get("/protected", dependencies=[Depends(require_bearer)])
    async def protected() -> dict[str, str]:
        return {"status": "allowed"}

    return app


def test_health_is_unauthenticated_process_liveness(monkeypatch) -> None:
    monkeypatch.setenv("SIGNER_AUTH_TOKEN", "not-used-by-health")

    response = TestClient(create_app()).get("/health")

    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_health_remains_available_when_auth_configuration_is_invalid(monkeypatch) -> None:
    monkeypatch.setenv("SIGNER_AUTH_TOKEN", "bad token")

    response = TestClient(create_app()).get("/health")

    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_valid_bearer_token_allows_protected_operation(monkeypatch) -> None:
    monkeypatch.setenv("SIGNER_AUTH_TOKEN", "signer-secret")

    response = TestClient(protected_app()).get(
        "/protected", headers={"Authorization": "Bearer signer-secret"}
    )

    assert response.status_code == 200
    assert response.json() == {"status": "allowed"}


def test_missing_or_invalid_bearer_token_is_401(monkeypatch) -> None:
    monkeypatch.setenv("SIGNER_AUTH_TOKEN", "signer-secret")
    client = TestClient(protected_app())

    for headers in ({}, {"Authorization": "Basic signer-secret"}, {"Authorization": "Bearer"}):
        response = client.get("/protected", headers=headers)
        assert response.status_code == 401
        assert response.headers["www-authenticate"] == "Bearer"
        assert response.json() == {
            "error": {"code": "invalid_auth", "message": "Authentication required."}
        }


def test_bearer_token_is_case_insensitive_only_for_scheme(monkeypatch) -> None:
    monkeypatch.setenv("SIGNER_AUTH_TOKEN", "Signer-Secret")
    client = TestClient(protected_app())

    assert (
        client.get("/protected", headers={"Authorization": "bearer Signer-Secret"}).status_code
        == 200
    )
    assert (
        client.get("/protected", headers={"Authorization": "Bearer signer-secret"}).status_code
        == 401
    )


def test_duplicate_or_non_exact_authorization_is_401(monkeypatch) -> None:
    monkeypatch.setenv("SIGNER_AUTH_TOKEN", "signer-secret")
    client = TestClient(protected_app())

    duplicate = client.get(
        "/protected",
        headers=[
            ("Authorization", "Bearer signer-secret"),
            ("Authorization", "Bearer signer-secret"),
        ],
    )
    extra_space = client.get("/protected", headers={"Authorization": "Bearer  signer-secret"})

    assert duplicate.status_code == 401
    assert extra_space.status_code == 401


def test_invalid_configuration_fails_closed_with_503(monkeypatch) -> None:
    client = TestClient(protected_app())

    for invalid in (None, "", "signer secret", "é-token"):
        if invalid is None:
            monkeypatch.delenv("SIGNER_AUTH_TOKEN", raising=False)
        else:
            monkeypatch.setenv("SIGNER_AUTH_TOKEN", invalid)
        response = client.get("/protected")
        assert response.status_code == 503
        assert response.json() == {
            "error": {"code": "auth_unavailable", "message": "Authentication unavailable."}
        }
