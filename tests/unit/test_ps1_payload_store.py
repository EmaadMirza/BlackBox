"""PS1 payload commitments and isolated payload store tests."""

from pathlib import Path

from fastapi.testclient import TestClient

from libs.blackbox_core.commitments import commit, create_salt, verify_opening
from services.payload_store.main import PayloadStore, create_app


def test_commitment_requires_32_byte_salt_and_verifies_opening():
    value = b'{"amount_minor":1250}'
    salt = create_salt()
    commitment = commit(value, salt)
    assert len(salt) == 32
    assert verify_opening(commitment, value, salt)
    assert not verify_opening(commitment, b'{"amount_minor":1251}', salt)
    assert not verify_opening(commitment, value, b"wrong-salt")


def test_payload_store_requires_auth_and_supports_crypto_shredding(tmp_path: Path):
    store = PayloadStore(tmp_path, bearer_token="payload-token")
    value = b'{"amount_minor":1250}'
    reference, commitment = store.put(value)
    salt = store.salt(reference)
    assert verify_opening(commitment, value, salt)
    with TestClient(create_app(store)) as client:
        assert client.get(f"/v1/payloads/{reference}").status_code == 401
        opened = client.get(
            f"/v1/payloads/{reference}", headers={"Authorization": "Bearer payload-token"}
        )
        assert opened.status_code == 200
        assert opened.json()["commitment"] == commitment
        assert opened.json()["value"] == value.decode()
        assert (
            client.delete(
                f"/v1/payloads/{reference}", headers={"Authorization": "Bearer payload-token"}
            ).status_code
            == 204
        )
        assert (
            client.get(
                f"/v1/payloads/{reference}", headers={"Authorization": "Bearer payload-token"}
            ).status_code
            == 404
        )
    assert verify_opening(commitment, value, salt)


def test_payload_store_rejects_duplicate_json_keys_and_sanitizes_errors(tmp_path: Path):
    store = PayloadStore(tmp_path, bearer_token="token")
    with TestClient(create_app(store)) as client:
        response = client.post(
            "/v1/payloads",
            content=b'{"value":"x","value":"y"}',
            headers={"Authorization": "Bearer token", "Content-Type": "application/json"},
        )
    assert response.status_code == 422
    assert response.json() == {"error": {"code": "malformed", "message": "Malformed request."}}


def test_payload_store_files_do_not_log_plaintext_value(tmp_path: Path):
    store = PayloadStore(tmp_path, bearer_token="token")
    secret = b"super-secret-payload"
    reference, _ = store.put(secret)
    raw = (tmp_path / f"{reference}.json").read_bytes()
    assert secret not in raw
