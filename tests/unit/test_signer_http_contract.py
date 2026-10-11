"""Declaration-level signer HTTP contract checks; these do not exercise routes."""

from __future__ import annotations

import json

import pytest
from pydantic import ValidationError

from libs.blackbox_core import schemas
from services.signer import http_contract as contract


def test_paths_and_authorization_contract() -> None:
    assert contract.HEALTH_PATH == "/health"
    assert contract.SEAL_PATH == "/seal"
    assert contract.ATTEST_PATH == "/attest"
    assert contract.CHECKPOINT_PATH == "/checkpoint"
    assert contract.AUTH_HEADER == "Authorization"
    assert contract.AUTH_SCHEME == "Bearer"
    assert contract.AUTH_TOKEN_ENV == "SIGNER_AUTH_TOKEN"


def test_health_serializes_exact_liveness_response() -> None:
    assert json.loads(contract.HealthResponse().model_dump_json()) == {"status": "ok"}
    with pytest.raises(ValidationError):
        contract.HealthResponse(status="ready")
    with pytest.raises(ValidationError):
        contract.HealthResponse(status="ok", extra=True)


@pytest.mark.parametrize("seq", [0, 1, 2**53 - 1])
def test_attest_request_accepts_core_sequence_range(seq: int) -> None:
    request = contract.AttestRequest.model_validate_json(json.dumps({"intent_seq": seq}))
    assert request.model_dump() == {"intent_seq": seq}


@pytest.mark.parametrize(
    "payload",
    [
        {},
        {"intent_seq": 1, "body_digest": "client-supplied"},
        {"intent_seq": 1, "unknown": 0.5},
        {"intent_seq": 1.0},
        {"intent_seq": 0.5},
        {"intent_seq": True},
        {"intent_seq": "1"},
        {"intent_seq": None},
        {"intent_seq": -1},
        {"intent_seq": 2**53},
    ],
)
def test_attest_request_rejects_non_strict_or_unknown_data(payload: dict[str, object]) -> None:
    with pytest.raises(ValidationError):
        contract.AttestRequest.model_validate_json(json.dumps(payload))


def test_error_response_is_exact_non_sensitive_envelope() -> None:
    detail = contract.ErrorDetail(code="invalid_auth", message="Authentication required.")
    response = contract.ErrorResponse(error=detail)
    assert json.loads(response.model_dump_json()) == {
        "error": {"code": "invalid_auth", "message": "Authentication required."}
    }


@pytest.mark.parametrize(
    "payload",
    [
        {"error": {"code": "invalid_auth"}},
        {"error": {"code": 401, "message": "Authentication required."}},
        {"error": {"code": "invalid_auth", "message": 401}},
        {"error": {"code": "invalid_auth", "message": "Rejected", "token": "secret"}},
        {"error": {"code": "invalid_auth", "message": "Rejected"}, "detail": []},
    ],
)
def test_error_envelope_rejects_missing_wrong_type_and_extra_fields(
    payload: dict[str, object],
) -> None:
    with pytest.raises(ValidationError):
        contract.ErrorResponse.model_validate_json(json.dumps(payload))


def test_signed_wire_types_are_existing_core_types() -> None:
    assert contract.Entry is schemas.Entry
    assert contract.SealedEntry is schemas.SealedEntry
    assert contract.Attestation is schemas.Attestation
    assert contract.Checkpoint is schemas.Checkpoint
