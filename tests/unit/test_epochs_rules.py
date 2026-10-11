"""Certificate trust/expiry and passing/failing pure signer rules."""

from dataclasses import replace

import pytest

from libs.blackbox_core.encoding import encode_base64url
from libs.blackbox_core.epochs import (
    build_epoch_certificate,
    build_intermediate_certificate,
    certificate_id,
    validate_contiguity,
    verify_epoch_certificate,
)
from libs.blackbox_core.errors import SignerRuleError
from libs.blackbox_core.labels import derive_log_id
from libs.blackbox_core.schemas import parse_entry
from libs.blackbox_core.signer_rules import SignerState, check_seal_request
from tests._dev_keys import dev_key
from tests.unit.test_schemas import action


def certificates() -> tuple:
    root, inter, epoch = [dev_key(i) for i in (1, 2, 3)]
    log = derive_log_id(root.public_key().public_bytes_raw(), "test")
    ic = build_intermediate_certificate(
        log,
        "i0",
        encode_base64url(inter.public_key().public_bytes_raw()),
        "2026-01-01T00:00:00.000Z",
        "2026-02-01T00:00:00.000Z",
        root,
    )
    ec = build_epoch_certificate(
        0,
        encode_base64url(epoch.public_key().public_bytes_raw()),
        "2026-01-01T00:00:00.000Z",
        "2026-01-01T00:05:00.000Z",
        "i0",
        log_id=log,
        signing_operation=inter,
    )
    return root, inter, epoch, ic, ec


def test_epoch_trust_and_boundaries() -> None:
    root, inter, epoch, ic, ec = certificates()
    pub = root.public_key().public_bytes_raw()
    assert verify_epoch_certificate(ec, ic, pub, ec.valid_from)
    assert not verify_epoch_certificate(ec, ic, pub, ec.valid_until)
    assert not verify_epoch_certificate(
        ec, ic, epoch.public_key().public_bytes_raw(), ec.valid_from
    )
    next_ec = build_epoch_certificate(
        1,
        ec.epoch_public_key,
        ec.valid_until,
        "2026-01-01T00:10:00.000Z",
        "i0",
        log_id=ec.log_id,
        signing_operation=inter,
    )
    validate_contiguity(ec, next_ec)
    with pytest.raises(ValueError):
        validate_contiguity(ec, next_ec.model_copy(update={"epoch_id": 3}))
    with pytest.raises(ValueError):
        validate_contiguity(ec, next_ec.model_copy(update={"valid_from": ec.valid_from}))


def fixture_state() -> tuple:
    *_, ec = certificates()
    data = action()
    data["log_id"] = ec.log_id
    data["epoch_certificate_id"] = certificate_id(ec)
    candidate = parse_entry(data)
    return SignerState(
        -1, candidate.prev_hash, 0, certificate_id(ec), ec.valid_from, ec.valid_until, ec.valid_from
    ), candidate


def test_valid_seal_rule() -> None:
    state, candidate = fixture_state()
    check_seal_request(state, candidate)


@pytest.mark.parametrize(
    "change",
    [
        {"last_seq": 1},
        {"last_hash": "sha256:" + "a" * 64},
        {"now": "2026-01-01T00:05:00.000Z"},
        {"entries_this_second": 1000},
        {"epoch_id": 1},
        {"epoch_certificate_id": "sha256:" + "a" * 64},
    ],
)
def test_invalid_seal_rule(change: dict) -> None:
    state, candidate = fixture_state()
    with pytest.raises(SignerRuleError):
        check_seal_request(replace(state, **change), candidate)


def test_reserved_type_and_invalid_schema() -> None:
    state, candidate = fixture_state()
    data = candidate.model_dump()
    for field in ("action_name", "reason", "target_reference"):
        data.pop(field)
    data["type"] = "epoch_end"
    entry = parse_entry(data)
    with pytest.raises(SignerRuleError):
        check_seal_request(state, entry)
    check_seal_request(replace(state, caller="signer"), entry)
    data["unknown"] = 1
    with pytest.raises(SignerRuleError):
        check_seal_request(state, data)


def request_pair() -> tuple:
    from libs.blackbox_core.schemas import Intent, Outcome

    state, entry = fixture_state()
    data = entry.model_dump()
    for key in ("action_name", "reason", "target_reference"):
        data.pop(key)
    data.update(
        type="intent",
        status="ready",
        principal=dict(
            client_key_id="c",
            source_address="local",
            human_identity="h",
            agent_identity="a",
            agent_version="1",
            delegation_chain=["h", "a"],
        ),
        action=dict(
            adapter="http",
            method="POST",
            path="/refund",
            tool_name="refund",
            body_digest="sha256:" + "a" * 64,
            arguments_commitment="sha256:" + "b" * 64,
            idempotency_key="sha256:" + "d" * 64,
            payload_reference="p",
        ),
        policy=dict(
            version="1",
            decision="allow",
            matching_rule_id="r",
            severity="high",
            approval_receipt_id=None,
        ),
        context=dict(
            system_prompt_hash="sha256:" + "1" * 64,
            tool_definitions_hash="sha256:" + "2" * 64,
            model_identifier="test",
            model_version="1",
            untrusted_inputs=[],
        ),
        claimed_time=state.now,
    )
    intent = Intent.model_validate(data)
    data.pop("status")
    data.update(
        type="outcome",
        intent_seq=0,
        upstream_status=200,
        result_commitment="sha256:" + "c" * 64,
        provider_request_id="p1",
        latency=1,
    )
    return state, intent, Outcome.model_validate(data)


def test_outcome_rules() -> None:
    state, intent, outcome = request_pair()
    with pytest.raises(SignerRuleError):
        check_seal_request(state, outcome)
    state = replace(state, intents={0: intent})
    check_seal_request(state, outcome)
    with pytest.raises(SignerRuleError):
        check_seal_request(replace(state, outcomes={0: outcome}), outcome)
    check_seal_request(
        replace(state, outcomes={0: outcome}), outcome.model_copy(update={"retry": True})
    )
    wrong = outcome.model_copy(
        update={
            "action": outcome.action.model_copy(update={"idempotency_key": "sha256:" + "f" * 64})
        }
    )
    with pytest.raises(SignerRuleError):
        check_seal_request(state, wrong)


def test_attestation_rules() -> None:
    from libs.blackbox_core.signer_rules import validate_attest

    _, intent, _ = request_pair()
    digest = intent.action.body_digest
    validate_attest(intent, digest, None, True, 0)
    validate_attest(intent, digest, digest, False, None)
    for requested, prior, risk, coverage in [
        ("sha256:" + "f" * 64, None, False, None),
        (digest, "sha256:" + "f" * 64, False, None),
        (digest, None, True, None),
        (digest, None, True, -1),
    ]:
        with pytest.raises(SignerRuleError):
            validate_attest(intent, requested, prior, risk, coverage)
    with pytest.raises(SignerRuleError):
        validate_attest(intent.model_copy(update={"status": "pending"}), digest, None, False, None)
