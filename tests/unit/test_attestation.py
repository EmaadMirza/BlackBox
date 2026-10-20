"""A1 attestation rules and core verification."""

import pytest

from libs.blackbox_core.attestation import build_attestation, verify_attestation
from libs.blackbox_core.errors import SignerRuleError
from libs.blackbox_core.signer_rules import check_attest_request
from tests._dev_keys import dev_key
from tests.unit.test_epochs_rules import request_pair


class Evidence:
    def covers(self, intent_seq: int) -> bool:
        return intent_seq == 0


def test_attestation_is_signed_and_expires() -> None:
    _, intent, _ = request_pair()
    key = dev_key(30)
    attestation = build_attestation(
        intent, "2026-01-01T00:00:00.000Z", "2026-01-01T00:00:30.000Z", key
    )
    assert verify_attestation(
        attestation, key.public_key().public_bytes_raw(), "2026-01-01T00:00:01.000Z"
    )
    assert not verify_attestation(
        attestation, key.public_key().public_bytes_raw(), "2026-01-01T00:00:30.000Z"
    )
    changed = attestation.model_copy(update={"signature": ""})
    assert not verify_attestation(
        changed, key.public_key().public_bytes_raw(), "2026-01-01T00:00:01.000Z"
    )


def test_attest_rules_bind_digest_and_checkpoint() -> None:
    _, intent, _ = request_pair()
    check_attest_request(intent, None, None, Evidence())
    with pytest.raises(SignerRuleError):
        check_attest_request(intent, "sha256:" + "f" * 64, None, Evidence())
    with pytest.raises(SignerRuleError):
        check_attest_request(intent, None, "sha256:" + "f" * 64, Evidence())
    with pytest.raises(SignerRuleError):
        check_attest_request(intent, None, None, None)


def test_blocked_and_unknown_policy_fail_closed() -> None:
    _, intent, _ = request_pair()
    blocked = intent.model_copy(
        update={"policy": intent.policy.model_copy(update={"decision": "block"})}
    )
    with pytest.raises(SignerRuleError):
        check_attest_request(blocked, None, None, Evidence())
    unknown = intent.model_copy(
        update={"policy": intent.policy.model_copy(update={"severity": ""})}
    )
    with pytest.raises(SignerRuleError):
        check_attest_request(unknown, None, None, None)


def test_attestation_domain_is_not_entry_domain() -> None:
    _, intent, _ = request_pair()
    key = dev_key(31)
    attestation = build_attestation(
        intent, "2026-01-01T00:00:00.000Z", "2026-01-01T00:00:30.000Z", key
    )
    from libs.blackbox_core.signing import verify_structure

    assert not verify_structure(attestation, key.public_key().public_bytes_raw(), "entry")
