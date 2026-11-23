"""PO1 deterministic policy engine tests."""

from pathlib import Path

import pytest
from hypothesis import given
from hypothesis import strategies as st

from libs.blackbox_core.schemas import Principal, RequestAction
from services.gateway.policy.engine import PolicyEngine, load_rules


def _action(tool: str = "refund", amount: int | None = None) -> RequestAction:
    return RequestAction(
        adapter="http",
        method="POST",
        path="/x",
        tool_name=tool,
        body_digest="sha256:" + "a" * 64,
        arguments_commitment="sha256:" + "b" * 64,
        idempotency_key="sha256:" + "c" * 64,
        payload_reference="p",
        amount_minor=amount,
    )


def _principal() -> Principal:
    return Principal(
        client_key_id="c",
        source_address="s",
        human_identity="h",
        agent_identity="a",
        agent_version="1",
        delegation_chain=[],
    )


def test_policy_decisions_include_version_rule_and_severity(tmp_path: Path):
    engine = PolicyEngine(load_rules(Path("services/gateway/policy/rules.yaml")))
    decision = engine.evaluate(_action(amount=12000), _principal())
    assert decision.decision == "require_approval"
    assert decision.version == "dev-scaffold-1"
    assert decision.matching_rule_id == "approve-large-refund"
    assert decision.severity == "high"


def test_unknown_tool_and_destructive_operation_deny():
    engine = PolicyEngine(load_rules(Path("services/gateway/policy/rules.yaml")))
    assert engine.evaluate(_action("unknown"), _principal()).decision == "block"
    assert engine.evaluate(_action("delete_account"), _principal()).decision == "block"


def test_invalid_rules_refuse_to_load(tmp_path: Path):
    path = tmp_path / "bad.yaml"
    path.write_text("version: x\nrisk_classes: []\ntool_allow_list: nope\nrules: []\n")
    with pytest.raises(ValueError):
        load_rules(path)


@given(st.integers(min_value=0, max_value=100000))
def test_same_input_and_policy_are_deterministic(amount: int):
    rules = load_rules(Path("services/gateway/policy/rules.yaml"))
    first = PolicyEngine(rules).evaluate(_action(amount=amount), _principal())
    second = PolicyEngine(rules).evaluate(_action(amount=amount), _principal())
    assert first == second


def test_rate_limit_uses_injected_clock(tmp_path: Path):
    path = tmp_path / "rules.yaml"
    path.write_text(
        """version: v1\ncurrency_unit: minor\nrisk_classes: {read: low}\ntool_allow_list: [read]\nrules:\n  - id: permit\n    tools: [read]\n    decision: allow\n    severity: low\n    rate_limit: {count: 1, window_seconds: 10}\n"""
    )
    now = [0.0]
    engine = PolicyEngine(load_rules(path), clock=lambda: now[0])
    assert engine.evaluate(_action("read"), _principal()).decision == "allow"
    assert engine.evaluate(_action("read"), _principal()).decision == "block"
    now[0] = 11.0
    assert engine.evaluate(_action("read"), _principal()).decision == "allow"
