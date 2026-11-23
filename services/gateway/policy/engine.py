"""Deterministic, validated declarative gateway policy evaluation."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import Any

import yaml

from libs.blackbox_core import schemas


def load_rules(path: Path) -> dict[str, object]:
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise ValueError("policy rules could not be loaded") from exc
    if not isinstance(raw, dict) or not isinstance(raw.get("version"), str):
        raise ValueError("policy rules require a version")
    if raw.get("currency_unit") != "minor" or not isinstance(raw.get("risk_classes"), dict):
        raise ValueError("policy rules have an invalid currency or risk class map")
    tools = raw.get("tool_allow_list")
    if not isinstance(tools, list) or not all(isinstance(item, str) for item in tools):
        raise ValueError("policy tool allow-list is invalid")
    rules = raw.get("rules")
    if not isinstance(rules, list):
        raise ValueError("policy rules list is invalid")
    for rule in rules:
        if not isinstance(rule, dict) or not isinstance(rule.get("id"), str):
            raise ValueError("policy rule is invalid")
        if rule.get("decision") not in {"allow", "block", "require_approval"}:
            raise ValueError("policy decision is invalid")
        if not isinstance(rule.get("severity"), str):
            raise ValueError("policy severity is invalid")
        threshold = rule.get("amount_above_minor")
        if threshold is not None and (type(threshold) is not int or threshold < 0):
            raise ValueError("policy amount threshold is invalid")
        rate = rule.get("rate_limit")
        if rate is not None and (
            not isinstance(rate, dict)
            or type(rate.get("count")) is not int
            or type(rate.get("window_seconds")) is not int
            or rate["count"] < 1
            or rate["window_seconds"] < 1
        ):
            raise ValueError("policy rate limit is invalid")
    return raw


class PolicyEngine:
    def __init__(
        self, rules: dict[str, object], *, clock: Callable[[], float] | None = None
    ) -> None:
        self.rules = rules
        self.clock = clock or __import__("time").monotonic
        self._rate_events: dict[str, list[float]] = {}

    def evaluate(
        self, action: schemas.RequestAction, principal: schemas.Principal
    ) -> schemas.Policy:
        version = str(self.rules["version"])
        tool = action.tool_name
        risk_classes = self.rules["risk_classes"]
        allowed = self.rules["tool_allow_list"]
        if tool not in allowed or tool not in risk_classes:
            return self._policy(version, "block", "unknown-tool", "high")
        for rule in self.rules["rules"]:
            if not self._matches(rule, action):
                continue
            severity = (
                rule["severity"]
                if rule["severity"] in {"low", "medium", "high", "critical"}
                else "high"
            )
            decision = rule["decision"]
            rate = rule.get("rate_limit")
            if rate is not None and not self._within_rate(rule["id"], rate):
                return self._policy(version, "block", f"{rule['id']}-rate-limit", "high")
            return self._policy(version, decision, rule["id"], severity)
        return self._policy(version, "block", "no-matching-rule", "high")

    @staticmethod
    def _policy(version: str, decision: str, rule_id: str, severity: str) -> schemas.Policy:
        return schemas.Policy(
            version=version,
            decision=decision,
            matching_rule_id=rule_id,
            severity=severity,
            approval_receipt_id=None,
        )

    @staticmethod
    def _matches(rule: dict[str, Any], action: schemas.RequestAction) -> bool:
        tools = rule.get("tools", rule.get("tool"))
        if isinstance(tools, str):
            tools = [tools]
        if tools is not None and action.tool_name not in tools:
            return False
        operations = rule.get("operations")
        if operations is not None and action.tool_name not in operations:
            return False
        threshold = rule.get("amount_above_minor")
        return threshold is None or (
            action.amount_minor is not None and action.amount_minor > threshold
        )

    def _within_rate(self, rule_id: str, rate: dict[str, int]) -> bool:
        now = self.clock()
        events = [
            stamp
            for stamp in self._rate_events.get(rule_id, [])
            if now - stamp < rate["window_seconds"]
        ]
        if len(events) >= rate["count"]:
            self._rate_events[rule_id] = events
            return False
        events.append(now)
        self._rate_events[rule_id] = events
        return True


def evaluate(
    action: schemas.RequestAction, principal: schemas.Principal, rules: dict[str, object]
) -> schemas.Policy:
    return PolicyEngine(rules).evaluate(action, principal)
