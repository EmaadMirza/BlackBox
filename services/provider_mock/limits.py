"""Independent provider refund limits."""

from __future__ import annotations


def check_refund(
    amount_minor: int, daily_total_minor: int, per_call_cap_minor: int, daily_cap_minor: int
) -> None:
    if amount_minor > per_call_cap_minor:
        raise ValueError("per-call limit exceeded")
    if daily_total_minor + amount_minor > daily_cap_minor:
        raise ValueError("daily cap exceeded")
