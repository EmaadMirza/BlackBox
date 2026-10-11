"""Signer-owned wall clock; candidate timestamps never supply current time."""

from datetime import datetime, timezone

from libs.blackbox_core.encoding import format_timestamp


def system_utc_now() -> str:
    """Sample UTC wall time once and truncate it to wire-format milliseconds."""

    now = datetime.now(timezone.utc)
    return format_timestamp(now.replace(microsecond=(now.microsecond // 1000) * 1000))
