"""E3: Ledger-host rewrite."""

import pytest


# TODO(spec §29.4): implement E3 with controls and offline evidence.
@pytest.mark.xfail(reason="not built", strict=True, raises=NotImplementedError)
def test_e03() -> None:
    """- **Expected alarms:** `WITNESS_REFUSAL` from every witness within the time budget.
    - **Expected verdicts:** the verifier marks the deleted range `MISSING` or `TAMPERED` against the last witnessed checkpoint; the reconciler raises `UNRECORDED_ACTION` for the refund still present in the provider's event log.
    - **Pass:** all three witnesses refuse; no quorum is reached; all verdicts and findings as listed."""
    raise NotImplementedError("not built")
