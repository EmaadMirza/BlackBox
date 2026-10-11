"""E9: Load and performance."""

import pytest


# TODO(spec §29.4): implement E9 with controls and offline evidence.
@pytest.mark.xfail(reason="not built", strict=True, raises=NotImplementedError)
def test_e09() -> None:
    """- **Measure:** added latency (p50, p95, p99); throughput in entries per second; time from sealing to witnessed checkpoint; unverified-window length; storage per entry; proof size and verification time as the ledger grows.
    - **Pass:** no sequence gaps, chain breaks or signer errors under load; high-risk waits stay under the timeout; results recorded in a table and graph. This test passes on integrity, not on speed: speed is reported, not judged."""
    raise NotImplementedError("not built")
