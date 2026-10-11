"""E1: Honest path (baseline)."""

import pytest


# TODO(spec §29.4): implement E1 with controls and offline evidence.
@pytest.mark.xfail(reason="not built", strict=True, raises=NotImplementedError)
def test_e01() -> None:
    """- **Expected:** all entries become `VERIFIED` after the next witnessed checkpoint; the unverified window stays within the configured bound; reconciler reports zero findings; no alarms except informational ones; the `epoch_end` and `epoch_start` entries are present and contiguous.
    - **Pass:** all of the above. If E1 fails, no other result is meaningful, so stop and fix."""
    raise NotImplementedError("not built")
