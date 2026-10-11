"""E7: Split view."""

import pytest


# TODO(spec §29.4): implement E7 with controls and offline evidence.
@pytest.mark.xfail(reason="not built", strict=True, raises=NotImplementedError)
def test_e07() -> None:
    """- **Expected:** gossip detects differing roots for the same size; `SPLIT_VIEW` fires; no quorum for the contested checkpoint.
    - **Pass:** `SPLIT_VIEW` within the time budget and no cosigned checkpoint for the conflicting size."""
    raise NotImplementedError("not built")
