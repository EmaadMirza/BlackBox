"""E10: Approval abuse."""

import pytest


# TODO(spec §29.4): implement E10 with controls and offline evidence.
@pytest.mark.xfail(reason="not built", strict=True, raises=NotImplementedError)
def test_e10() -> None:
    """- **Expected:** each attempt is rejected and recorded as a `blocked` entry stating the reason; no provider event occurs.
    - **Pass:** all five rejected and sealed; the offline evidence shows the denials."""
    raise NotImplementedError("not built")
