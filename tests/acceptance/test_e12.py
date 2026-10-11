"""E12: Tool poisoning."""

import pytest


# TODO(spec §29.4): implement E12 with controls and offline evidence.
@pytest.mark.xfail(reason="not built", strict=True, raises=NotImplementedError)
def test_e12() -> None:
    """- **Expected:** the recorded tool-definitions hash changes; `TOOL_DEF_CHANGE` fires; the new hash appears in subsequent intents so an investigator can see exactly when the change took effect.
    - **Pass:** alarm within the time budget and the hash change is visible in the evidence."""
    raise NotImplementedError("not built")
