"""E5: Bypass from the agent network."""

import pytest


# TODO(spec §29.4): implement E5 with controls and offline evidence.
@pytest.mark.xfail(reason="not built", strict=True, raises=NotImplementedError)
def test_e05() -> None:
    """- **Expected:** with egress control on, connections fail and nothing reaches the provider. With the rule loosened, requests reach the provider, which records `UNATTESTED` events; the reconciler raises `UNATTESTED_ACTION` within the time budget.
    - **Pass:** both layers behave as stated, showing the first line of defence and the safety net separately."""
    raise NotImplementedError("not built")
