"""E6: Witness outage and availability attacks."""

import pytest


# TODO(spec §29.4): implement E6 with controls and offline evidence.
@pytest.mark.xfail(reason="not built", strict=True, raises=NotImplementedError)
def test_e06() -> None:
    """- **Expected (a):** a witness-health alarm; quorum still met; normal operation. **(b):** `CHECKPOINT_STALL` and `HEARTBEAT_STALL` escalating; high-risk actions fail closed with `blocked` entries; low-risk reads continue and are queued with a `gap` marker when sealing is impaired; the unverified window grows and is reported. **(c):** same as (b). **(d):** witnesses catch up through gossip, the unverified window shrinks, entries become `VERIFIED`, the `gap` marker is visible in the ledger.
    - **Pass:** the fail-closed and fail-open behaviours match section 13.7 exactly and recovery completes without ledger corruption."""
    raise NotImplementedError("not built")
