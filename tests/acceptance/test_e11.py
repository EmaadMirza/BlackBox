"""E11: Key compromise and rogue epochs."""

import pytest


# TODO(spec §29.4): implement E11 with controls and offline evidence.
@pytest.mark.xfail(reason="not built", strict=True, raises=NotImplementedError)
def test_e11() -> None:
    """- **Expected:** (i) entries inserted outside the signer's sequence rules are caught by the sequence, chain and witness checks (they conflict with the signer's actual chain and the heartbeat counts); (ii) the verifier rejects signatures from an expired epoch window; (iii) witnesses and verifier reject the rogue epoch; (iv) revoked certification is refused after the effective time.
    - **Pass:** the damage of a stolen epoch key is demonstrably limited to ordered appends within the epoch, as claimed."""
    raise NotImplementedError("not built")
