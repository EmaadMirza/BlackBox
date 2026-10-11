"""E4: Compromised gateway logs one thing and sends another."""

import pytest


# TODO(spec §29.4): implement E4 with controls and offline evidence.
@pytest.mark.xfail(reason="not built", strict=True, raises=NotImplementedError)
def test_e04() -> None:
    """- **Expected:** (i) provider recomputes the body digest, rejects, records `ATTESTATION_BODY_MISMATCH`, alarm fires. (ii) detected as in E3 (altered entry cannot be re-signed). (iii) the provider records an event without a valid attestation: `UNATTESTED_ACTION`, and if enforcement mode is on, the request is rejected. (iv) the signer refuses; the refusal is logged.
    - **Pass:** every variant is rejected or flagged as stated; none results in a provider effect without a matching verified ledger entry."""
    raise NotImplementedError("not built")
