"""E2: Hijacked agent with a poisoned invoice."""

import pytest


# TODO(spec §29.4): implement E2 with controls and offline evidence.
@pytest.mark.xfail(reason="not built", strict=True, raises=NotImplementedError)
def test_e02() -> None:
    """- **Expected (a):** a sealed `intent` marked pending with the invoice listed as an untrusted input in context; a `blocked` entry recording the denial; no provider event; no findings.
    - **Expected (b):** intent, `approval`, outcome and the provider event all present and consistent; reconciler agrees; the evidence bundle shows the invoice hash and trust label in the intent's context, so an investigator can trace the cause.
    - **Pass:** every named field is present and verifies offline. State that the test shows the *record is complete*, not that the injection was prevented."""
    raise NotImplementedError("not built")
