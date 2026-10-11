"""Build-time gate G4; expected failure is not a passed gate."""

import pytest


# TODO(spec §29.7): implement gate G4 before advancing its stage.
@pytest.mark.xfail(reason="not built", strict=True, raises=NotImplementedError)
def test_g4() -> None:
    """- **G4: attestation binding (end of Stage 3).** Seal an intent for a small body and attempt to forward a different body with the resulting attestation. Expected: the provider's recomputed digest differs and the request is rejected. Also attempt to obtain an attestation for a digest not in any sealed intent; expected: the signer refuses."""
    raise NotImplementedError("not built")
