"""Build-time gate G3; expected failure is not a passed gate."""

import pytest


# TODO(spec §29.7): implement gate G3 before advancing its stage.
@pytest.mark.xfail(reason="not built", strict=True, raises=NotImplementedError)
def test_g3() -> None:
    """- **G3: witness refuses a rewrite (end of Stage 2).** A witness has cosigned size 10. The ledger offers a rebuilt tree of size 12 whose first ten entries differ and which is correctly signed. Expected: no consistency proof exists, the witness refuses, `WITNESS_REFUSAL` fires. Control: with no witness, the rewrite is silently accepted."""
    raise NotImplementedError("not built")
