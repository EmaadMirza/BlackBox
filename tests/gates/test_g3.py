"""Build-time gate G3 is implemented by the witness refusal core test."""

from tests.gates.test_g3_witness_refusal import (
    test_g3_witness_refuses_rewritten_history_and_plain_ledger_control,
)


def test_g3(tmp_path) -> None:
    test_g3_witness_refuses_rewritten_history_and_plain_ledger_control(tmp_path)
