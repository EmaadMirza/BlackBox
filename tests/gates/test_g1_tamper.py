"""G1: rehashed edit fails signature checks; unsigned control accepts it."""

from tests.unit.test_verifier import demo
from tools.attack_suite.tamper_battery import evaluate, variants
from tools.verifier.verify import verify_evidence


def test_g1_tamper_and_control() -> None:
    bundle, pins = demo()
    result = evaluate(bundle, pins)
    print("\nPlain hash chain: ACCEPTED | Signed log: TAMPERED at seq 5 (signature failure)")
    assert result["control"]["plain_hash_chain"] == "ACCEPTED"
    attacked = variants(bundle)
    changed = verify_evidence(attacked["edit_and_rehash"], pins)
    seq5 = next(e for e in changed.entries if e.seq == 5)
    assert seq5.verdict == "TAMPERED" and "entry signature failure" in seq5.reasons
    deleted = verify_evidence(attacked["delete_seq_7"], pins)
    assert next(e for e in deleted.entries if e.seq == 7).verdict == "MISSING"
    assert all(row["verdict"] != "VERIFIED" for row in result["variants"])
