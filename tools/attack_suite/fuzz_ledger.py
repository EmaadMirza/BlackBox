"""E8: Stored-ledger fuzzing attack harness (spec §29.4)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from libs.blackbox_core.canonical import canonicalize, loads
from libs.blackbox_core.evidence import Bundle
from tests._dev_keys import dev_key
from tools.attack_suite.fixture import build_demo
from tools.verifier.verify import verify_evidence


def run(tmp_dir: Path | None = None) -> dict[str, Any]:
    """Run E8 stored ledger fuzzing simulation."""
    keys = [(dev_key(i), dev_key(i).public_key().public_bytes_raw()) for i in range(1, 8)]
    bundle, pins = build_demo(keys)
    baseline_report = verify_evidence(bundle, pins)
    assert baseline_report.verdict == "VERIFIED", "Baseline bundle must verify"

    raw = canonicalize(bundle.model_dump(mode="json"))
    raw_len = len(raw)
    assert raw_len > 1000

    tested = 0
    detected = 0

    # 1. Single-byte bit flips across the serialized bundle
    step = max(1, raw_len // 100)
    for offset in range(0, raw_len, step):
        for bit in (0x01, 0x80):
            mutated = bytearray(raw)
            mutated[offset] ^= bit
            tested += 1

            try:
                parsed = loads(bytes(mutated))
                mutated_bundle = Bundle.model_validate(parsed)
                report = verify_evidence(mutated_bundle, pins)
                if report.verdict != "VERIFIED":
                    detected += 1
            except Exception:
                # Malformed JSON, schema violation, or decode error -> caught
                detected += 1

    # 2. Mutate every individual entry in the bundle
    for entry_idx in range(len(bundle.entries)):
        mutated_entries = [e.copy() for e in bundle.entries]
        target = mutated_entries[entry_idx]
        is_sig_mutation = False
        if "signature" in target:
            sig = list(target["signature"])
            sig[0] = "A" if sig[0] != "A" else "B"
            target["signature"] = "".join(sig)
            is_sig_mutation = True
        elif "body" in target and "seq" in target["body"]:
            target["body"]["seq"] += 9999

        mutated_bundle = bundle.model_copy(update={"entries": mutated_entries})
        tested += 1
        try:
            report = verify_evidence(mutated_bundle, pins)
            if report.verdict != "VERIFIED":
                if is_sig_mutation:
                    assert any("entry signature failure" in e.reasons for e in report.entries), (
                        "Signature mutation must be caught specifically as entry signature failure"
                    )
                detected += 1
        except AssertionError:
            raise
        except Exception:
            detected += 1

    assert tested > 50, f"Expected >50 mutations, tested {tested}"
    assert detected == tested, f"Expected 100% detection, but detected {detected}/{tested}"

    return {
        "scenario": "E8_stored_ledger_fuzz",
        "verdict": "PASSED",
        "mutations_tested": tested,
        "mutations_detected": detected,
        "detection_rate_percent": (detected / tested) * 100.0,
    }


def main() -> None:
    print(json.dumps(run(), indent=2))


if __name__ == "__main__":
    main()
