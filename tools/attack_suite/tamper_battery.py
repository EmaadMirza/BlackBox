"""Stage 1 reproducible mutation battery and unsigned-chain control (§22, G1)."""

from __future__ import annotations

import json
from pathlib import Path

from libs.blackbox_core.chain import entry_hash, verify_chain
from libs.blackbox_core.evidence import Bundle, PinnedKeys
from libs.blackbox_core.schemas import SealedEntry, parse_entry
from tools.attack_suite.fixture import build_demo
from tools.verifier.verify import verify_evidence


def variants(bundle: Bundle) -> dict[str, Bundle]:
    cases = {}
    data = bundle.model_dump()
    data["entries"][5]["body"]["reason"] = "attacker rewrote event"
    for i in range(6, 10):
        data["entries"][i]["body"]["prev_hash"] = entry_hash(
            parse_entry(data["entries"][i - 1]["body"])
        )
    cases["edit_and_rehash"] = Bundle.model_validate(data)
    data = bundle.model_dump()
    del data["entries"][7]
    cases["delete_seq_7"] = Bundle.model_validate(data)
    data = bundle.model_dump()
    data["entries"][5], data["entries"][6] = data["entries"][6], data["entries"][5]
    cases["reorder"] = Bundle.model_validate(data)
    data = bundle.model_dump()
    data["entries"].insert(6, data["entries"][5].copy())
    cases["duplicate"] = Bundle.model_validate(data)
    data = bundle.model_dump()
    data["entries"] = data["entries"][:-2]
    cases["truncate"] = Bundle.model_validate(data)
    data = bundle.model_dump()
    a = data["entries"][0]["body"]
    b = data["entries"][4]["body"]
    a["certificate"], b["certificate"] = b["certificate"], a["certificate"]
    cases["swap_epoch_certificates"] = Bundle.model_validate(data)
    data = bundle.model_dump()
    a = data["entries"][5]
    b = data["entries"][6]
    a["signature"], b["signature"] = b["signature"], a["signature"]
    cases["swap_signatures"] = Bundle.model_validate(data)
    return cases


def evaluate(bundle: Bundle, pins: PinnedKeys) -> dict[str, object]:
    honest = verify_evidence(bundle, pins)
    if honest.verdict != "VERIFIED":
        raise AssertionError(honest.to_dict())
    cases = variants(bundle)
    rows = []
    expected = {
        "edit_and_rehash": "TAMPERED",
        "delete_seq_7": "MISSING",
        "reorder": "TAMPERED",
        "duplicate": "TAMPERED",
        "truncate": "MISSING",
        "swap_epoch_certificates": "TAMPERED",
        "swap_signatures": "TAMPERED",
    }
    for name, changed in cases.items():
        report = verify_evidence(changed, pins)
        if report.verdict != expected[name]:
            raise AssertionError((name, report.to_dict()))
        failed = [e for e in report.entries if e.verdict != "VERIFIED"]
        rows.append(
            {
                "variant": name,
                "verdict": report.verdict,
                "affected_sequences": [e.seq for e in failed],
            }
        )
    rehashed = cases["edit_and_rehash"]
    unsigned_accepts = (
        verify_chain([SealedEntry.model_validate(e) for e in rehashed.entries]) is None
    )
    signed_seq5 = next(e for e in verify_evidence(rehashed, pins).entries if e.seq == 5)
    if not unsigned_accepts or "entry signature failure" not in signed_seq5.reasons:
        raise AssertionError("G1 control failed")
    return {
        "honest": honest.verdict,
        "variants": rows,
        "control": {
            "plain_hash_chain": "ACCEPTED",
            "signed_log_seq_5": signed_seq5.verdict,
            "reason": "entry signature failure",
        },
    }


def run(output: Path | None = None) -> dict[str, object]:
    from tools.ceremony import generate_dev_keys

    bundle, pins = build_demo(generate_dev_keys())
    result = evaluate(bundle, pins)
    if output is not None:
        output.mkdir(parents=True, exist_ok=True)
        # Public evidence only; exclusive creation avoids overwriting previous runs.
        files = {
            "honest.bundle.json": bundle.model_dump(),
            "pinned-keys.json": pins.model_dump(),
            "results.json": result,
        }
        files.update(
            {f"{name}.bundle.json": value.model_dump() for name, value in variants(bundle).items()}
        )
        for filename, value in files.items():
            with (output / filename).open("x") as stream:
                json.dump(value, stream, indent=2)
    return result


def main() -> None:
    print(json.dumps(run(), indent=2))


if __name__ == "__main__":
    main()
