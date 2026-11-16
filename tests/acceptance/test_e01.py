"""E1: Honest path (baseline)."""

from pathlib import Path

from libs.blackbox_core.epochs import validate_contiguity
from libs.blackbox_core.schemas import SealedEntry
from services.reconciler.findings_store import FindingsStore
from services.reconciler.main import Reconciler
from tests._dev_keys import dev_key
from tools.attack_suite.fixture import build_demo
from tools.verifier.verify import verify_evidence


def test_e01(tmp_path: Path) -> None:
    """E1: Honest path (baseline).

    Expected:
    - All entries become VERIFIED against witnessed checkpoints.
    - Contiguous epoch transitions (epoch_start, epoch_end).
    - Reconciler reports zero findings on consistent ledger and provider events.
    - No unexpected alarms.
    """
    keys = [(dev_key(i), dev_key(i).public_key().public_bytes_raw()) for i in range(1, 8)]
    bundle, pins = build_demo(keys)

    # 1. Offline verification against pinned keys
    report = verify_evidence(bundle, pins)
    assert report.verdict == "VERIFIED"

    # 2. Contiguous epochs
    assert len(bundle.epochs) >= 2
    validate_contiguity(bundle.epochs[0], bundle.epochs[1])

    # 3. Reconciler run over matching entries and provider events -> zero findings
    entries = [SealedEntry.model_validate(e) for e in bundle.entries]
    matching_events = []
    for entry in entries:
        if entry.body.type == "action":
            matching_events.append(
                {
                    "request_id": f"prov-{entry.body.seq}",
                    "intent_seq": entry.body.seq,
                    "body_digest": getattr(
                        getattr(entry.body, "action", None), "body_digest", None
                    ),
                    "attested": True,
                    "status": 200,
                }
            )

    findings_store = FindingsStore(tmp_path / "findings.json")
    reconciler = Reconciler(
        ledger_reader=lambda: entries,
        event_reader=lambda: matching_events,
        findings_store=findings_store,
        clock=lambda: "2026-01-01T00:05:00.000Z",
        grace_seconds=300,
    )
    findings = reconciler.run_once()
    assert len(findings) == 0, f"Expected 0 reconciler findings on honest path, got: {findings}"
