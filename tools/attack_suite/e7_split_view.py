"""E7: Split view (spec §29.4)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from services.witness.gossip import detect_split_view, split_view_evidence
from tests._dev_keys import dev_key
from tools.attack_suite.fixture import build_demo


def run(tmp_dir: Path | None = None) -> dict[str, Any]:
    """Run E7 split view attack simulation."""
    keys = [(dev_key(i), dev_key(i).public_key().public_bytes_raw()) for i in range(1, 8)]
    bundle, _ = build_demo(keys)
    first = bundle.checkpoints[0].checkpoint
    conflicting = first.model_copy(update={"root_hash": "sha256:" + "f" * 64})

    # Conflicting roots for the same tree size trigger split view
    detected = detect_split_view([first, conflicting])
    assert detected is True, "Conflicting roots for same size must trigger split view"

    evidence = split_view_evidence([first, conflicting])
    assert len(evidence) == 2, "Evidence must contain both conflicting checkpoints"

    # Different tree sizes do not constitute a split view
    other_size = bundle.checkpoints[1].checkpoint
    assert first.tree_size != other_size.tree_size
    diff_size_detected = detect_split_view([first, other_size])
    assert diff_size_detected is False, "Different tree sizes must not trigger split view"

    return {
        "scenario": "E7_split_view",
        "verdict": "PASSED",
        "split_view_detected": detected,
        "conflicting_evidence_count": len(evidence),
        "different_sizes_split_view": diff_size_detected,
    }


def main() -> None:
    print(json.dumps(run(), indent=2))


if __name__ == "__main__":
    main()
