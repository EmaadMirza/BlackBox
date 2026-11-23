"""E7: Split view (in-process, not network-separated)."""

from pathlib import Path

from services.witness.gossip import detect_split_view, split_view_evidence
from tests.unit.test_witness_service import _app


def test_e07(tmp_path: Path) -> None:
    """E7: Split view (in-process, not network-separated).

    Points to existing W4 gossip and split-view detection.
    Expected: gossip detects differing roots for the same size; SPLIT_VIEW fires;
    no quorum for the contested checkpoint.
    """
    _, bundle, _ = _app(tmp_path)
    first = bundle.checkpoints[0].checkpoint
    conflicting = first.model_copy(update={"root_hash": "sha256:" + "f" * 64})

    # Conflicting roots for the same tree size trigger split view
    assert detect_split_view([first, conflicting]) is True
    evidence = split_view_evidence([first, conflicting])
    assert len(evidence) == 2

    # Different tree sizes do not constitute a split view
    other_size = bundle.checkpoints[1].checkpoint
    assert first.tree_size != other_size.tree_size
    assert detect_split_view([first, other_size]) is False
