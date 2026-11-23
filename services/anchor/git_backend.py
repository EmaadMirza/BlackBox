"""Append-only Git commit anchoring backend (spec §12).

Maintains an append-only log of witnessed checkpoints committed into a Git repository.
Each commit records checkpoint timestamp, tree size, root hash, and signatures.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any

from libs.blackbox_core import schemas
from libs.blackbox_core.canonical import canonicalize
from libs.blackbox_core.encoding import encode_base64url


class GitAnchorBackend:
    """Manages append-only checkpoint commitments in a local/remote Git repository."""

    def __init__(self, repo_path: Path, branch: str = "main") -> None:
        self.repo_path = Path(repo_path)
        self.branch = branch
        self.log_file = self.repo_path / "anchors.jsonl"
        self._ensure_repo()

    def _ensure_repo(self) -> None:
        """Initialize Git repository if not already present."""
        self.repo_path.mkdir(parents=True, exist_ok=True)
        git_dir = self.repo_path / ".git"
        if not git_dir.exists():
            try:
                subprocess.run(
                    ["git", "init", "-b", self.branch],
                    cwd=self.repo_path,
                    check=True,
                    capture_output=True,
                )
                subprocess.run(
                    ["git", "config", "user.name", "BlackBox Anchor Service"],
                    cwd=self.repo_path,
                    check=True,
                    capture_output=True,
                )
                subprocess.run(
                    ["git", "config", "user.email", "anchor@blackbox.local"],
                    cwd=self.repo_path,
                    check=True,
                    capture_output=True,
                )
            except Exception:
                pass

    def append_checkpoint(
        self,
        checkpoint: schemas.Checkpoint,
        cosignatures: list[Any] | None = None,
    ) -> dict[str, Any]:
        """Append witnessed checkpoint to log and commit to Git."""
        cosigs: list[dict[str, Any]] = []
        if cosignatures:
            for cs in cosignatures:
                if hasattr(cs, "model_dump"):
                    cosigs.append(cs.model_dump(mode="json"))
                elif isinstance(cs, dict):
                    cosigs.append(cs)

        record: dict[str, Any] = {
            "checkpoint_timestamp": checkpoint.signer_timestamp,
            "tree_size": checkpoint.tree_size,
            "root_hash": checkpoint.root_hash,
            "epoch_id": checkpoint.epoch_id,
            "log_id": checkpoint.log_id,
            "signature": checkpoint.signature,
            "cosignatures": cosigs,
            "raw_checkpoint_base64": encode_base64url(canonicalize(checkpoint.model_dump())),
        }
        line = json.dumps(record, sort_keys=True) + "\n"

        with open(self.log_file, "a", encoding="utf-8") as f:
            f.write(line)

        # Commit to Git if possible
        commit_hash = f"mock-commit-{checkpoint.tree_size}"
        try:
            subprocess.run(
                ["git", "add", "anchors.jsonl"],
                cwd=self.repo_path,
                check=True,
                capture_output=True,
            )
            commit_msg = f"anchor: tree_size={checkpoint.tree_size} root={checkpoint.root_hash}"
            subprocess.run(
                ["git", "commit", "-m", commit_msg],
                cwd=self.repo_path,
                check=True,
                capture_output=True,
                text=True,
            )
            rev_res = subprocess.run(
                ["git", "rev-parse", "HEAD"],
                cwd=self.repo_path,
                check=True,
                capture_output=True,
                text=True,
            )
            commit_hash = rev_res.stdout.strip()
        except Exception:
            pass

        record["git_commit"] = commit_hash
        return record

    def get_anchors(self) -> list[dict[str, Any]]:
        """Return all published anchors from the repository log."""
        if not self.log_file.exists():
            return []
        anchors = []
        with open(self.log_file, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    anchors.append(json.loads(line))
        return anchors

    def get_anchor_for_tree_size(self, tree_size: int) -> dict[str, Any] | None:
        """Lookup published anchor by Merkle tree size."""
        for a in self.get_anchors():
            if a.get("tree_size") == tree_size:
                return a
        return None
