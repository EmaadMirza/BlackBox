"""Read-only witness peer exchange and split-view detection."""

from __future__ import annotations

import httpx

from libs.blackbox_core import schemas


async def exchange(peer_urls: list[str], *, bearer_token: str = "") -> list[schemas.Checkpoint]:
    headers = {"Authorization": f"Bearer {bearer_token}"} if bearer_token else {}
    checkpoints: list[schemas.Checkpoint] = []
    async with httpx.AsyncClient() as client:
        for url in peer_urls:
            response = await client.get(url.rstrip("/") + "/v1/latest", headers=headers)
            response.raise_for_status()
            payload = response.json()
            checkpoints.append(schemas.Checkpoint.model_validate(payload["checkpoint"]))
    return checkpoints


def detect_split_view(checkpoints: list[schemas.Checkpoint]) -> bool:
    roots_by_size: dict[tuple[str, int], set[str]] = {}
    for checkpoint in checkpoints:
        roots_by_size.setdefault((checkpoint.log_id, checkpoint.tree_size), set()).add(
            checkpoint.root_hash
        )
    return any(len(roots) > 1 for roots in roots_by_size.values())


def split_view_evidence(checkpoints: list[schemas.Checkpoint]) -> list[dict[str, object]]:
    """Return the conflicting signed checkpoint documents for alarm evidence."""
    conflicts: list[dict[str, object]] = []
    grouped: dict[tuple[str, int], list[schemas.Checkpoint]] = {}
    for checkpoint in checkpoints:
        grouped.setdefault((checkpoint.log_id, checkpoint.tree_size), []).append(checkpoint)
    for values in grouped.values():
        if len({item.root_hash for item in values}) > 1:
            conflicts.extend(item.model_dump(mode="json") for item in values)
    return conflicts
