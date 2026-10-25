"""Cooperative, best-effort direct heartbeat publication to witnesses."""

from __future__ import annotations


class HeartbeatPublisher:
    def __init__(self, signer, witnesses: dict[str, object], *, clock=None) -> None:
        self.signer = signer
        self.witnesses = witnesses
        self.clock = clock
        self.last_published_at = None

    def tick(self) -> object | None:
        try:
            _, heartbeat = self.signer.tick()
        except Exception:
            return None
        if heartbeat is None:
            return None
        for client in self.witnesses.values():
            try:
                getattr(client, "post")("/v1/heartbeat", json=heartbeat.model_dump(mode="json"))
            except Exception:
                continue
        self.last_published_at = heartbeat.signer_timestamp
        return heartbeat
