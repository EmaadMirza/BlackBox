"""Thin cooperative heartbeat tick runner."""

import asyncio


class TickRunner:
    def __init__(self, signer) -> None:
        self.signer = signer
        self.stopped = False

    def tick_once(self):
        if self.stopped:
            return (), None
        return self.signer.tick()

    def stop(self) -> None:
        self.stopped = True


async def run(signer, interval_seconds: int = 5) -> None:
    """Run cooperative ticks without owning signer concurrency."""
    runner = TickRunner(signer)
    while not runner.stopped:
        runner.tick_once()
        await asyncio.sleep(interval_seconds)
