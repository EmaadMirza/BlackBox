"""Thin cooperative heartbeat tick runner."""


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


async def run(interval_seconds: int = 5) -> None:
    del interval_seconds
    raise NotImplementedError("external scheduler must call TickRunner.tick_once")
