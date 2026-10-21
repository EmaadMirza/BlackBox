"""K2b cooperative tick tests."""

from services.signer.heartbeat import TickRunner


class FakeSigner:
    def __init__(self) -> None:
        self.calls = 0

    def tick(self):
        self.calls += 1
        return (), None


def test_runner_stops_cleanly_without_threads_or_sleep() -> None:
    signer = FakeSigner()
    runner = TickRunner(signer)
    assert runner.tick_once() == ((), None)
    runner.stop()
    assert runner.tick_once() == ((), None)
    assert signer.calls == 1
