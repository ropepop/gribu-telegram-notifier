from scheduler import PeriodicScheduler


class FakeClock:
    def __init__(self):
        self.now = 0.0

    def monotonic(self):
        return self.now

    def sleep(self, seconds):
        self.now += seconds


class FakeStopEvent:
    def __init__(self, clock: FakeClock, stop_at: float):
        self.clock = clock
        self.stop_at = stop_at

    def is_set(self):
        return self.clock.now >= self.stop_at


def test_scheduler_runs_once_per_interval_without_double_fire():
    clock = FakeClock()
    calls = []
    scheduler = PeriodicScheduler(
        interval_sec=1.0,
        monotonic=clock.monotonic,
        sleep=clock.sleep,
    )
    stop_event = FakeStopEvent(clock=clock, stop_at=5.2)

    scheduler.run(
        stop_event=stop_event,
        job=lambda: calls.append(round(clock.now, 2)),
    )

    assert calls == [0.0, 1.0, 2.0, 3.0, 4.0, 5.0]
