from __future__ import annotations

import time
from typing import Callable


class PeriodicScheduler:
    def __init__(
        self,
        interval_sec: float,
        monotonic: Callable[[], float] | None = None,
        sleep: Callable[[float], None] | None = None,
    ):
        if interval_sec <= 0:
            raise ValueError("interval_sec must be > 0")
        self.interval_sec = interval_sec
        self._monotonic = monotonic or time.monotonic
        self._sleep = sleep or time.sleep

    def run(
        self,
        stop_event,
        job: Callable[[], None],
        should_run: Callable[[], bool] | None = None,
    ) -> None:
        next_run = self._monotonic()
        while not stop_event.is_set():
            now = self._monotonic()
            if now >= next_run:
                if should_run is None or should_run():
                    job()
                next_run += self.interval_sec
                if now > next_run:
                    behind = now - next_run
                    skipped = int(behind // self.interval_sec) + 1
                    next_run += skipped * self.interval_sec
                continue

            sleep_for = min(0.25, max(0.0, next_run - now))
            self._sleep(sleep_for)
