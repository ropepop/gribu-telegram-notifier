from __future__ import annotations

import json
import os
from contextlib import contextmanager
from copy import deepcopy
from pathlib import Path
from typing import Any, Callable

import fcntl


DEFAULT_STATE: dict[str, Any] = {
    "enabled": False,
    "last_unread": None,
    "last_check_ts": None,
    "last_success_ts": None,
    "last_check_result": None,
    "last_error_message": None,
    "last_parse_source": None,
    "last_parse_confidence": None,
    "consecutive_errors": 0,
    "paused_reason": "manual_off",
    "last_error_alert_ts": None,
    "telegram_update_offset": None,
    "telegram_poll_error_count": 0,
    "daemon_started_ts": None,
    "daemon_last_heartbeat_ts": None,
    "telegram_last_heartbeat_ts": None,
    "scheduler_last_heartbeat_ts": None,
    "command_worker_last_heartbeat_ts": None,
    "last_watchdog_reason": None,
    "daemon_restart_count": 0,
    "last_restart_ts": None,
    "current_check_interval_sec": None,
    "next_check_due_ts": None,
    "last_notification_sent_ts": None,
    "last_command_latency_ms": None,
    "check_duration_ms": None,
}


class StateStore:
    def __init__(self, path: Path):
        self.path = path
        self.lock_path = path.with_suffix(path.suffix + ".lock")

    @contextmanager
    def _locked(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        lock_fd = os.open(self.lock_path, os.O_CREAT | os.O_RDWR, 0o600)
        with os.fdopen(lock_fd, "r+") as lock_file:
            fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)

    def _read_unlocked(self) -> dict[str, Any]:
        if not self.path.exists():
            return deepcopy(DEFAULT_STATE)
        with self.path.open("r", encoding="utf-8") as fh:
            data = json.load(fh)
        merged = deepcopy(DEFAULT_STATE)
        merged.update(data)
        return merged

    def _write_unlocked(self, state: dict[str, Any]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        temp_path = self.path.with_suffix(self.path.suffix + ".tmp")
        with temp_path.open("w", encoding="utf-8") as fh:
            json.dump(state, fh, indent=2, sort_keys=True)
            fh.write("\n")
        os.replace(temp_path, self.path)

    def load(self) -> dict[str, Any]:
        with self._locked():
            return self._read_unlocked()

    def save(self, state: dict[str, Any]) -> dict[str, Any]:
        with self._locked():
            merged = deepcopy(DEFAULT_STATE)
            merged.update(state)
            self._write_unlocked(merged)
            return merged

    def patch(self, values: dict[str, Any]) -> dict[str, Any]:
        with self._locked():
            state = self._read_unlocked()
            state.update(values)
            self._write_unlocked(state)
            return state

    def mutate(self, mutator: Callable[[dict[str, Any]], dict[str, Any] | None]) -> dict[str, Any]:
        with self._locked():
            state = self._read_unlocked()
            maybe_new_state = mutator(deepcopy(state))
            if maybe_new_state is not None:
                state = maybe_new_state
            self._write_unlocked(state)
            return state
