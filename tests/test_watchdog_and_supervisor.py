from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

import app
from app import (
    DAEMON_EXIT_HEARTBEAT_STALE,
    DAEMON_EXIT_LOCK_HELD,
    DAEMON_EXIT_THREAD_DIED,
    evaluate_watchdog,
    run_daemon,
)
from config import Config
from process_lock import ProcessLock
from state_store import StateStore


def _make_config(tmp_path: Path) -> Config:
    return Config(
        telegram_bot_token="token",
        telegram_chat_id=111,
        gribu_base_url="https://www.gribu.lv",
        gribu_check_url="/lv/messages",
        gribu_login_id="demo@example.com",
        gribu_login_password="secret",
        gribu_login_path="/pieslegties",
        gribu_cookie_header="",
        check_interval_sec=60,
        check_interval_fast_sec=20,
        check_interval_idle_sec=60,
        check_interval_error_backoff_max_sec=180,
        state_file=(tmp_path / "state.json"),
        http_timeout_sec=5,
        error_alert_cooldown_sec=1800,
        telegram_api_base_url="https://api.telegram.org",
        telegram_nav_buttons_enabled=True,
        env_file_path=(tmp_path / ".env"),
        daemon_lock_file=(tmp_path / "daemon.lock"),
        watchdog_check_sec=10,
        watchdog_stale_sec=120,
        supervisor_restart_base_sec=2,
        supervisor_restart_max_sec=5,
        parse_low_confidence_delta_limit=20,
    )


def test_watchdog_detects_dead_scheduler_thread():
    now_dt = datetime.now(timezone.utc)
    exit_code, reason = evaluate_watchdog(
        now_dt=now_dt,
        stale_sec=120,
        thread_alive={"telegram": True, "scheduler": False, "command_worker": True},
        heartbeats={
            "telegram_last_heartbeat_ts": now_dt.isoformat(),
            "scheduler_last_heartbeat_ts": now_dt.isoformat(),
            "command_worker_last_heartbeat_ts": now_dt.isoformat(),
        },
    )
    assert exit_code == DAEMON_EXIT_THREAD_DIED
    assert reason == "scheduler_thread_dead"


def test_watchdog_detects_missing_heartbeat():
    now_dt = datetime.now(timezone.utc)
    exit_code, reason = evaluate_watchdog(
        now_dt=now_dt,
        stale_sec=120,
        thread_alive={"telegram": True, "scheduler": True, "command_worker": True},
        heartbeats={
            "telegram_last_heartbeat_ts": None,
            "scheduler_last_heartbeat_ts": now_dt.isoformat(),
            "command_worker_last_heartbeat_ts": now_dt.isoformat(),
        },
    )
    assert exit_code == DAEMON_EXIT_HEARTBEAT_STALE
    assert reason == "telegram_heartbeat_missing"


def test_run_daemon_lock_held_is_non_recoverable(tmp_path: Path):
    config = _make_config(tmp_path)
    lock = ProcessLock(config.daemon_lock_file)
    lock.acquire()
    try:
        try:
            run_daemon(config)
            raise AssertionError("Expected SystemExit")
        except SystemExit as exc:
            assert exc.code == DAEMON_EXIT_LOCK_HELD
    finally:
        lock.release()


def test_run_daemon_retries_recoverable_worker_exits_with_backoff(tmp_path: Path, monkeypatch):
    config = _make_config(tmp_path)
    worker_exits = [
        DAEMON_EXIT_THREAD_DIED,
        DAEMON_EXIT_HEARTBEAT_STALE,
        DAEMON_EXIT_THREAD_DIED,
        0,
    ]
    sleep_calls: list[float] = []

    def fake_worker(_config, _lock, _stop_event):
        return worker_exits.pop(0)

    monkeypatch.setattr(app, "_run_daemon_worker", fake_worker)
    monkeypatch.setattr(app, "_sleep_with_stop", lambda _stop_event, seconds: sleep_calls.append(seconds))

    run_daemon(config)

    assert sleep_calls == [2, 4, 5]
    state = StateStore(config.state_file).load()
    assert state["daemon_restart_count"] == 3
    assert state["last_restart_ts"] is not None


def test_backoff_resets_after_stable_window(tmp_path: Path, monkeypatch):
    config = _make_config(tmp_path)
    run_outcomes = [DAEMON_EXIT_THREAD_DIED, DAEMON_EXIT_THREAD_DIED, DAEMON_EXIT_THREAD_DIED, 0]
    sleep_calls: list[float] = []

    monotonic_values = [
        0.0,
        1.0,
        2.0,
        3.0,
        4.0,
        604.0,
        605.0,
        606.0,
    ]

    def fake_worker(_config, _lock, _stop_event):
        return run_outcomes.pop(0)

    def fake_monotonic():
        if not monotonic_values:
            raise AssertionError("Not enough monotonic values")
        return monotonic_values.pop(0)

    monkeypatch.setattr(app, "_run_daemon_worker", fake_worker)
    monkeypatch.setattr(app, "_sleep_with_stop", lambda _stop_event, seconds: sleep_calls.append(seconds))
    monkeypatch.setattr(app.time, "monotonic", fake_monotonic)

    run_daemon(config)

    assert sleep_calls == [2, 4, 2]


def test_watchdog_detects_stale_heartbeat():
    now_dt = datetime.now(timezone.utc)
    stale_ts = (now_dt - timedelta(seconds=121)).isoformat()
    exit_code, reason = evaluate_watchdog(
        now_dt=now_dt,
        stale_sec=120,
        thread_alive={"telegram": True, "scheduler": True, "command_worker": True},
        heartbeats={
            "telegram_last_heartbeat_ts": stale_ts,
            "scheduler_last_heartbeat_ts": now_dt.isoformat(),
            "command_worker_last_heartbeat_ts": now_dt.isoformat(),
        },
    )
    assert exit_code == DAEMON_EXIT_HEARTBEAT_STALE
    assert reason.startswith("telegram_heartbeat_stale")
