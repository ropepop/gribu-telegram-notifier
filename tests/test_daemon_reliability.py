from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from app import (
    DAEMON_EXIT_HEARTBEAT_STALE,
    DAEMON_EXIT_LOCK_HELD,
    DAEMON_EXIT_THREAD_DIED,
    evaluate_watchdog,
    run_daemon,
    run_healthcheck,
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
        supervisor_restart_max_sec=30,
        parse_low_confidence_delta_limit=20,
    )


def test_run_daemon_exits_when_lock_already_held(tmp_path: Path):
    config = _make_config(tmp_path)
    lock = ProcessLock(config.daemon_lock_file)
    lock.acquire()
    try:
        with pytest.raises(SystemExit) as exc:
            run_daemon(config)
        assert exc.value.code == DAEMON_EXIT_LOCK_HELD
    finally:
        lock.release()


def test_watchdog_detects_dead_worker_thread():
    now_dt = datetime.now(timezone.utc)
    exit_code, reason = evaluate_watchdog(
        now_dt=now_dt,
        stale_sec=120,
        thread_alive={"telegram": False, "scheduler": True, "command_worker": True},
        heartbeats={
            "telegram_last_heartbeat_ts": now_dt.isoformat(),
            "scheduler_last_heartbeat_ts": now_dt.isoformat(),
            "command_worker_last_heartbeat_ts": now_dt.isoformat(),
        },
    )
    assert exit_code == DAEMON_EXIT_THREAD_DIED
    assert reason == "telegram_thread_dead"


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


def test_healthcheck_fails_for_uninitialized_state(tmp_path: Path, capsys):
    config = _make_config(tmp_path)
    assert run_healthcheck(config) == 1
    captured = capsys.readouterr().out
    assert "unhealthy" in captured


def test_healthcheck_fails_for_stale_heartbeat(tmp_path: Path, capsys):
    config = _make_config(tmp_path)
    state_store = StateStore(config.state_file)
    stale_ts = (datetime.now(timezone.utc) - timedelta(seconds=121)).replace(microsecond=0).isoformat()
    state_store.patch(
        {
            "daemon_started_ts": stale_ts,
            "daemon_last_heartbeat_ts": stale_ts,
            "telegram_last_heartbeat_ts": stale_ts,
            "scheduler_last_heartbeat_ts": stale_ts,
            "command_worker_last_heartbeat_ts": stale_ts,
        }
    )
    assert run_healthcheck(config) == 1
    captured = capsys.readouterr().out
    assert "heartbeat_stale" in captured
