from pathlib import Path

from app import compute_check_interval_sec
from config import Config


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


def test_enabled_healthy_uses_fast_interval(tmp_path: Path):
    config = _make_config(tmp_path)
    interval = compute_check_interval_sec(
        config,
        {"enabled": True, "paused_reason": "none", "consecutive_errors": 0},
    )
    assert interval == 20


def test_disabled_uses_idle_interval(tmp_path: Path):
    config = _make_config(tmp_path)
    interval = compute_check_interval_sec(
        config,
        {"enabled": False, "paused_reason": "manual_off", "consecutive_errors": 0},
    )
    assert interval == 60


def test_errors_back_off_and_cap(tmp_path: Path):
    config = _make_config(tmp_path)
    interval = compute_check_interval_sec(
        config,
        {"enabled": True, "paused_reason": "none", "consecutive_errors": 10},
    )
    assert interval == 180
