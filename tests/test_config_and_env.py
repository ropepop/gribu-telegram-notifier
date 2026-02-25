from __future__ import annotations

from pathlib import Path

import pytest

from config import ConfigError, load_config
from env_store import upsert_env_value


def _write_env(path: Path, lines: list[str]) -> None:
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def _clear_relevant_env(monkeypatch) -> None:
    keys = [
        "TELEGRAM_BOT_TOKEN",
        "TELEGRAM_CHAT_ID",
        "GRIBU_BASE_URL",
        "GRIBU_CHECK_URL",
        "GRIBU_LOGIN_ID",
        "GRIBU_LOGIN_PASSWORD",
        "GRIBU_LOGIN_PATH",
        "GRIBU_COOKIE_HEADER",
        "CHECK_INTERVAL_SEC",
        "CHECK_INTERVAL_FAST_SEC",
        "CHECK_INTERVAL_IDLE_SEC",
        "CHECK_INTERVAL_ERROR_BACKOFF_MAX_SEC",
        "STATE_FILE",
        "HTTP_TIMEOUT_SEC",
        "ERROR_ALERT_COOLDOWN_SEC",
        "TELEGRAM_API_BASE_URL",
        "TELEGRAM_NAV_BUTTONS_ENABLED",
        "DAEMON_LOCK_FILE",
        "WATCHDOG_CHECK_SEC",
        "WATCHDOG_STALE_SEC",
        "SUPERVISOR_RESTART_BASE_SEC",
        "SUPERVISOR_RESTART_MAX_SEC",
        "PARSE_LOW_CONFIDENCE_DELTA_LIMIT",
    ]
    for key in keys:
        monkeypatch.delenv(key, raising=False)


def test_missing_login_id_raises_config_error(tmp_path: Path, monkeypatch):
    _clear_relevant_env(monkeypatch)
    env_path = tmp_path / ".env"
    _write_env(
        env_path,
        [
            "TELEGRAM_BOT_TOKEN=token",
            "TELEGRAM_CHAT_ID=42",
            "GRIBU_LOGIN_PASSWORD=secret",
        ],
    )

    with pytest.raises(ConfigError) as exc:
        load_config(str(env_path))
    assert "GRIBU_LOGIN_ID" in str(exc.value)


def test_cookie_header_is_optional(tmp_path: Path, monkeypatch):
    _clear_relevant_env(monkeypatch)
    env_path = tmp_path / ".env"
    _write_env(
        env_path,
        [
            "TELEGRAM_BOT_TOKEN=token",
            "TELEGRAM_CHAT_ID=42",
            "GRIBU_LOGIN_ID=demo@example.com",
            "GRIBU_LOGIN_PASSWORD=secret",
        ],
    )

    config = load_config(str(env_path))
    assert config.gribu_cookie_header == ""
    assert config.env_file_path == env_path.resolve()
    assert config.state_file == (tmp_path / "state" / "state.json").resolve()
    assert config.daemon_lock_file == (tmp_path / "state" / "daemon.lock").resolve()
    assert config.watchdog_check_sec == 10
    assert config.watchdog_stale_sec == 120
    assert config.supervisor_restart_base_sec == 2
    assert config.supervisor_restart_max_sec == 30
    assert config.parse_low_confidence_delta_limit == 20
    assert config.check_interval_fast_sec == 20
    assert config.check_interval_idle_sec == 60
    assert config.check_interval_error_backoff_max_sec == 180
    assert config.telegram_nav_buttons_enabled is True


def test_absolute_paths_are_preserved(tmp_path: Path, monkeypatch):
    _clear_relevant_env(monkeypatch)
    env_path = tmp_path / ".env"
    explicit_state = (tmp_path / "custom" / "state.json").resolve()
    explicit_lock = (tmp_path / "custom" / "daemon.lock").resolve()
    _write_env(
        env_path,
        [
            "TELEGRAM_BOT_TOKEN=token",
            "TELEGRAM_CHAT_ID=42",
            "GRIBU_LOGIN_ID=demo@example.com",
            "GRIBU_LOGIN_PASSWORD=secret",
            f"STATE_FILE={explicit_state}",
            f"DAEMON_LOCK_FILE={explicit_lock}",
        ],
    )

    config = load_config(str(env_path))
    assert config.state_file == explicit_state
    assert config.daemon_lock_file == explicit_lock


def test_watchdog_stale_must_be_greater_than_watchdog_check(tmp_path: Path, monkeypatch):
    _clear_relevant_env(monkeypatch)
    env_path = tmp_path / ".env"
    _write_env(
        env_path,
        [
            "TELEGRAM_BOT_TOKEN=token",
            "TELEGRAM_CHAT_ID=42",
            "GRIBU_LOGIN_ID=demo@example.com",
            "GRIBU_LOGIN_PASSWORD=secret",
            "WATCHDOG_CHECK_SEC=30",
            "WATCHDOG_STALE_SEC=30",
        ],
    )

    with pytest.raises(ConfigError) as exc:
        load_config(str(env_path))
    assert "WATCHDOG_STALE_SEC" in str(exc.value)


def test_supervisor_restart_max_must_be_at_least_base(tmp_path: Path, monkeypatch):
    _clear_relevant_env(monkeypatch)
    env_path = tmp_path / ".env"
    _write_env(
        env_path,
        [
            "TELEGRAM_BOT_TOKEN=token",
            "TELEGRAM_CHAT_ID=42",
            "GRIBU_LOGIN_ID=demo@example.com",
            "GRIBU_LOGIN_PASSWORD=secret",
            "SUPERVISOR_RESTART_BASE_SEC=10",
            "SUPERVISOR_RESTART_MAX_SEC=5",
        ],
    )

    with pytest.raises(ConfigError) as exc:
        load_config(str(env_path))
    assert "SUPERVISOR_RESTART_MAX_SEC" in str(exc.value)


def test_error_backoff_max_must_be_at_least_fast_interval(tmp_path: Path, monkeypatch):
    _clear_relevant_env(monkeypatch)
    env_path = tmp_path / ".env"
    _write_env(
        env_path,
        [
            "TELEGRAM_BOT_TOKEN=token",
            "TELEGRAM_CHAT_ID=42",
            "GRIBU_LOGIN_ID=demo@example.com",
            "GRIBU_LOGIN_PASSWORD=secret",
            "CHECK_INTERVAL_FAST_SEC=45",
            "CHECK_INTERVAL_ERROR_BACKOFF_MAX_SEC=30",
        ],
    )

    with pytest.raises(ConfigError) as exc:
        load_config(str(env_path))
    assert "CHECK_INTERVAL_ERROR_BACKOFF_MAX_SEC" in str(exc.value)


def test_nav_buttons_boolean_is_parsed(tmp_path: Path, monkeypatch):
    _clear_relevant_env(monkeypatch)
    env_path = tmp_path / ".env"
    _write_env(
        env_path,
        [
            "TELEGRAM_BOT_TOKEN=token",
            "TELEGRAM_CHAT_ID=42",
            "GRIBU_LOGIN_ID=demo@example.com",
            "GRIBU_LOGIN_PASSWORD=secret",
            "TELEGRAM_NAV_BUTTONS_ENABLED=false",
        ],
    )

    config = load_config(str(env_path))
    assert config.telegram_nav_buttons_enabled is False


def test_upsert_env_value_rewrites_cookie_line_only(tmp_path: Path):
    env_path = tmp_path / ".env"
    original = (
        "TELEGRAM_BOT_TOKEN=token\n"
        "GRIBU_COOKIE_HEADER=OLD=1; OLD2=2\n"
        "CHECK_INTERVAL_SEC=60\n"
    )
    env_path.write_text(original, encoding="utf-8")

    upsert_env_value(env_path, "GRIBU_COOKIE_HEADER", "DATED=abc; DATINGSES=def")
    updated = env_path.read_text(encoding="utf-8")

    assert "TELEGRAM_BOT_TOKEN=token\n" in updated
    assert "CHECK_INTERVAL_SEC=60\n" in updated
    assert "GRIBU_COOKIE_HEADER=DATED=abc; DATINGSES=def\n" in updated
    assert "GRIBU_COOKIE_HEADER=OLD=1; OLD2=2\n" not in updated
