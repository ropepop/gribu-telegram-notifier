from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv


class ConfigError(Exception):
    pass


@dataclass(frozen=True)
class Config:
    telegram_bot_token: str
    telegram_chat_id: int
    gribu_base_url: str
    gribu_check_url: str
    gribu_login_id: str
    gribu_login_password: str
    gribu_login_path: str
    gribu_cookie_header: str
    check_interval_sec: int
    check_interval_fast_sec: int
    check_interval_idle_sec: int
    check_interval_error_backoff_max_sec: int
    state_file: Path
    http_timeout_sec: int
    error_alert_cooldown_sec: int
    telegram_api_base_url: str
    telegram_nav_buttons_enabled: bool
    env_file_path: Path
    daemon_lock_file: Path
    watchdog_check_sec: int
    watchdog_stale_sec: int
    supervisor_restart_base_sec: int
    supervisor_restart_max_sec: int
    parse_low_confidence_delta_limit: int


def _get_required(name: str) -> str:
    value = os.getenv(name, "").strip()
    if not value:
        raise ConfigError(f"Missing required environment variable: {name}")
    return value


def _get_int(name: str, default: int) -> int:
    raw = os.getenv(name, str(default)).strip()
    try:
        value = int(raw)
    except ValueError as exc:
        raise ConfigError(f"{name} must be an integer, got: {raw!r}") from exc
    if value <= 0:
        raise ConfigError(f"{name} must be > 0, got: {value}")
    return value


def _get_bool(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    value = raw.strip().lower()
    if value in {"1", "true", "yes", "on"}:
        return True
    if value in {"0", "false", "no", "off"}:
        return False
    raise ConfigError(f"{name} must be a boolean value, got: {raw!r}")


def _resolve_path_env_relative(name: str, default: str, base_dir: Path) -> Path:
    raw_value = os.getenv(name, default).strip() or default
    path = Path(raw_value).expanduser()
    if not path.is_absolute():
        path = base_dir / path
    return path.resolve()


def load_config(env_file: str | None = ".env") -> Config:
    if env_file:
        load_dotenv(env_file)
        env_file_path = Path(env_file).expanduser().resolve()
    else:
        load_dotenv()
        env_file_path = Path(".env").resolve()
    env_dir = env_file_path.parent

    chat_id_raw = _get_required("TELEGRAM_CHAT_ID")
    try:
        chat_id = int(chat_id_raw)
    except ValueError as exc:
        raise ConfigError(
            f"TELEGRAM_CHAT_ID must be an integer, got: {chat_id_raw!r}"
        ) from exc

    state_file = _resolve_path_env_relative("STATE_FILE", "./state/state.json", env_dir)
    daemon_lock_file = _resolve_path_env_relative("DAEMON_LOCK_FILE", "./state/daemon.lock", env_dir)
    watchdog_check_sec = _get_int("WATCHDOG_CHECK_SEC", 10)
    watchdog_stale_sec = _get_int("WATCHDOG_STALE_SEC", 120)
    if watchdog_stale_sec <= watchdog_check_sec:
        raise ConfigError(
            "WATCHDOG_STALE_SEC must be greater than WATCHDOG_CHECK_SEC "
            f"({watchdog_stale_sec} <= {watchdog_check_sec})"
        )
    supervisor_restart_base_sec = _get_int("SUPERVISOR_RESTART_BASE_SEC", 2)
    supervisor_restart_max_sec = _get_int("SUPERVISOR_RESTART_MAX_SEC", 30)
    parse_low_confidence_delta_limit = _get_int("PARSE_LOW_CONFIDENCE_DELTA_LIMIT", 20)
    if supervisor_restart_max_sec < supervisor_restart_base_sec:
        raise ConfigError(
            "SUPERVISOR_RESTART_MAX_SEC must be >= SUPERVISOR_RESTART_BASE_SEC "
            f"({supervisor_restart_max_sec} < {supervisor_restart_base_sec})"
        )

    check_interval_sec = _get_int("CHECK_INTERVAL_SEC", 60)
    check_interval_fast_default = min(check_interval_sec, 20)
    check_interval_fast_sec = _get_int("CHECK_INTERVAL_FAST_SEC", check_interval_fast_default)
    check_interval_idle_sec = _get_int("CHECK_INTERVAL_IDLE_SEC", check_interval_sec)
    check_interval_error_backoff_max_sec = _get_int("CHECK_INTERVAL_ERROR_BACKOFF_MAX_SEC", 180)
    if check_interval_error_backoff_max_sec < check_interval_fast_sec:
        raise ConfigError(
            "CHECK_INTERVAL_ERROR_BACKOFF_MAX_SEC must be >= CHECK_INTERVAL_FAST_SEC "
            f"({check_interval_error_backoff_max_sec} < {check_interval_fast_sec})"
        )

    return Config(
        telegram_bot_token=_get_required("TELEGRAM_BOT_TOKEN"),
        telegram_chat_id=chat_id,
        gribu_base_url=os.getenv("GRIBU_BASE_URL", "https://www.gribu.lv").strip(),
        gribu_check_url=os.getenv("GRIBU_CHECK_URL", "/lv/messages").strip(),
        gribu_login_id=_get_required("GRIBU_LOGIN_ID"),
        gribu_login_password=_get_required("GRIBU_LOGIN_PASSWORD"),
        gribu_login_path=os.getenv("GRIBU_LOGIN_PATH", "/pieslegties").strip() or "/pieslegties",
        gribu_cookie_header=os.getenv("GRIBU_COOKIE_HEADER", "").strip(),
        check_interval_sec=check_interval_sec,
        check_interval_fast_sec=check_interval_fast_sec,
        check_interval_idle_sec=check_interval_idle_sec,
        check_interval_error_backoff_max_sec=check_interval_error_backoff_max_sec,
        state_file=state_file,
        http_timeout_sec=_get_int("HTTP_TIMEOUT_SEC", 20),
        error_alert_cooldown_sec=_get_int("ERROR_ALERT_COOLDOWN_SEC", 1800),
        telegram_api_base_url=os.getenv(
            "TELEGRAM_API_BASE_URL", "https://api.telegram.org"
        ).strip(),
        telegram_nav_buttons_enabled=_get_bool("TELEGRAM_NAV_BUTTONS_ENABLED", True),
        env_file_path=env_file_path,
        daemon_lock_file=daemon_lock_file,
        watchdog_check_sec=watchdog_check_sec,
        watchdog_stale_sec=watchdog_stale_sec,
        supervisor_restart_base_sec=supervisor_restart_base_sec,
        supervisor_restart_max_sec=supervisor_restart_max_sec,
        parse_low_confidence_delta_limit=parse_low_confidence_delta_limit,
    )
