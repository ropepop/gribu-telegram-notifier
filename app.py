from __future__ import annotations

import argparse
import json
import logging
import queue
import signal
import threading
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Callable

from config import Config, ConfigError, load_config
from env_store import EnvStoreError, upsert_env_value
from gribu_auth import GribuAuthError, GribuAuthenticator
from gribu_client import GribuClient, GribuClientError, looks_like_session_expired
from process_lock import ProcessLock, ProcessLockHeldError
from state_store import StateStore
from telegram_control import (
    TelegramApiError,
    TelegramClient,
    TelegramCommandCallbacks,
    TelegramController,
    build_navigation_reply_markup,
)
from unread_parser import UnreadParseError, parse_unread_count

LOG = logging.getLogger("gribu_notifier")
ERROR_ALERT_THRESHOLD = 3
DAEMON_EXIT_LOCK_HELD = 10
DAEMON_EXIT_THREAD_DIED = 20
DAEMON_EXIT_HEARTBEAT_STALE = 21
WORKER_HEARTBEAT_COMPONENTS = ("telegram", "scheduler", "command_worker")
HEARTBEAT_COMPONENTS = ("daemon",) + WORKER_HEARTBEAT_COMPONENTS
SUPERVISOR_STABLE_WINDOW_SEC = 600
RECOVERABLE_WORKER_EXIT_CODES = {DAEMON_EXIT_THREAD_DIED, DAEMON_EXIT_HEARTBEAT_STALE}
ASYNC_COMMAND_CHECKNOW = "checknow"
ASYNC_COMMAND_REAUTH = "reauth"


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def parse_iso(ts: str | None) -> datetime | None:
    if not ts:
        return None
    try:
        return datetime.fromisoformat(ts)
    except ValueError:
        return None


def _heartbeat_key(component: str) -> str:
    return f"{component}_last_heartbeat_ts"


def _heartbeat_age_seconds(now_dt: datetime, heartbeat_iso: str | None) -> float | None:
    heartbeat_dt = parse_iso(heartbeat_iso)
    if heartbeat_dt is None:
        return None
    age = (now_dt - heartbeat_dt).total_seconds()
    return max(0.0, age)


def _format_time_delta(seconds: float) -> str:
    seconds_int = max(0, int(seconds))
    minutes, secs = divmod(seconds_int, 60)
    hours, minutes = divmod(minutes, 60)
    if hours > 0:
        return f"{hours}h {minutes}m"
    if minutes > 0:
        return f"{minutes}m {secs}s"
    return f"{secs}s"


def _format_age(now_dt: datetime, ts: str | None) -> str:
    value = parse_iso(ts)
    if value is None:
        return "never"
    age_sec = (now_dt - value).total_seconds()
    if age_sec < 0:
        return "just now"
    return f"{_format_time_delta(age_sec)} ago"


def _format_eta(now_dt: datetime, ts: str | None) -> str:
    value = parse_iso(ts)
    if value is None:
        return "unknown"
    delta = (value - now_dt).total_seconds()
    if delta <= 0:
        return "due now"
    return f"in {_format_time_delta(delta)}"


def compute_check_interval_sec(config: Config, state: dict) -> int:
    enabled = bool(state.get("enabled"))
    paused_reason = str(state.get("paused_reason") or "none")
    if not enabled or paused_reason == "session_expired":
        return config.check_interval_idle_sec

    consecutive_errors = max(0, int(state.get("consecutive_errors", 0)))
    if consecutive_errors <= 0:
        return config.check_interval_fast_sec

    step = config.check_interval_fast_sec * (2 ** min(consecutive_errors - 1, 10))
    return min(config.check_interval_error_backoff_max_sec, step)


def _next_due_iso(interval_sec: int) -> str:
    return (datetime.now(timezone.utc) + timedelta(seconds=interval_sec)).replace(microsecond=0).isoformat()


def evaluate_watchdog(
    *,
    now_dt: datetime,
    stale_sec: int,
    thread_alive: dict[str, bool],
    heartbeats: dict[str, str | None],
) -> tuple[int | None, str | None]:
    for component in WORKER_HEARTBEAT_COMPONENTS:
        if not thread_alive.get(component, False):
            return DAEMON_EXIT_THREAD_DIED, f"{component}_thread_dead"

    for component in WORKER_HEARTBEAT_COMPONENTS:
        heartbeat_key = _heartbeat_key(component)
        age = _heartbeat_age_seconds(now_dt, heartbeats.get(heartbeat_key))
        if age is None:
            return DAEMON_EXIT_HEARTBEAT_STALE, f"{component}_heartbeat_missing"
        if age > stale_sec:
            return DAEMON_EXIT_HEARTBEAT_STALE, f"{component}_heartbeat_stale:{int(age)}s"

    return None, None


def evaluate_health_state(
    *,
    state: dict,
    now_dt: datetime,
    stale_sec: int,
) -> tuple[bool, str]:
    started_dt = parse_iso(state.get("daemon_started_ts"))
    if started_dt is None:
        return False, "daemon_not_initialized"

    for component in HEARTBEAT_COMPONENTS:
        heartbeat_key = _heartbeat_key(component)
        age = _heartbeat_age_seconds(now_dt, state.get(heartbeat_key))
        if age is None:
            return False, f"{heartbeat_key}_missing_or_invalid"
        if age > stale_sec:
            return False, f"{component}_heartbeat_stale:{int(age)}s"
    return True, "ok"


class HeartbeatTracker:
    def __init__(self, state_store: StateStore):
        self.state_store = state_store
        self._lock = threading.Lock()
        self._heartbeats: dict[str, str | None] = {
            _heartbeat_key(component): None for component in HEARTBEAT_COMPONENTS
        }

    def initialize(self, now_iso: str) -> None:
        with self._lock:
            for component in HEARTBEAT_COMPONENTS:
                self._heartbeats[_heartbeat_key(component)] = now_iso
            snapshot = dict(self._heartbeats)
        self.state_store.patch(snapshot)

    def mark(self, component: str, now_iso: str | None = None) -> str:
        if component not in HEARTBEAT_COMPONENTS:
            raise ValueError(f"Unknown heartbeat component: {component}")
        ts = now_iso or utc_now_iso()
        key = _heartbeat_key(component)
        with self._lock:
            self._heartbeats[key] = ts
        self.state_store.patch({key: ts})
        return ts

    def snapshot(self) -> dict[str, str | None]:
        with self._lock:
            return dict(self._heartbeats)


class NotifierService:
    def __init__(
        self,
        config: Config,
        state_store: StateStore,
        gribu_client: GribuClient,
        gribu_authenticator: GribuAuthenticator,
        telegram_client: TelegramClient,
        on_checks_enabled: Callable[[], None] | None = None,
        navigation_reply_markup: dict[str, Any] | None = None,
    ):
        self.config = config
        self.state_store = state_store
        self.gribu_client = gribu_client
        self.gribu_authenticator = gribu_authenticator
        self.telegram_client = telegram_client
        self._check_lock = threading.Lock()
        self._on_checks_enabled = on_checks_enabled
        self._navigation_reply_markup = navigation_reply_markup

    def is_enabled(self) -> bool:
        state = self.state_store.load()
        return bool(state.get("enabled"))

    def _send_telegram(self, text: str) -> bool:
        try:
            self.telegram_client.send_message(
                chat_id=self.config.telegram_chat_id,
                text=text,
                reply_markup=self._navigation_reply_markup,
            )
            return True
        except TelegramApiError as exc:
            LOG.error("Failed to send Telegram message: %s", exc)
            return False

    def _status_mode(self, state: dict) -> str:
        if not state.get("enabled"):
            return "off"
        paused_reason = str(state.get("paused_reason") or "none")
        if paused_reason != "none":
            return f"paused ({paused_reason})"
        return "active"

    def _status_health(self, state: dict) -> str:
        problems: list[str] = []
        if int(state.get("consecutive_errors", 0)) > 0:
            problems.append(f"errors={state.get('consecutive_errors')}")
        last_watchdog_reason = state.get("last_watchdog_reason")
        if last_watchdog_reason not in (None, "none"):
            problems.append(f"watchdog={last_watchdog_reason}")
        if state.get("paused_reason") == "session_expired":
            problems.append("session_expired")
        if problems:
            return "degraded (" + ", ".join(problems) + ")"
        return "healthy"

    def _status_action(self, state: dict) -> str:
        if state.get("paused_reason") == "session_expired":
            return "Action: tap Reauth (or send /reauth)."
        if not state.get("enabled"):
            return "Action: tap Enable (or send /on)."
        if int(state.get("consecutive_errors", 0)) > 0:
            return "Action: tap Check now (or send /checknow)."
        return "Action: monitoring normally."

    def _format_status(self, state: dict) -> str:
        now_dt = datetime.now(timezone.utc)
        current_interval = state.get("current_check_interval_sec") or self.config.check_interval_idle_sec
        return (
            "gribu notifier status:\n"
            f"- mode: {self._status_mode(state)}\n"
            f"- health: {self._status_health(state)}\n"
            f"- unread baseline: {state.get('last_unread')}\n"
            f"- last success: {_format_age(now_dt, state.get('last_success_ts'))}\n"
            f"- cadence: every {current_interval}s, next check {_format_eta(now_dt, state.get('next_check_due_ts'))}\n"
            f"- last result: {state.get('last_check_result')}\n"
            f"- {self._status_action(state)}"
        )

    def _format_debug_status(self, state: dict) -> str:
        return (
            "gribu checker debug status:\n"
            f"- enabled: {state.get('enabled')}\n"
            f"- paused_reason: {state.get('paused_reason')}\n"
            f"- last_unread: {state.get('last_unread')}\n"
            f"- last_check_ts: {state.get('last_check_ts')}\n"
            f"- last_success_ts: {state.get('last_success_ts')}\n"
            f"- last_check_result: {state.get('last_check_result')}\n"
            f"- last_error_message: {state.get('last_error_message')}\n"
            f"- last_parse_source: {state.get('last_parse_source')}\n"
            f"- last_parse_confidence: {state.get('last_parse_confidence')}\n"
            f"- consecutive_errors: {state.get('consecutive_errors')}\n"
            f"- daemon_started_ts: {state.get('daemon_started_ts')}\n"
            f"- daemon_last_heartbeat_ts: {state.get('daemon_last_heartbeat_ts')}\n"
            f"- telegram_last_heartbeat_ts: {state.get('telegram_last_heartbeat_ts')}\n"
            f"- scheduler_last_heartbeat_ts: {state.get('scheduler_last_heartbeat_ts')}\n"
            f"- command_worker_last_heartbeat_ts: {state.get('command_worker_last_heartbeat_ts')}\n"
            f"- current_check_interval_sec: {state.get('current_check_interval_sec')}\n"
            f"- next_check_due_ts: {state.get('next_check_due_ts')}\n"
            f"- check_duration_ms: {state.get('check_duration_ms')}\n"
            f"- last_notification_sent_ts: {state.get('last_notification_sent_ts')}\n"
            f"- last_command_latency_ms: {state.get('last_command_latency_ms')}\n"
            f"- last_watchdog_reason: {state.get('last_watchdog_reason')}\n"
            f"- daemon_restart_count: {state.get('daemon_restart_count')}\n"
            f"- last_restart_ts: {state.get('last_restart_ts')}\n"
            f"- telegram_poll_error_count: {state.get('telegram_poll_error_count')}"
        )

    def command_on(self) -> str:
        previous = self.state_store.load()
        state = self.state_store.patch(
            {
                "enabled": True,
                "paused_reason": "none",
            }
        )
        if not bool(previous.get("enabled")) and self._on_checks_enabled is not None:
            self._on_checks_enabled()
        return (
            "Checks enabled."
            f"\nFast cadence: {self.config.check_interval_fast_sec}s (idle {self.config.check_interval_idle_sec}s)."
            f"\nCurrent unread baseline: {state.get('last_unread')}"
        )

    def command_off(self) -> str:
        self.state_store.patch(
            {
                "enabled": False,
                "paused_reason": "manual_off",
            }
        )
        return "Checks disabled."

    def command_status(self) -> str:
        state = self.state_store.load()
        return self._format_status(state)

    def command_debug(self) -> str:
        state = self.state_store.load()
        return self._format_debug_status(state)

    def command_checknow(self) -> str:
        result = self.run_check(force=True)
        return f"Manual check result: {result}"

    def command_reauth(self) -> str:
        with self._check_lock:
            ok, error_message = self._try_reauthenticate()
            if not ok:
                self.state_store.patch({
                    "last_error_message": error_message,
                    "last_check_result": "reauth_failed",
                })
                return f"Reauth failed: {error_message}"

            state = self.state_store.load()
            if state.get("paused_reason") == "session_expired":
                self.state_store.patch(
                    {
                        "enabled": True,
                        "paused_reason": "none",
                        "last_error_message": None,
                        "last_check_result": "reauth_resumed",
                    }
                )
                return "Reauth successful. Checks resumed."

            self.state_store.patch({"last_error_message": None, "last_check_result": "reauth_ok"})
            return "Reauth successful."

    def command_help(self) -> str:
        return (
            "Quick actions: Enable, Pause, Status, Check now, Reauth, Help.\n"
            "Commands:\n"
            "/on - enable checks\n"
            "/off - disable checks\n"
            "/status - compact status summary\n"
            "/debug - full technical diagnostics\n"
            "/checknow - run one check now\n"
            "/reauth - force login and refresh session cookie\n"
            "/help - show this help"
        )

    def _persist_cookie_header(self) -> None:
        cookie_header = self.gribu_client.export_cookie_header().strip()
        if not cookie_header:
            raise GribuAuthError("Authentication succeeded but no session cookies were captured")
        upsert_env_value(self.config.env_file_path, "GRIBU_COOKIE_HEADER", cookie_header)
        self.gribu_client.cookie_header = cookie_header

    def _authenticate_and_persist_cookie(self) -> None:
        self.gribu_authenticator.authenticate(
            login_id=self.config.gribu_login_id,
            login_password=self.config.gribu_login_password,
        )
        self._persist_cookie_header()

    def startup_authenticate(self) -> bool:
        try:
            self._authenticate_and_persist_cookie()
            return True
        except (GribuAuthError, EnvStoreError) as exc:
            LOG.warning("Initial authentication failed: %s", exc)
            return False

    def _try_reauthenticate(self) -> tuple[bool, str | None]:
        try:
            self._authenticate_and_persist_cookie()
            return True, None
        except (GribuAuthError, EnvStoreError) as exc:
            return False, str(exc)

    def _should_send_error_alert(self, state: dict, now_dt: datetime) -> bool:
        consecutive = int(state.get("consecutive_errors", 0))
        if consecutive < ERROR_ALERT_THRESHOLD:
            return False
        last_alert_dt = parse_iso(state.get("last_error_alert_ts"))
        if last_alert_dt is None:
            return True
        elapsed = (now_dt - last_alert_dt).total_seconds()
        return elapsed >= self.config.error_alert_cooldown_sec

    def _handle_transient_error(
        self,
        state: dict,
        now_iso: str,
        error_message: str,
        *,
        parse_source: str | None = None,
        parse_confidence: float | None = None,
    ) -> str:
        now_dt = parse_iso(now_iso) or datetime.now(timezone.utc)
        next_errors = int(state.get("consecutive_errors", 0)) + 1
        result = f"error: {error_message}"
        patch = {
            "last_check_ts": now_iso,
            "consecutive_errors": next_errors,
            "last_check_result": result,
            "last_error_message": error_message,
            "last_parse_source": parse_source,
            "last_parse_confidence": parse_confidence,
        }
        temp_state = dict(state)
        temp_state.update(patch)
        if self._should_send_error_alert(temp_state, now_dt):
            self._send_telegram(
                "gribu checker warning: consecutive errors detected.\n"
                f"errors: {next_errors}\n"
                f"last error: {error_message}"
            )
            patch["last_error_alert_ts"] = now_iso
        self.state_store.patch(patch)
        return result

    def _handle_session_expired(self, state: dict, now_iso: str, reauth_error: str | None = None) -> str:
        already_paused = (
            state.get("enabled") is False and state.get("paused_reason") == "session_expired"
        )
        error_text = reauth_error or "session appears expired"
        patch = {
            "enabled": False,
            "paused_reason": "session_expired",
            "last_check_ts": now_iso,
            "consecutive_errors": int(state.get("consecutive_errors", 0)) + 1,
            "last_check_result": "session_expired",
            "last_error_message": error_text,
            "last_parse_source": None,
            "last_parse_confidence": None,
        }
        self.state_store.patch(patch)
        if not already_paused:
            message = (
                "gribu session appears expired and automatic reauth failed. Checks are paused.\n"
                "Send /reauth to retry."
            )
            if reauth_error:
                message += f"\nlast error: {reauth_error}"
            self._send_telegram(message)
        return "session_expired"

    def run_check(self, force: bool = False) -> str:
        started = time.monotonic()
        try:
            with self._check_lock:
                state = self.state_store.load()
                if not force and not state.get("enabled"):
                    self.state_store.patch(
                        {
                            "last_check_result": "skipped_disabled",
                            "last_error_message": None,
                            "last_parse_source": None,
                            "last_parse_confidence": None,
                        }
                    )
                    return "skipped_disabled"

                now_iso = utc_now_iso()

                try:
                    response = self.gribu_client.fetch_check_page(self.config.gribu_check_url)
                except GribuClientError as exc:
                    return self._handle_transient_error(state, now_iso, str(exc))

                if looks_like_session_expired(response):
                    reauth_ok, reauth_error = self._try_reauthenticate()
                    if not reauth_ok:
                        return self._handle_session_expired(state, now_iso, reauth_error)
                    try:
                        response = self.gribu_client.fetch_check_page(self.config.gribu_check_url)
                    except GribuClientError as exc:
                        return self._handle_transient_error(state, now_iso, str(exc))
                    if looks_like_session_expired(response):
                        return self._handle_session_expired(
                            state,
                            now_iso,
                            "Session still appears expired after reauth",
                        )

                try:
                    parsed = parse_unread_count(response.text)
                except UnreadParseError as exc:
                    if looks_like_session_expired(response):
                        return self._handle_session_expired(state, now_iso, str(exc))
                    return self._handle_transient_error(state, now_iso, str(exc))

                previous_unread = state.get("last_unread")
                current_unread = parsed.unread_count

                if previous_unread is not None and parsed.confidence < 0.5:
                    delta = abs(current_unread - int(previous_unread))
                    if delta > self.config.parse_low_confidence_delta_limit:
                        return self._handle_transient_error(
                            state,
                            now_iso,
                            (
                                "Low-confidence parse jump rejected "
                                f"({previous_unread}->{current_unread}, "
                                f"source={parsed.source}, confidence={parsed.confidence:.2f})"
                            ),
                            parse_source=parsed.source,
                            parse_confidence=parsed.confidence,
                        )

                if previous_unread is None:
                    result = f"baseline_set:{current_unread}"
                elif current_unread > int(previous_unread):
                    result = f"notified:{previous_unread}->{current_unread}"
                else:
                    result = f"no_change:{previous_unread}->{current_unread}"

                self.state_store.patch(
                    {
                        "last_check_ts": now_iso,
                        "last_success_ts": now_iso,
                        "consecutive_errors": 0,
                        "last_unread": current_unread,
                        "last_check_result": result,
                        "last_error_message": None,
                        "last_parse_source": parsed.source,
                        "last_parse_confidence": parsed.confidence,
                    }
                )

                if previous_unread is not None and current_unread > int(previous_unread):
                    if self._send_telegram(
                        "New gribu.lv messages.\n"
                        f"Unread increased: {previous_unread} -> {current_unread}\n"
                        f"Open: {response.url}"
                    ):
                        self.state_store.patch({"last_notification_sent_ts": utc_now_iso()})

                return result
        finally:
            duration_ms = int((time.monotonic() - started) * 1000)
            self.state_store.patch({"check_duration_ms": max(0, duration_ms)})


def build_service(
    config: Config,
    on_checks_enabled: Callable[[], None] | None = None,
) -> NotifierService:
    state_store = StateStore(config.state_file)
    state_store.load()
    gribu_client = GribuClient(
        base_url=config.gribu_base_url,
        cookie_header=config.gribu_cookie_header,
        timeout_sec=config.http_timeout_sec,
    )
    gribu_authenticator = GribuAuthenticator(
        base_url=config.gribu_base_url,
        login_path=config.gribu_login_path,
        session=gribu_client.session,
        timeout_sec=config.http_timeout_sec,
    )
    telegram_client = TelegramClient(
        token=config.telegram_bot_token,
        timeout_sec=config.http_timeout_sec,
        api_base_url=config.telegram_api_base_url,
    )
    navigation_markup = (
        build_navigation_reply_markup() if config.telegram_nav_buttons_enabled else None
    )
    service = NotifierService(
        config=config,
        state_store=state_store,
        gribu_client=gribu_client,
        gribu_authenticator=gribu_authenticator,
        telegram_client=telegram_client,
        on_checks_enabled=on_checks_enabled,
        navigation_reply_markup=navigation_markup,
    )
    service.startup_authenticate()
    return service


def _increment_telegram_poll_error(state_store: StateStore, error: Exception) -> None:
    def _mutator(state: dict) -> dict:
        state["telegram_poll_error_count"] = int(state.get("telegram_poll_error_count", 0)) + 1
        state["last_error_message"] = f"telegram_poll_error: {error}"
        return state

    state_store.mutate(_mutator)


def _record_scheduler_timing(state_store: StateStore, config: Config) -> int:
    state = state_store.load()
    interval_sec = compute_check_interval_sec(config, state)
    state_store.patch(
        {
            "current_check_interval_sec": interval_sec,
            "next_check_due_ts": _next_due_iso(interval_sec),
        }
    )
    return interval_sec


def _run_adaptive_scheduler_loop(
    *,
    stop_event: threading.Event,
    force_check_event: threading.Event,
    service: NotifierService,
    state_store: StateStore,
    config: Config,
    on_iteration: Callable[[], None] | None = None,
) -> None:
    next_run = time.monotonic()
    last_heartbeat_monotonic = next_run

    while not stop_event.is_set():
        now = time.monotonic()
        if on_iteration is not None and now - last_heartbeat_monotonic >= 1.0:
            on_iteration()
            last_heartbeat_monotonic = now

        force = force_check_event.is_set()
        if not force and now < next_run:
            sleep_for = min(0.25, max(0.0, next_run - now))
            time.sleep(sleep_for)
            continue

        if force:
            force_check_event.clear()
            state = state_store.load()
            if not state.get("enabled"):
                force = False

        started = time.monotonic()
        try:
            service.run_check(force=force)
        except Exception:
            LOG.exception("Unhandled exception in scheduler job")

        duration_ms = int((time.monotonic() - started) * 1000)
        interval_sec = _record_scheduler_timing(state_store, config)
        next_run = time.monotonic() + interval_sec
        state_store.patch({"check_duration_ms": max(0, duration_ms)})
        if on_iteration is not None:
            on_iteration()
            last_heartbeat_monotonic = time.monotonic()


def _run_async_command_worker(
    *,
    stop_event: threading.Event,
    command_queue: "queue.Queue[tuple[str, Callable[[], str]]]",
    in_flight_commands: set[str],
    in_flight_lock: threading.Lock,
    service: NotifierService,
    state_store: StateStore,
    on_iteration: Callable[[], None] | None = None,
) -> None:
    last_heartbeat_monotonic = time.monotonic()
    while not stop_event.is_set():
        now = time.monotonic()
        if on_iteration is not None and now - last_heartbeat_monotonic >= 1.0:
            on_iteration()
            last_heartbeat_monotonic = now

        try:
            command_name, handler = command_queue.get(timeout=0.25)
        except queue.Empty:
            continue

        started = time.monotonic()
        try:
            response = handler()
        except Exception:
            LOG.exception("Unhandled exception in async command worker (%s)", command_name)
            response = f"{command_name} failed due to an unexpected error."

        latency_ms = int((time.monotonic() - started) * 1000)
        state_store.patch({"last_command_latency_ms": max(0, latency_ms)})
        service._send_telegram(response)

        with in_flight_lock:
            in_flight_commands.discard(command_name)
        command_queue.task_done()

        if on_iteration is not None:
            on_iteration()
            last_heartbeat_monotonic = time.monotonic()


def _run_daemon_worker(config: Config, lock: ProcessLock, supervisor_stop_event: threading.Event) -> int:
    del lock  # Lock ownership is managed by the supervisor.
    stop_event = threading.Event()
    force_check_event = threading.Event()
    command_queue: queue.Queue[tuple[str, Callable[[], str]]] = queue.Queue()
    in_flight_commands: set[str] = set()
    in_flight_lock = threading.Lock()
    telegram_thread: threading.Thread | None = None
    scheduler_thread: threading.Thread | None = None
    command_worker_thread: threading.Thread | None = None

    try:
        def _request_immediate_check() -> None:
            force_check_event.set()

        service = build_service(config, on_checks_enabled=_request_immediate_check)
        state_store = service.state_store
        heartbeat_tracker = HeartbeatTracker(state_store)
        now_iso = utc_now_iso()
        state_store.patch(
            {
                "daemon_started_ts": now_iso,
                "last_watchdog_reason": "none",
            }
        )
        heartbeat_tracker.initialize(now_iso)
        _record_scheduler_timing(state_store, config)

        def _enqueue_async_command(
            command_name: str,
            handler: Callable[[], str],
            started_message: str,
            in_progress_message: str,
        ) -> str:
            with in_flight_lock:
                if command_name in in_flight_commands:
                    return in_progress_message
                in_flight_commands.add(command_name)
            command_queue.put((command_name, handler))
            return started_message

        def _queue_checknow() -> str:
            return _enqueue_async_command(
                ASYNC_COMMAND_CHECKNOW,
                service.command_checknow,
                "Manual check started. I will send the result shortly.",
                "Manual check is already in progress.",
            )

        def _queue_reauth() -> str:
            return _enqueue_async_command(
                ASYNC_COMMAND_REAUTH,
                service.command_reauth,
                "Reauth started. I will send the result shortly.",
                "Reauth is already in progress.",
            )

        callbacks = TelegramCommandCallbacks(
            on_on=service.command_on,
            on_off=service.command_off,
            on_status=service.command_status,
            on_debug=service.command_debug,
            on_checknow=_queue_checknow,
            on_reauth=_queue_reauth,
            on_help=service.command_help,
        )
        controller = TelegramController(
            client=service.telegram_client,
            state_store=state_store,
            authorized_chat_id=config.telegram_chat_id,
            callbacks=callbacks,
            navigation_buttons_enabled=config.telegram_nav_buttons_enabled,
        )

        def _mark_telegram_heartbeat() -> None:
            heartbeat_tracker.mark("telegram")

        def _mark_scheduler_heartbeat() -> None:
            heartbeat_tracker.mark("scheduler")

        def _mark_command_worker_heartbeat() -> None:
            heartbeat_tracker.mark("command_worker")

        def _on_telegram_poll_error(exc: Exception) -> None:
            _increment_telegram_poll_error(state_store, exc)

        telegram_thread = threading.Thread(
            target=controller.run_forever,
            kwargs={
                "stop_event": stop_event,
                "on_iteration": _mark_telegram_heartbeat,
                "on_poll_error": _on_telegram_poll_error,
            },
            daemon=True,
            name="telegram-controller",
        )
        scheduler_thread = threading.Thread(
            target=_run_adaptive_scheduler_loop,
            kwargs={
                "stop_event": stop_event,
                "force_check_event": force_check_event,
                "service": service,
                "state_store": state_store,
                "config": config,
                "on_iteration": _mark_scheduler_heartbeat,
            },
            daemon=True,
            name="check-scheduler",
        )
        command_worker_thread = threading.Thread(
            target=_run_async_command_worker,
            kwargs={
                "stop_event": stop_event,
                "command_queue": command_queue,
                "in_flight_commands": in_flight_commands,
                "in_flight_lock": in_flight_lock,
                "service": service,
                "state_store": state_store,
                "on_iteration": _mark_command_worker_heartbeat,
            },
            daemon=True,
            name="command-worker",
        )
        telegram_thread.start()
        scheduler_thread.start()
        command_worker_thread.start()
        LOG.info("Daemon worker started. Waiting for Telegram commands.")

        while not supervisor_stop_event.is_set():
            time.sleep(config.watchdog_check_sec)
            now_iso = heartbeat_tracker.mark("daemon")
            now_dt = parse_iso(now_iso) or datetime.now(timezone.utc)
            thread_alive = {
                "telegram": telegram_thread.is_alive(),
                "scheduler": scheduler_thread.is_alive(),
                "command_worker": command_worker_thread.is_alive(),
            }
            exit_code, reason = evaluate_watchdog(
                now_dt=now_dt,
                stale_sec=config.watchdog_stale_sec,
                thread_alive=thread_alive,
                heartbeats=heartbeat_tracker.snapshot(),
            )
            if exit_code is not None:
                state_store.patch({"last_watchdog_reason": reason})
                LOG.error("Watchdog requested restart: %s", reason)
                stop_event.set()
                return exit_code

        return 0
    finally:
        stop_event.set()
        if telegram_thread is not None:
            telegram_thread.join(timeout=2.0)
        if scheduler_thread is not None:
            scheduler_thread.join(timeout=2.0)
        if command_worker_thread is not None:
            command_worker_thread.join(timeout=2.0)


def _sleep_with_stop(stop_event: threading.Event, sleep_sec: float) -> None:
    remaining = max(0.0, sleep_sec)
    while remaining > 0 and not stop_event.is_set():
        step = min(0.25, remaining)
        time.sleep(step)
        remaining -= step


def run_daemon(config: Config) -> None:
    lock = ProcessLock(config.daemon_lock_file)
    try:
        lock.acquire()
    except ProcessLockHeldError:
        LOG.warning("Daemon already running (lock held): %s", config.daemon_lock_file)
        raise SystemExit(DAEMON_EXIT_LOCK_HELD)

    supervisor_stop_event = threading.Event()

    def _stop_handler(_signum, _frame):
        supervisor_stop_event.set()

    signal.signal(signal.SIGINT, _stop_handler)
    signal.signal(signal.SIGTERM, _stop_handler)

    restart_attempt = 0
    state_store = StateStore(config.state_file)

    try:
        while not supervisor_stop_event.is_set():
            started_monotonic = time.monotonic()
            try:
                worker_exit_code = _run_daemon_worker(config, lock, supervisor_stop_event)
            except Exception:
                LOG.exception("Unhandled exception in daemon worker")
                worker_exit_code = DAEMON_EXIT_THREAD_DIED
                state_store.patch({"last_watchdog_reason": "worker_exception"})

            run_duration = time.monotonic() - started_monotonic

            if supervisor_stop_event.is_set():
                return

            if worker_exit_code in RECOVERABLE_WORKER_EXIT_CODES:
                if run_duration >= SUPERVISOR_STABLE_WINDOW_SEC:
                    restart_attempt = 0

                sleep_sec = min(
                    config.supervisor_restart_max_sec,
                    config.supervisor_restart_base_sec * (2 ** restart_attempt),
                )
                restart_attempt = min(restart_attempt + 1, 60)
                restart_ts = utc_now_iso()

                def _restart_mutator(state: dict) -> dict:
                    state["daemon_restart_count"] = int(state.get("daemon_restart_count", 0)) + 1
                    state["last_restart_ts"] = restart_ts
                    return state

                state_store.mutate(_restart_mutator)
                LOG.warning(
                    "Recoverable worker exit (%s). Restarting in %.1f seconds.",
                    worker_exit_code,
                    sleep_sec,
                )
                _sleep_with_stop(supervisor_stop_event, sleep_sec)
                continue

            if worker_exit_code != 0:
                raise SystemExit(worker_exit_code)

            return
    finally:
        lock.release()


def run_check_once(config: Config) -> None:
    service = build_service(config)
    result = service.run_check(force=True)
    print(result)


def show_local_status(config: Config) -> None:
    state_store = StateStore(config.state_file)
    state = state_store.load()
    print(json.dumps(state, indent=2, sort_keys=True))


def run_healthcheck(config: Config) -> int:
    state_store = StateStore(config.state_file)
    state = state_store.load()
    now_dt = datetime.now(timezone.utc)
    healthy, reason = evaluate_health_state(
        state=state,
        now_dt=now_dt,
        stale_sec=config.watchdog_stale_sec,
    )
    if healthy:
        print("healthy: daemon heartbeat is fresh")
        return 0
    print(f"unhealthy: {reason}")
    return 1


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="gribu.lv Telegram notifier")
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("daemon", help="Run Telegram listener + adaptive scheduler")
    subparsers.add_parser("check-once", help="Run one immediate check")
    subparsers.add_parser("status-local", help="Print current local state JSON")
    subparsers.add_parser("healthcheck", help="Exit 0 when daemon heartbeats are healthy")
    return parser.parse_args()


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    args = parse_args()
    try:
        config = load_config(".env")
    except ConfigError as exc:
        raise SystemExit(f"Config error: {exc}")

    if args.command == "daemon":
        run_daemon(config)
        return
    if args.command == "check-once":
        run_check_once(config)
        return
    if args.command == "status-local":
        show_local_status(config)
        return
    if args.command == "healthcheck":
        raise SystemExit(run_healthcheck(config))
    raise SystemExit(f"Unknown command: {args.command}")


if __name__ == "__main__":
    main()
