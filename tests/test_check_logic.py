from pathlib import Path

from app import NotifierService
from config import Config
from gribu_auth import GribuAuthError
from gribu_client import GribuResponse
from state_store import StateStore


class FakeGribuClient:
    def __init__(self, responses):
        self.responses = list(responses)
        self.cookie_header = "DATED=1; DATINGSES=1"

    def fetch_check_page(self, _check_url):
        if not self.responses:
            raise AssertionError("No fake responses left")
        return self.responses.pop(0)

    def export_cookie_header(self):
        return self.cookie_header


class FakeGribuAuthenticator:
    def __init__(self, outcomes=None):
        self.outcomes = list(outcomes or [])
        self.calls = []

    def authenticate(self, login_id, login_password):
        self.calls.append((login_id, login_password))
        if not self.outcomes:
            return
        outcome = self.outcomes.pop(0)
        if isinstance(outcome, Exception):
            raise outcome


class FakeTelegramClient:
    def __init__(self):
        self.sent = []

    def send_message(self, chat_id, text, reply_markup=None):
        self.sent.append({"chat_id": chat_id, "text": text, "reply_markup": reply_markup})


def _make_config(tmp_path: Path) -> Config:
    return Config(
        telegram_bot_token="token",
        telegram_chat_id=111,
        gribu_base_url="https://www.gribu.lv",
        gribu_check_url="/lv/messages",
        gribu_login_id="demo@example.com",
        gribu_login_password="secret",
        gribu_login_path="/pieslegties",
        gribu_cookie_header="a=b",
        check_interval_sec=60,
        check_interval_fast_sec=20,
        check_interval_idle_sec=60,
        check_interval_error_backoff_max_sec=180,
        state_file=(tmp_path / "state.json"),
        http_timeout_sec=10,
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


def _message_html(count: int) -> str:
    return f'<div data-header-notification-count data-count="{count}"></div>'


def _keyword_message_html(count: int) -> str:
    return f"<html><body><p>Unread messages: {count}</p></body></html>"


def test_first_check_sets_baseline_without_alert(tmp_path: Path):
    config = _make_config(tmp_path)
    store = StateStore(config.state_file)
    gribu = FakeGribuClient(
        [
            GribuResponse(status_code=200, url="https://www.gribu.lv/lv/messages", text=_message_html(2)),
        ]
    )
    telegram = FakeTelegramClient()
    auth = FakeGribuAuthenticator()
    service = NotifierService(config, store, gribu, auth, telegram)

    result = service.run_check(force=True)
    state = store.load()
    assert result == "baseline_set:2"
    assert state["last_unread"] == 2
    assert state["last_success_ts"] is not None
    assert telegram.sent == []


def test_increase_triggers_alert(tmp_path: Path):
    config = _make_config(tmp_path)
    store = StateStore(config.state_file)
    store.patch({"enabled": True, "paused_reason": "none", "last_unread": 2})
    gribu = FakeGribuClient(
        [
            GribuResponse(status_code=200, url="https://www.gribu.lv/lv/messages", text=_message_html(5)),
        ]
    )
    telegram = FakeTelegramClient()
    auth = FakeGribuAuthenticator()
    service = NotifierService(config, store, gribu, auth, telegram)

    result = service.run_check(force=False)
    assert result == "notified:2->5"
    assert len(telegram.sent) == 1
    assert "Unread increased: 2 -> 5" in telegram.sent[0]["text"]


def test_decrease_does_not_trigger_alert(tmp_path: Path):
    config = _make_config(tmp_path)
    store = StateStore(config.state_file)
    store.patch({"enabled": True, "paused_reason": "none", "last_unread": 5})
    gribu = FakeGribuClient(
        [
            GribuResponse(status_code=200, url="https://www.gribu.lv/lv/messages", text=_message_html(1)),
        ]
    )
    telegram = FakeTelegramClient()
    auth = FakeGribuAuthenticator()
    service = NotifierService(config, store, gribu, auth, telegram)

    result = service.run_check(force=False)
    assert result == "no_change:5->1"
    assert telegram.sent == []
    assert store.load()["last_unread"] == 1


def test_session_expiry_triggers_auto_reauth_and_recovers(tmp_path: Path):
    config = _make_config(tmp_path)
    store = StateStore(config.state_file)
    store.patch({"enabled": True, "paused_reason": "none"})
    login_like_html = '<form data-login-form><input type="password" name="login"></form>'
    gribu = FakeGribuClient(
        [
            GribuResponse(status_code=200, url="https://www.gribu.lv/login", text=login_like_html),
            GribuResponse(status_code=200, url="https://www.gribu.lv/lv/messages", text=_message_html(3)),
        ]
    )
    telegram = FakeTelegramClient()
    auth = FakeGribuAuthenticator(outcomes=[None])
    service = NotifierService(config, store, gribu, auth, telegram)

    result = service.run_check(force=False)
    state = store.load()
    assert result == "baseline_set:3"
    assert state["enabled"] is True
    assert state["paused_reason"] == "none"
    assert auth.calls == [("demo@example.com", "secret")]
    assert telegram.sent == []


def test_session_expiry_alerts_and_pauses_when_reauth_fails(tmp_path: Path):
    config = _make_config(tmp_path)
    store = StateStore(config.state_file)
    store.patch({"enabled": True, "paused_reason": "none"})
    login_like_html = '<form data-login-form><input type="password" name="login"></form>'
    gribu = FakeGribuClient(
        [
            GribuResponse(status_code=200, url="https://www.gribu.lv/login", text=login_like_html),
        ]
    )
    telegram = FakeTelegramClient()
    auth = FakeGribuAuthenticator(outcomes=[GribuAuthError("bad credentials")])
    service = NotifierService(config, store, gribu, auth, telegram)

    result = service.run_check(force=False)
    state = store.load()
    assert result == "session_expired"
    assert state["enabled"] is False
    assert state["paused_reason"] == "session_expired"
    assert len(telegram.sent) == 1
    assert "session appears expired" in telegram.sent[0]["text"]


def test_command_reauth_resumes_paused_checks(tmp_path: Path):
    config = _make_config(tmp_path)
    store = StateStore(config.state_file)
    store.patch({"enabled": False, "paused_reason": "session_expired"})
    gribu = FakeGribuClient([])
    telegram = FakeTelegramClient()
    auth = FakeGribuAuthenticator(outcomes=[None])
    service = NotifierService(config, store, gribu, auth, telegram)

    result = service.command_reauth()
    state = store.load()
    assert result == "Reauth successful. Checks resumed."
    assert state["enabled"] is True
    assert state["paused_reason"] == "none"


def test_low_confidence_large_jump_is_rejected(tmp_path: Path):
    config = _make_config(tmp_path)
    store = StateStore(config.state_file)
    store.patch({"enabled": True, "paused_reason": "none", "last_unread": 2})
    gribu = FakeGribuClient(
        [
            GribuResponse(
                status_code=200,
                url="https://www.gribu.lv/lv/messages",
                text=_keyword_message_html(100),
            ),
        ]
    )
    telegram = FakeTelegramClient()
    auth = FakeGribuAuthenticator()
    service = NotifierService(config, store, gribu, auth, telegram)

    result = service.run_check(force=False)
    state = store.load()
    assert result.startswith("error: Low-confidence parse jump rejected")
    assert state["last_unread"] == 2
    assert state["last_parse_source"] == "keyword-near-match"
    assert state["last_parse_confidence"] < 0.5
