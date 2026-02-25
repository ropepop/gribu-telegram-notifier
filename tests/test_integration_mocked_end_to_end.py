import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs

from app import NotifierService
from config import Config
from gribu_auth import GribuAuthenticator
from gribu_client import GribuClient
from state_store import StateStore
from telegram_control import TelegramClient, TelegramCommandCallbacks, TelegramController


class MockState:
    def __init__(self):
        self.updates = [
            {"update_id": 1, "message": {"chat": {"id": 42}, "text": "/on"}},
        ]
        self.sent_messages = []
        self.unread = 2
        self.login_posts = []


def _json_response(handler: BaseHTTPRequestHandler, payload: dict):
    body = json.dumps(payload).encode("utf-8")
    handler.send_response(200)
    handler.send_header("Content-Type", "application/json")
    handler.send_header("Content-Length", str(len(body)))
    handler.end_headers()
    handler.wfile.write(body)


def _html_response(handler: BaseHTTPRequestHandler, html: str):
    body = html.encode("utf-8")
    handler.send_response(200)
    handler.send_header("Content-Type", "text/html; charset=utf-8")
    handler.send_header("Content-Length", str(len(body)))
    handler.end_headers()
    handler.wfile.write(body)


def _make_handler(mock_state: MockState):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, _format, *_args):
            return

        def do_POST(self):  # noqa: N802
            content_length = int(self.headers.get("Content-Length", "0"))
            raw = self.rfile.read(content_length).decode("utf-8") if content_length else "{}"
            if self.path == "/pieslegties":
                payload = parse_qs(raw, keep_blank_values=True)
                mock_state.login_posts.append(payload)
                if payload.get("login[_token]", [""])[0] == "token123":
                    self.send_response(302)
                    self.send_header("Location", "/lv/messages")
                    self.send_header("Set-Cookie", "DATED=abc; Path=/")
                    self.send_header("Set-Cookie", "DATINGSES=def; Path=/")
                    self.end_headers()
                    return
                _html_response(self, "<form><input name='login[_token]' value='token123'></form>")
                return

            payload = json.loads(raw)
            if self.path.endswith("/botTOKEN/getUpdates"):
                offset = payload.get("offset")
                if offset is None:
                    updates = mock_state.updates
                else:
                    updates = [u for u in mock_state.updates if u["update_id"] >= offset]
                _json_response(self, {"ok": True, "result": updates})
                return
            if self.path.endswith("/botTOKEN/sendMessage"):
                mock_state.sent_messages.append(payload)
                _json_response(self, {"ok": True, "result": {"message_id": len(mock_state.sent_messages)}})
                return
            self.send_response(404)
            self.end_headers()

        def do_GET(self):  # noqa: N802
            if self.path == "/lv/messages":
                html = (
                    '<html><body><div data-header-notification-count '
                    f'data-count="{mock_state.unread}"></div></body></html>'
                )
                _html_response(self, html)
                return
            if self.path == "/pieslegties":
                html = (
                    "<html><body><form>"
                    '<input type="hidden" name="login[_token]" value="token123">'
                    '<input type="text" name="login[email]">'
                    '<input type="password" name="login[password]">'
                    "</form></body></html>"
                )
                _html_response(self, html)
                return
            self.send_response(404)
            self.end_headers()

    return Handler


def _make_config(tmp_path: Path, base_url: str) -> Config:
    return Config(
        telegram_bot_token="TOKEN",
        telegram_chat_id=42,
        gribu_base_url=base_url,
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
        telegram_api_base_url=base_url,
        telegram_nav_buttons_enabled=True,
        env_file_path=(tmp_path / ".env"),
        daemon_lock_file=(tmp_path / "daemon.lock"),
        watchdog_check_sec=10,
        watchdog_stale_sec=120,
        supervisor_restart_base_sec=2,
        supervisor_restart_max_sec=30,
        parse_low_confidence_delta_limit=20,
    )


def test_end_to_end_with_mocked_http(tmp_path: Path):
    mock_state = MockState()
    server = ThreadingHTTPServer(("127.0.0.1", 0), _make_handler(mock_state))
    host, port = server.server_address
    base_url = f"http://{host}:{port}"
    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()

    try:
        config = _make_config(tmp_path, base_url)
        store = StateStore(config.state_file)
        gribu = GribuClient(config.gribu_base_url, config.gribu_cookie_header, timeout_sec=5)
        auth = GribuAuthenticator(
            base_url=config.gribu_base_url,
            login_path=config.gribu_login_path,
            session=gribu.session,
            timeout_sec=5,
        )
        telegram = TelegramClient(
            token=config.telegram_bot_token,
            timeout_sec=5,
            api_base_url=config.telegram_api_base_url,
        )
        service = NotifierService(config, store, gribu, auth, telegram)
        assert service.startup_authenticate() is True
        assert "GRIBU_COOKIE_HEADER=DATED=abc; DATINGSES=def" in config.env_file_path.read_text(
            encoding="utf-8"
        )
        callbacks = TelegramCommandCallbacks(
            on_on=service.command_on,
            on_off=service.command_off,
            on_status=service.command_status,
            on_debug=service.command_debug,
            on_checknow=service.command_checknow,
            on_reauth=service.command_reauth,
            on_help=service.command_help,
        )
        controller = TelegramController(
            client=telegram,
            state_store=store,
            authorized_chat_id=config.telegram_chat_id,
            callbacks=callbacks,
        )

        controller.poll_once(timeout=0)
        assert store.load()["enabled"] is True

        first = service.run_check(force=False)
        assert first == "baseline_set:2"

        mock_state.unread = 5
        second = service.run_check(force=False)
        assert second == "notified:2->5"

        sent_texts = [payload["text"] for payload in mock_state.sent_messages]
        assert any("Checks enabled" in text for text in sent_texts)
        assert any("Unread increased: 2 -> 5" in text for text in sent_texts)
        assert any("reply_markup" in payload for payload in mock_state.sent_messages)
        assert len(mock_state.login_posts) == 1
    finally:
        server.shutdown()
        server.server_close()
