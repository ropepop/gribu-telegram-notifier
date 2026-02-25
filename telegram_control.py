from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from typing import Any, Callable

import requests

from state_store import StateStore


LOG = logging.getLogger("gribu_notifier")
NAV_BUTTON_ROWS = (
    ("Enable", "Pause"),
    ("Status", "Check now"),
    ("Reauth", "Help"),
)
BUTTON_COMMAND_ALIASES = {
    "enable": "/on",
    "pause": "/off",
    "status": "/status",
    "check now": "/checknow",
    "reauth": "/reauth",
    "help": "/help",
}
UNKNOWN_COMMAND_MESSAGE = "Unknown command. Use the buttons below or send /help."


def build_navigation_reply_markup() -> dict[str, Any]:
    return {
        "keyboard": [list(row) for row in NAV_BUTTON_ROWS],
        "resize_keyboard": True,
        "is_persistent": True,
        "one_time_keyboard": False,
        "input_field_placeholder": "Choose an action",
    }


class TelegramApiError(Exception):
    pass


@dataclass(frozen=True)
class TelegramCommandCallbacks:
    on_on: Callable[[], str]
    on_off: Callable[[], str]
    on_status: Callable[[], str]
    on_debug: Callable[[], str]
    on_checknow: Callable[[], str]
    on_reauth: Callable[[], str]
    on_help: Callable[[], str]


class TelegramClient:
    def __init__(self, token: str, timeout_sec: int = 20, api_base_url: str = "https://api.telegram.org"):
        self.token = token
        self.timeout_sec = timeout_sec
        self.api_base_url = api_base_url.rstrip("/")
        self.session = requests.Session()

    @property
    def _base(self) -> str:
        return f"{self.api_base_url}/bot{self.token}"

    def get_updates(self, offset: int | None, timeout: int = 30) -> list[dict[str, Any]]:
        payload: dict[str, Any] = {
            "timeout": timeout,
            "allowed_updates": ["message"],
        }
        if offset is not None:
            payload["offset"] = offset
        try:
            response = self.session.post(
                f"{self._base}/getUpdates",
                json=payload,
                timeout=self.timeout_sec + timeout,
            )
            response.raise_for_status()
            data = response.json()
        except (requests.RequestException, ValueError) as exc:
            raise TelegramApiError(f"Failed to get updates: {exc}") from exc

        if not data.get("ok"):
            raise TelegramApiError(f"Telegram returned non-ok getUpdates response: {data}")
        return data.get("result", [])

    def send_message(self, chat_id: int, text: str, reply_markup: dict[str, Any] | None = None) -> None:
        payload = {
            "chat_id": chat_id,
            "text": text,
            "disable_web_page_preview": True,
        }
        if reply_markup is not None:
            payload["reply_markup"] = reply_markup
        try:
            response = self.session.post(
                f"{self._base}/sendMessage",
                json=payload,
                timeout=self.timeout_sec,
            )
            response.raise_for_status()
            data = response.json()
        except (requests.RequestException, ValueError) as exc:
            raise TelegramApiError(f"Failed to send message: {exc}") from exc
        if not data.get("ok"):
            raise TelegramApiError(f"Telegram returned non-ok sendMessage response: {data}")


class TelegramController:
    def __init__(
        self,
        client: TelegramClient,
        state_store: StateStore,
        authorized_chat_id: int,
        callbacks: TelegramCommandCallbacks,
        navigation_buttons_enabled: bool = True,
    ):
        self.client = client
        self.state_store = state_store
        self.authorized_chat_id = authorized_chat_id
        self.callbacks = callbacks
        self.navigation_buttons_enabled = navigation_buttons_enabled

    def _reply_markup(self) -> dict[str, Any] | None:
        if not self.navigation_buttons_enabled:
            return None
        return build_navigation_reply_markup()

    def _normalize_command(self, text: str) -> str:
        cleaned = (text or "").strip()
        if not cleaned:
            return ""
        if cleaned.startswith("/"):
            first_token = cleaned.split()[0]
            first_token = first_token.split("@", 1)[0]
            return first_token.lower()
        return BUTTON_COMMAND_ALIASES.get(cleaned.lower(), "")

    def _dispatch(self, command: str) -> str | None:
        if command == "/on":
            return self.callbacks.on_on()
        if command == "/off":
            return self.callbacks.on_off()
        if command == "/status":
            return self.callbacks.on_status()
        if command == "/debug":
            return self.callbacks.on_debug()
        if command == "/checknow":
            return self.callbacks.on_checknow()
        if command == "/reauth":
            return self.callbacks.on_reauth()
        if command == "/help":
            return self.callbacks.on_help()
        return None

    def _record_command_latency(self, latency_ms: int) -> None:
        self.state_store.patch({"last_command_latency_ms": max(0, latency_ms)})

    def _send_response(self, text: str) -> None:
        self.client.send_message(
            chat_id=self.authorized_chat_id,
            text=text,
            reply_markup=self._reply_markup(),
        )

    def poll_once(self, timeout: int = 30) -> None:
        state = self.state_store.load()
        offset = state.get("telegram_update_offset")
        updates = self.client.get_updates(offset=offset, timeout=timeout)
        for update in updates:
            update_id = update.get("update_id")
            message = update.get("message") or {}
            text = message.get("text", "")
            chat_id = message.get("chat", {}).get("id")
            command = self._normalize_command(text)

            is_authorized = isinstance(chat_id, int) and chat_id == self.authorized_chat_id
            if is_authorized:
                if command:
                    started = time.monotonic()
                    response = self._dispatch(command)
                    latency_ms = int((time.monotonic() - started) * 1000)
                    self._record_command_latency(latency_ms)
                    if response:
                        self._send_response(response)
                    else:
                        self._send_response(UNKNOWN_COMMAND_MESSAGE)
                elif isinstance(text, str) and text.strip():
                    self._send_response(UNKNOWN_COMMAND_MESSAGE)

            if isinstance(update_id, int):
                self.state_store.patch({"telegram_update_offset": update_id + 1})

    def run_forever(
        self,
        stop_event,
        on_iteration: Callable[[], None] | None = None,
        on_poll_error: Callable[[Exception], None] | None = None,
    ) -> None:
        while not stop_event.is_set():
            try:
                self.poll_once(timeout=30)
            except TelegramApiError as exc:
                LOG.warning("Telegram polling failed: %s", exc)
                if on_poll_error is not None:
                    on_poll_error(exc)
                time.sleep(2.0)
            except Exception as exc:
                LOG.exception("Unexpected error in Telegram polling loop")
                if on_poll_error is not None:
                    on_poll_error(exc)
                time.sleep(2.0)
            finally:
                if on_iteration is not None:
                    on_iteration()
