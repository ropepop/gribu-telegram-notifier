from pathlib import Path
import threading

from state_store import StateStore
import telegram_control
from telegram_control import TelegramApiError, TelegramCommandCallbacks, TelegramController


class FakeTelegramClient:
    def __init__(self, updates):
        self.updates = updates
        self.sent_messages = []

    def get_updates(self, offset=None, timeout=30):
        if offset is None:
            return self.updates
        return [u for u in self.updates if u["update_id"] >= offset]

    def send_message(self, chat_id, text, reply_markup=None):
        self.sent_messages.append({"chat_id": chat_id, "text": text, "reply_markup": reply_markup})


def _callbacks(calls):
    return TelegramCommandCallbacks(
        on_on=lambda: calls.append("on") or "on-ok",
        on_off=lambda: calls.append("off") or "off-ok",
        on_status=lambda: calls.append("status") or "status-ok",
        on_debug=lambda: calls.append("debug") or "debug-ok",
        on_checknow=lambda: calls.append("checknow") or "checknow-ok",
        on_reauth=lambda: calls.append("reauth") or "reauth-ok",
        on_help=lambda: "help-ok",
    )


def test_unauthorized_chat_is_ignored(tmp_path: Path):
    store = StateStore(tmp_path / "state.json")
    client = FakeTelegramClient(
        updates=[
            {"update_id": 1, "message": {"chat": {"id": 999}, "text": "/on"}},
        ]
    )
    calls = []
    controller = TelegramController(
        client=client,
        state_store=store,
        authorized_chat_id=123,
        callbacks=_callbacks(calls),
    )

    controller.poll_once(timeout=0)
    assert calls == []
    assert client.sent_messages == []
    assert store.load()["telegram_update_offset"] == 2


def test_status_command_from_authorized_chat(tmp_path: Path):
    store = StateStore(tmp_path / "state.json")
    client = FakeTelegramClient(
        updates=[
            {"update_id": 7, "message": {"chat": {"id": 123}, "text": "/status"}},
        ]
    )
    calls = []
    controller = TelegramController(
        client=client,
        state_store=store,
        authorized_chat_id=123,
        callbacks=_callbacks(calls),
    )

    controller.poll_once(timeout=0)
    assert calls == ["status"]
    assert client.sent_messages[0]["chat_id"] == 123
    assert client.sent_messages[0]["text"] == "status-ok"
    assert client.sent_messages[0]["reply_markup"] is not None
    assert store.load()["telegram_update_offset"] == 8


def test_reauth_command_from_authorized_chat(tmp_path: Path):
    store = StateStore(tmp_path / "state.json")
    client = FakeTelegramClient(
        updates=[
            {"update_id": 11, "message": {"chat": {"id": 123}, "text": "/reauth"}},
        ]
    )
    calls = []
    controller = TelegramController(
        client=client,
        state_store=store,
        authorized_chat_id=123,
        callbacks=_callbacks(calls),
    )

    controller.poll_once(timeout=0)
    assert calls == ["reauth"]
    assert client.sent_messages[0]["chat_id"] == 123
    assert client.sent_messages[0]["text"] == "reauth-ok"
    assert store.load()["telegram_update_offset"] == 12


def test_debug_command_from_authorized_chat(tmp_path: Path):
    store = StateStore(tmp_path / "state.json")
    client = FakeTelegramClient(
        updates=[
            {"update_id": 15, "message": {"chat": {"id": 123}, "text": "/debug"}},
        ]
    )
    calls = []
    controller = TelegramController(
        client=client,
        state_store=store,
        authorized_chat_id=123,
        callbacks=_callbacks(calls),
    )

    controller.poll_once(timeout=0)
    assert calls == ["debug"]
    assert client.sent_messages[0]["text"] == "debug-ok"


def test_button_alias_dispatches_as_command(tmp_path: Path):
    store = StateStore(tmp_path / "state.json")
    client = FakeTelegramClient(
        updates=[
            {"update_id": 13, "message": {"chat": {"id": 123}, "text": "Check now"}},
        ]
    )
    calls = []
    controller = TelegramController(
        client=client,
        state_store=store,
        authorized_chat_id=123,
        callbacks=_callbacks(calls),
    )

    controller.poll_once(timeout=0)
    assert calls == ["checknow"]
    assert client.sent_messages[0]["text"] == "checknow-ok"


def test_unknown_text_returns_hint(tmp_path: Path):
    store = StateStore(tmp_path / "state.json")
    client = FakeTelegramClient(
        updates=[
            {"update_id": 14, "message": {"chat": {"id": 123}, "text": "what now?"}},
        ]
    )
    controller = TelegramController(
        client=client,
        state_store=store,
        authorized_chat_id=123,
        callbacks=_callbacks([]),
    )

    controller.poll_once(timeout=0)
    assert "Unknown command" in client.sent_messages[0]["text"]


def test_run_forever_recovers_from_unexpected_exceptions(tmp_path: Path, monkeypatch):
    store = StateStore(tmp_path / "state.json")
    controller = TelegramController(
        client=FakeTelegramClient(updates=[]),
        state_store=store,
        authorized_chat_id=123,
        callbacks=_callbacks([]),
    )
    stop_event = threading.Event()
    loop_calls: list[int] = []
    iteration_calls: list[str] = []
    poll_errors: list[str] = []

    def flaky_poll_once(timeout=30):
        loop_calls.append(timeout)
        if len(loop_calls) == 1:
            raise RuntimeError("boom")
        stop_event.set()

    monkeypatch.setattr(controller, "poll_once", flaky_poll_once)
    monkeypatch.setattr(telegram_control.time, "sleep", lambda _seconds: None)
    controller.run_forever(
        stop_event=stop_event,
        on_iteration=lambda: iteration_calls.append("ok"),
        on_poll_error=lambda exc: poll_errors.append(str(exc)),
    )

    assert len(loop_calls) == 2
    assert iteration_calls == ["ok", "ok"]
    assert poll_errors == ["boom"]


def test_run_forever_reports_telegram_api_errors(tmp_path: Path, monkeypatch):
    store = StateStore(tmp_path / "state.json")
    controller = TelegramController(
        client=FakeTelegramClient(updates=[]),
        state_store=store,
        authorized_chat_id=123,
        callbacks=_callbacks([]),
    )
    stop_event = threading.Event()
    iteration_calls: list[str] = []
    poll_errors: list[str] = []
    calls = 0

    def flaky_poll_once(timeout=30):
        nonlocal calls
        calls += 1
        if calls == 1:
            raise TelegramApiError("network down")
        stop_event.set()

    monkeypatch.setattr(controller, "poll_once", flaky_poll_once)
    monkeypatch.setattr(telegram_control.time, "sleep", lambda _seconds: None)
    controller.run_forever(
        stop_event=stop_event,
        on_iteration=lambda: iteration_calls.append("tick"),
        on_poll_error=lambda exc: poll_errors.append(str(exc)),
    )

    assert iteration_calls == ["tick", "tick"]
    assert poll_errors == ["network down"]
