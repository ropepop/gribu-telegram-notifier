from pathlib import Path

from state_store import StateStore


def test_default_state_and_on_off_transition(tmp_path: Path):
    path = tmp_path / "state.json"
    store = StateStore(path)

    state = store.load()
    assert state["enabled"] is False
    assert state["paused_reason"] == "manual_off"
    assert state["last_unread"] is None

    state = store.patch({"enabled": True, "paused_reason": "none"})
    assert state["enabled"] is True
    assert state["paused_reason"] == "none"

    state = store.patch({"enabled": False, "paused_reason": "manual_off"})
    assert state["enabled"] is False
    assert state["paused_reason"] == "manual_off"
