from gribu_client import GribuResponse, looks_like_session_expired


def test_meta_refresh_to_login_is_detected_as_expired():
    html = (
        "<html><head>"
        "<meta http-equiv=\"refresh\" content=\"0;url='/pieslegties'\">"
        "</head><body></body></html>"
    )
    response = GribuResponse(status_code=200, url="https://www.gribu.lv/lv/messages", text=html)
    assert looks_like_session_expired(response) is True


def test_generic_sign_in_text_is_not_enough_to_mark_expired():
    html = "<html><body><h1>Sign in to newsletter</h1></body></html>"
    response = GribuResponse(status_code=200, url="https://www.gribu.lv/lv/messages", text=html)
    assert looks_like_session_expired(response) is False


def test_login_form_fields_are_detected_as_expired():
    html = (
        "<html><body><form>"
        "<input name=\"login[email]\">"
        "<input name=\"login[password]\" type=\"password\">"
        "</form></body></html>"
    )
    response = GribuResponse(status_code=200, url="https://www.gribu.lv/lv/messages", text=html)
    assert looks_like_session_expired(response) is True
