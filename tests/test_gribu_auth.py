from __future__ import annotations

from dataclasses import dataclass

from requests.cookies import RequestsCookieJar

from gribu_auth import GribuAuthError, GribuAuthenticator, extract_login_token


@dataclass
class _FakeResponse:
    status_code: int
    url: str
    text: str

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            raise RuntimeError(f"HTTP error: {self.status_code}")


class _FakeSession:
    def __init__(self):
        self.cookies = RequestsCookieJar()
        self.last_get = None
        self.last_post = None
        self.get_response = _FakeResponse(
            status_code=200,
            url="https://www.gribu.lv/pieslegties",
            text='<form><input type="hidden" name="login[_token]" value="token-123"></form>',
        )
        self.post_response = _FakeResponse(
            status_code=200,
            url="https://www.gribu.lv/lv/messages",
            text="<html>ok</html>",
        )

    def get(self, url, timeout, allow_redirects):
        self.last_get = {"url": url, "timeout": timeout, "allow_redirects": allow_redirects}
        return self.get_response

    def post(self, url, data, headers, timeout, allow_redirects):
        self.last_post = {
            "url": url,
            "data": data,
            "headers": headers,
            "timeout": timeout,
            "allow_redirects": allow_redirects,
        }
        return self.post_response


def test_extract_login_token_success():
    html = '<form><input type="hidden" name="login[_token]" value="abc123"></form>'
    assert extract_login_token(html) == "abc123"


def test_extract_login_token_missing_raises():
    html = "<form><input type='text' name='login[email]'></form>"
    try:
        extract_login_token(html)
        raise AssertionError("Expected GribuAuthError")
    except GribuAuthError as exc:
        assert "CSRF token" in str(exc)


def test_authenticate_submits_expected_login_payload():
    session = _FakeSession()
    authenticator = GribuAuthenticator(
        base_url="https://www.gribu.lv",
        login_path="/pieslegties",
        session=session,
        timeout_sec=7,
    )

    def _post_with_cookie(url, data, headers, timeout, allow_redirects):
        session.last_post = {
            "url": url,
            "data": data,
            "headers": headers,
            "timeout": timeout,
            "allow_redirects": allow_redirects,
        }
        session.cookies.set("DATED", "abc", domain="www.gribu.lv", path="/")
        session.cookies.set("DATINGSES", "def", domain="www.gribu.lv", path="/")
        return session.post_response

    session.post = _post_with_cookie

    authenticator.authenticate(login_id="demo@example.com", login_password="secret")

    assert session.last_get["url"] == "https://www.gribu.lv/pieslegties"
    assert session.last_post["url"] == "https://www.gribu.lv/pieslegties"
    assert session.last_post["data"]["login[email]"] == "demo@example.com"
    assert session.last_post["data"]["login[password]"] == "secret"
    assert session.last_post["data"]["login[_token]"] == "token-123"
    assert session.last_post["headers"]["Referer"] == "https://www.gribu.lv/pieslegties"


def test_authenticate_raises_when_login_form_still_present():
    session = _FakeSession()
    session.post_response = _FakeResponse(
        status_code=200,
        url="https://www.gribu.lv/pieslegties",
        text=(
            "<html><form>"
            '<input name="login[email]">'
            '<input name="login[password]" type="password">'
            '<input name="login[_token]" value="x">'
            "</form></html>"
        ),
    )
    authenticator = GribuAuthenticator(
        base_url="https://www.gribu.lv",
        login_path="/pieslegties",
        session=session,
        timeout_sec=7,
    )

    try:
        authenticator.authenticate(login_id="demo@example.com", login_password="secret")
        raise AssertionError("Expected GribuAuthError")
    except GribuAuthError as exc:
        assert "still on login form" in str(exc)
