from __future__ import annotations

from urllib.parse import urljoin

import requests
from bs4 import BeautifulSoup


class GribuAuthError(Exception):
    pass


def extract_login_token(html: str) -> str:
    soup = BeautifulSoup(html, "html.parser")
    token_input = soup.find("input", attrs={"name": "login[_token]"})
    token_value = ""
    if token_input and token_input.has_attr("value"):
        token_value = str(token_input.get("value", "")).strip()
    if not token_value:
        raise GribuAuthError("Could not find login CSRF token in login page")
    return token_value


def _looks_like_login_form(html: str) -> bool:
    body = html.lower()
    has_email = 'name="login[email]"' in body
    has_password = 'name="login[password]"' in body
    has_token = 'name="login[_token]"' in body
    has_login_page_marker = any(
        marker in body
        for marker in (
            "login-layout",
            "data-form-errors",
            "form__errors",
            "data-check-device",
        )
    )
    return has_email and has_password and (has_token or has_login_page_marker)


class GribuAuthenticator:
    def __init__(self, base_url: str, login_path: str, session: requests.Session, timeout_sec: int = 20):
        self.base_url = base_url.rstrip("/")
        self.login_path = login_path.strip() or "/pieslegties"
        self.timeout_sec = timeout_sec
        self.session = session

    @property
    def login_url(self) -> str:
        return urljoin(f"{self.base_url}/", self.login_path.lstrip("/"))

    def authenticate(self, login_id: str, login_password: str) -> None:
        if not login_id.strip():
            raise GribuAuthError("Login identifier is empty")
        if not login_password:
            raise GribuAuthError("Login password is empty")

        try:
            login_page = self.session.get(self.login_url, timeout=self.timeout_sec, allow_redirects=True)
            login_page.raise_for_status()
        except requests.RequestException as exc:
            raise GribuAuthError(f"Failed to load login page: {exc}") from exc

        token = extract_login_token(login_page.text)
        payload = {
            "login[email]": login_id,
            "login[password]": login_password,
            "login[_token]": token,
        }
        headers = {
            "Referer": login_page.url,
        }

        try:
            response = self.session.post(
                self.login_url,
                data=payload,
                headers=headers,
                timeout=self.timeout_sec,
                allow_redirects=True,
            )
            response.raise_for_status()
        except requests.RequestException as exc:
            raise GribuAuthError(f"Login request failed: {exc}") from exc

        if _looks_like_login_form(response.text):
            body = response.text.lower()
            if any(marker in body for marker in ("captcha", "recaptcha", "2fa", "otp", "verification code")):
                raise GribuAuthError("Login challenge detected (captcha/2FA), automation cannot continue")
            raise GribuAuthError("Login failed: still on login form after submit")

        if not any(cookie.name and cookie.value for cookie in self.session.cookies):
            raise GribuAuthError("Login did not produce a usable session cookie")
