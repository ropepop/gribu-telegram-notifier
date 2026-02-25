from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import urljoin
from urllib.parse import urlparse

import requests


class GribuClientError(Exception):
    pass


@dataclass(frozen=True)
class GribuResponse:
    status_code: int
    url: str
    text: str


class GribuClient:
    def __init__(
        self,
        base_url: str,
        cookie_header: str,
        timeout_sec: int = 20,
    ):
        self.base_url = base_url.rstrip("/")
        self.cookie_header = cookie_header.strip()
        self.timeout_sec = timeout_sec
        self.session = requests.Session()
        self.session.headers.update(
            {
                "User-Agent": (
                    "Mozilla/5.0 (Linux; Android 14; Pixel) "
                    "AppleWebKit/537.36 (KHTML, like Gecko) "
                    "Chrome/120.0.0.0 Mobile Safari/537.36"
                ),
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            }
        )
        if self.cookie_header:
            self.set_cookie_header(self.cookie_header)

    def _base_host(self) -> str:
        return (urlparse(self.base_url).hostname or "").lower()

    def set_cookie_header(self, cookie_header: str) -> None:
        self.cookie_header = cookie_header.strip()
        self.session.cookies.clear()
        if not self.cookie_header:
            return

        host = self._base_host()
        for raw_item in self.cookie_header.split(";"):
            item = raw_item.strip()
            if not item or "=" not in item:
                continue
            name, value = item.split("=", 1)
            name = name.strip()
            value = value.strip()
            if not name:
                continue
            if host:
                self.session.cookies.set(name, value, domain=host, path="/")
            else:
                self.session.cookies.set(name, value, path="/")

    def export_cookie_header(self) -> str:
        host = self._base_host()
        cookies: list[tuple[str, str]] = []
        seen: set[str] = set()
        for cookie in self.session.cookies:
            name = (cookie.name or "").strip()
            if not name or name in seen:
                continue
            domain = (cookie.domain or "").lstrip(".").lower()
            if host and domain and domain != host and not host.endswith("." + domain):
                continue
            seen.add(name)
            cookies.append((name, cookie.value))

        cookies.sort(key=lambda item: item[0].lower())
        return "; ".join(f"{name}={value}" for name, value in cookies)

    def fetch_check_page(self, check_url: str) -> GribuResponse:
        target = urljoin(f"{self.base_url}/", check_url.lstrip("/"))
        try:
            response = self.session.get(target, timeout=self.timeout_sec, allow_redirects=True)
        except requests.RequestException as exc:
            raise GribuClientError(f"HTTP request failed: {exc}") from exc
        return GribuResponse(
            status_code=response.status_code,
            url=response.url,
            text=response.text,
        )


def looks_like_session_expired(response: GribuResponse) -> bool:
    if response.status_code in (401, 403):
        return True

    def _is_login_path(path: str) -> bool:
        normalized = (path or "").strip().lower()
        markers = ("/pieslegties", "/login", "/signin", "/sign-in")
        return any(normalized == marker or normalized.startswith(marker + "/") for marker in markers)

    final_path = urlparse(response.url).path.lower()
    if _is_login_path(final_path):
        return True

    body = response.text
    login_email_match = re.search(
        r"""name\s*=\s*["']login\[email\]["']""",
        body,
        flags=re.IGNORECASE,
    )
    login_password_match = re.search(
        r"""name\s*=\s*["']login\[password\]["']""",
        body,
        flags=re.IGNORECASE,
    )
    if login_email_match and login_password_match:
        return True

    redirect_targets: list[str] = []
    redirect_targets.extend(
        match.group(1)
        for match in re.finditer(
            r"""content\s*=\s*["'][^"']*url\s*=\s*['"]?([^"'>\s;]+)""",
            body,
            flags=re.IGNORECASE,
        )
    )
    redirect_targets.extend(
        match.group(1)
        for match in re.finditer(
            r"""<link[^>]+rel\s*=\s*["']canonical["'][^>]+href\s*=\s*["']([^"']+)["']""",
            body,
            flags=re.IGNORECASE,
        )
    )
    for target in redirect_targets:
        target_path = urlparse(target).path.lower()
        if _is_login_path(target_path):
            return True

    return False
