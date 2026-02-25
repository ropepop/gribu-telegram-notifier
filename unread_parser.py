from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterable

from bs4 import BeautifulSoup


class UnreadParseError(Exception):
    pass


@dataclass(frozen=True)
class ParseResult:
    unread_count: int
    source: str
    confidence: float


@dataclass(frozen=True)
class _Candidate:
    unread_count: int
    source: str
    confidence: float
    priority: int


_STRICT_SELECTOR_ATTRS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("[data-header-notification-count]", ("data-count", "data-unread", "data-messages-count")),
    ("[data-unread-count]", ("data-unread", "data-count")),
    ("[data-messages-count]", ("data-messages-count", "data-count")),
    (".header__button-notification_new", ("data-count", "data-unread", "aria-label", "title")),
    (".messages-new", ("data-count", "data-unread", "aria-label", "title")),
    (".messages-count", ("data-count", "data-unread", "aria-label", "title")),
    (".chat-count", ("data-count", "data-unread", "aria-label", "title")),
)

_NEAR_KEYWORD_PATTERN = re.compile(
    r"(?:unread|message|messages|chat|mail|zi[nņ]a|zi[nņ]as|neizlas[a-z]*)"
    r"[^0-9]{0,30}(\d{1,4})",
    flags=re.IGNORECASE,
)

_JSON_COUNT_PATTERNS = [
    re.compile(r'"unread(?:_count|Count)?":\s*(\d{1,4})'),
    re.compile(r'"newMessagesCount":\s*(\d{1,4})'),
    re.compile(r'"messagesUnread":\s*(\d{1,4})'),
]

_LOGIN_EMAIL_PATTERN = re.compile(r"""name\s*=\s*["']login\[email\]["']""", flags=re.IGNORECASE)
_LOGIN_PASSWORD_PATTERN = re.compile(
    r"""name\s*=\s*["']login\[password\]["']""",
    flags=re.IGNORECASE,
)


def _to_ints(text: str) -> list[int]:
    values: list[int] = []
    for match in re.findall(r"\d{1,4}", text):
        number = int(match)
        if 0 <= number <= 9999:
            values.append(number)
    return values


def _first_value(values: Iterable[int]) -> int | None:
    for value in values:
        if 0 <= value <= 9999:
            return value
    return None


def _looks_like_login_form(html: str) -> bool:
    return bool(_LOGIN_EMAIL_PATTERN.search(html) and _LOGIN_PASSWORD_PATTERN.search(html))


def _choose_best(candidates: list[_Candidate]) -> ParseResult | None:
    if not candidates:
        return None
    chosen = max(candidates, key=lambda item: (item.confidence, item.priority))
    return ParseResult(
        unread_count=chosen.unread_count,
        source=chosen.source,
        confidence=chosen.confidence,
    )


def parse_unread_count(html: str) -> ParseResult:
    if _looks_like_login_form(html):
        raise UnreadParseError("Login form detected instead of messages page")

    soup = BeautifulSoup(html, "html.parser")
    candidates: list[_Candidate] = []

    for selector, attrs in _STRICT_SELECTOR_ATTRS:
        for node in soup.select(selector):
            for attr in attrs:
                raw = node.attrs.get(attr)
                if raw:
                    values = _to_ints(str(raw))
                    value = _first_value(values)
                    if value is not None:
                        candidates.append(
                            _Candidate(
                                unread_count=value,
                                source=f"{selector}:{attr}",
                                confidence=0.98,
                                priority=100,
                            )
                        )
            text = node.get_text(" ", strip=True)
            if text:
                values = _to_ints(text)
                value = _first_value(values)
                if value is not None:
                    candidates.append(
                        _Candidate(
                            unread_count=value,
                            source=f"{selector}:text",
                            confidence=0.9,
                            priority=90,
                        )
                    )

    for pattern in _JSON_COUNT_PATTERNS:
        match = pattern.search(html)
        if match:
            candidates.append(
                _Candidate(
                    unread_count=int(match.group(1)),
                    source=f"json:{pattern.pattern}",
                    confidence=0.93,
                    priority=95,
                )
            )

    text_blob = soup.get_text("\n", strip=True)
    near_match = _NEAR_KEYWORD_PATTERN.search(text_blob)
    if near_match:
        candidates.append(
            _Candidate(
                unread_count=int(near_match.group(1)),
                source="keyword-near-match",
                confidence=0.35,
                priority=10,
            )
        )

    result = _choose_best(candidates)
    if result is not None:
        return result

    raise UnreadParseError("Could not parse unread message count from HTML")
