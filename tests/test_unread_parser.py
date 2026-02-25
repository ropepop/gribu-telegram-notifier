import pytest

from unread_parser import UnreadParseError, parse_unread_count


def test_parse_from_selector_data_count():
    html = '<div data-header-notification-count data-count="7"></div>'
    result = parse_unread_count(html)
    assert result.unread_count == 7
    assert result.confidence > 0.9


def test_parse_from_keyword_line():
    html = "<html><body><p>Unread messages: 12</p></body></html>"
    result = parse_unread_count(html)
    assert result.unread_count == 12
    assert result.source == "keyword-near-match"
    assert result.confidence < 0.5


def test_parse_from_json_pattern():
    html = '<script>window.boot={"newMessagesCount":3};</script>'
    result = parse_unread_count(html)
    assert result.unread_count == 3
    assert result.source.startswith("json:")
    assert result.confidence > 0.9


def test_parse_prefers_high_confidence_signal_over_keyword_fallback():
    html = (
        "<html><body>"
        "<p>Unread messages: 88</p>"
        '<script>window.boot={"newMessagesCount":3};</script>'
        "</body></html>"
    )
    result = parse_unread_count(html)
    assert result.unread_count == 3
    assert result.source.startswith("json:")


def test_parse_ignores_noisy_small_numbers_when_strict_counter_exists():
    html = (
        "<html><body>"
        "<p>Unread messages: 1</p>"
        "<p>Online: 2</p>"
        '<div data-header-notification-count data-count="31"></div>'
        "</body></html>"
    )
    result = parse_unread_count(html)
    assert result.unread_count == 31
    assert result.source == "[data-header-notification-count]:data-count"


def test_parse_raises_for_login_form_page():
    html = (
        "<html><body><form>"
        '<input type="text" name="login[email]">'
        '<input type="password" name="login[password]">'
        "</form></body></html>"
    )
    with pytest.raises(UnreadParseError):
        parse_unread_count(html)


def test_parse_raises_when_no_count():
    html = "<html><body><h1>No counters here</h1></body></html>"
    with pytest.raises(UnreadParseError):
        parse_unread_count(html)
