"""Unit tests for the TenzaiExposureSidebar dynamic-section widget."""

from TenzaiExposureSidebar import build_sidebar_html


def test_empty_state_placeholder():
    html = build_sidebar_html({})
    assert "No exposure timeline yet" in html


def test_timeline_card_renders_rows_with_status_and_time():
    fields = {
        "tenzaitimeline": [
            {"status": "OPEN", "time": "08-16 14:53:46"},
            {"status": "IN_PROGRESS", "time": "08-16 14:59:50"},
            {"status": "BLOCKED", "time": "08-16 15:01:10"},
        ]
    }
    html = build_sidebar_html(fields)
    assert ">Timeline<" in html
    assert "OPEN" in html
    assert "IN_PROGRESS" in html
    assert "BLOCKED" in html
    assert "08-16 15:01:10" in html
    assert "#f2607b" in html  # BLOCKED renders the red dot


def test_tolerates_non_list_field():
    html = build_sidebar_html({"tenzaitimeline": "garbage"})
    assert "No exposure timeline yet" in html
