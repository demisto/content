import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

from html import escape
from typing import Any

# Left-column companion to the Validate results panel: a native-chrome Timeline card showing the
# exposure lead's status history (OPEN / IN_PROGRESS / BLOCKED …) with timestamps. Reads the
# persisted grid field; renders inline-styled HTML only (the entry sanitizer strips
# <style>/<svg>/JavaScript/web fonts), mirroring TenzaiValidationSummary.

BG = "#1a1e23"
LINE = "#262b31"
INK = "#e7ebef"
DIM = "#9aa3ad"
FAINT = "#79828d"
MONO = "ui-monospace,'SF Mono','JetBrains Mono','Cascadia Code',Menlo,Consolas,monospace"
SANS = "'Helvetica Neue',Helvetica,Arial,system-ui,-apple-system,sans-serif"

# Timeline status -> dot color: grey opening, blue in-progress, red terminal-blocked/exploited.
_STATUS_DOT = {
    "OPEN": "#79828d",
    "IN_PROGRESS": "#4aa8d8",
    "PAUSED": "#4aa8d8",
    "BLOCKED": "#f2607b",
    "MATERIALIZED": "#f2607b",
    "INVALIDATED": "#79828d",
}


def _as_rows(value: Any) -> list:
    """Normalize a grid field value to a list of row dicts (or a lone dict / empty)."""
    if isinstance(value, list):
        return [row for row in value if isinstance(row, dict)]
    if isinstance(value, dict):
        return [value]
    return []


def _card(label: str, count_html: str, body: str) -> str:
    """A titled, bordered native-chrome card (label + optional count, then rows)."""
    header = (
        f'<div style="display:flex;justify-content:space-between;align-items:center;padding:13px 16px;">'
        f'<span style="font-family:{MONO};font-size:11px;letter-spacing:.18em;text-transform:uppercase;'
        f'color:{FAINT};">{label}</span>{count_html}</div>'
    )
    return (
        f'<div style="border:1px solid {LINE};border-radius:6px;background:{BG};overflow:hidden;'
        f'margin-bottom:14px;">{header}{body}</div>'
    )


def _row(left_html: str, right_html: str, lead_html: str = "") -> str:
    return (
        f'<div style="display:flex;align-items:center;gap:12px;padding:11px 16px;'
        f'border-top:1px solid {LINE};">{lead_html}{left_html}{right_html}</div>'
    )


def _timeline_card(rows: list) -> str:
    if not rows:
        return ""
    items = []
    for row in rows:
        status = str(row.get("status") or "").strip()
        time = str(row.get("time") or "").strip()
        dot = _STATUS_DOT.get(status.upper(), FAINT)
        lead = (
            f'<span style="width:9px;height:9px;border-radius:50%;background:{dot};flex:0 0 auto;'
            f'display:inline-block;"></span>'
        )
        left = f'<span style="font-family:{SANS};font-size:13.5px;color:{INK};flex:1;">{escape(status)}</span>'
        right = f'<span style="font-family:{MONO};font-size:12.5px;color:{DIM};">{escape(time)}</span>'
        items.append(_row(left, right, lead))
    return _card("Timeline", "", "".join(items))


def build_sidebar_html(fields: dict) -> str:
    """Render the exposure Timeline card, or a subtle placeholder when there is no data yet."""
    body = _timeline_card(_as_rows(fields.get("tenzaitimeline")))
    if not body:
        body = (
            f'<div style="font-family:{MONO};font-size:12px;letter-spacing:.04em;color:{FAINT};'
            f'padding:14px 2px;">No exposure timeline yet.</div>'
        )
    return f'<div style="font-family:{SANS};color:{INK};">{body}</div>'


def main():
    try:
        incident = demisto.incident() or {}
        fields = incident.get("CustomFields") or {}
        return_results({"ContentsFormat": EntryFormat.HTML, "Type": EntryType.NOTE, "Contents": build_sidebar_html(fields)})
    except Exception as ex:
        return_error(f"Failed to execute TenzaiExposureSidebar. Error: {ex!s}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
