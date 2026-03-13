import json
import html

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


# Helper for the "[BETA] CrowdStrike Endpoint Alert Layout".
# Renders the raw vendor alert/evidence for a CrowdStrike alert in an HTML table.
# Robust to different XSIAM shapes and field names.

DEBUG_MODE = False  # Set to True to include where the data came from.

CANDIDATE_PATHS = [
    # CustomFields common names
    ("CustomFields", "rawevent"),
    ("CustomFields", "raw_event"),
    ("CustomFields", "rawlog"),
    ("CustomFields", "raw_log"),
    ("CustomFields", "vendor_original_event"),
    ("CustomFields", "original_event"),
    ("CustomFields", "event_raw"),
    ("CustomFields", "original_log"),
    ("CustomFields", "crowdstrike_raw_event"),
    ("CustomFields", "crwd_raw_event"),
    # Top-level fallbacks
    (None, "rawevent"),
    (None, "raw_event"),
    (None, "rawlog"),
    (None, "original_event"),
]


def _maybe_parse_json(value):
    """If value is a JSON-looking string, parse it; otherwise return as-is."""
    if isinstance(value, str):
        stripped = value.strip()
        if (
                (stripped.startswith("{") and stripped.endswith("}"))
                or (stripped.startswith("[") and stripped.endswith("]"))
        ):
            try:
                return json.loads(stripped)
            except Exception:
                return value
    return value


def _to_html_value(value):
    """Render dict/list/primitive safely for HTML."""
    value = _maybe_parse_json(value)

    if isinstance(value, dict):
        parts = [f"<b>{html.escape(str(k))}</b>: {_to_html_value(v)}" for k, v in value.items()]
        return "<br>".join(parts)

    if isinstance(value, list):
        rendered = []
        for item in value:
            if isinstance(item, dict):
                inner = ", ".join(
                    f"{html.escape(str(k))}: {html.escape(str(v))}" for k, v in item.items()
                )
                rendered.append("{" + inner + "}")
            else:
                rendered.append(html.escape(str(item)))
        return ", ".join(rendered)

    if value is None:
        return "<i>none</i>"

    return html.escape(str(value))


def _dict_to_html_table(data, title_left="Field", title_right="Value", note=None):
    """Convert a dictionary into an HTML table."""
    table = (
        "<table style='border-collapse: collapse; width: 100%;'>"
        "<tr style='background-color: #01cc66;'>"
        f"<td style='text-align: center; vertical-align: top; width: 20%;'><b>{html.escape(title_left)}</b></td>"
        f"<td style='text-align: center; width: 80%;'><b>{html.escape(title_right)}</b></td>"
        "</tr>"
    )

    for key, value in data.items():
        key_html = (
            "<span style='text-align: right; display: inline-block; "
            "font-weight: bold; vertical-align: top;'>"
            f"{html.escape(str(key))}:&nbsp;</span>"
        )
        val_html = f"<span style='display: inline-block;'>{_to_html_value(value)}</span>"
        table += (
            "<tr>"
            f"<td style='text-align: right; vertical-align: top;'>{key_html}</td>"
            f"<td>{val_html}</td>"
            "</tr>"
        )

    if note:
        note_html = f"<i>{html.escape(note)}</i>"
        table += f"<tr><td colspan='2' style='padding-top:8px;'>{note_html}</td></tr>"

    table += "</table>"
    return table


def _find_vendor_raw(parsed_alert):
    """
    Try multiple likely locations for the vendor raw blob.

    Returns:
        tuple: (raw_object, where_found) or (None, "not found")
    """
    custom = parsed_alert.get("CustomFields") or {}

    for parent, key in CANDIDATE_PATHS:
        source = custom if parent == "CustomFields" else parsed_alert
        if isinstance(source, dict) and key in source and source.get(key) not in (None, "", {}):
            return source.get(key), f"{parent or 'root'}.{key}"

    for key in ("event", "original_event", "original_log", "vendor_original_event"):
        value = parsed_alert.get(key)
        if value not in (None, "", {}):
            return value, f"root.{key}"

    return None, "not found"


def _parse_alert(alert):
    """
    Parse alert rawJSON if present, otherwise fall back to the alert dict itself.
    """
    raw_json = alert.get("rawJSON")

    if isinstance(raw_json, str):
        try:
            return json.loads(raw_json)
        except Exception:
            return {"rawJSON": raw_json}

    if isinstance(raw_json, dict):
        return raw_json

    return alert


def render_alert_html(alert):
    """
    Build the HTML output entry for the alert.
    """
    parsed = _parse_alert(alert)
    raw_blob, where = _find_vendor_raw(parsed)

    if raw_blob is None:
        note = None
        if DEBUG_MODE:
            note = f"[DEBUG] No vendor raw field found ({where}). Showing parsed alert body."
        html_table = _dict_to_html_table(parsed, note=note)
    else:
        value = _maybe_parse_json(raw_blob)
        note = f"[Source: {where}]" if DEBUG_MODE else None

        if isinstance(value, dict):
            html_table = _dict_to_html_table(value, note=note)
        else:
            html_table = _dict_to_html_table({"raw": value}, note=note)

    return {
        "ContentsFormat": EntryFormat.HTML,
        "Type": EntryType.NOTE,
        "Contents": html_table,
    }


def main():
    try:
        alert = demisto.alert() or {}
        return_results(render_alert_html(alert))

    except Exception as exc:
        error_statement = (
            "There seems to be an issue rendering this field.\n\n"
            "This script pulls data from the vendor raw event in the alert/issue context. "
            "If that key is missing or the alert source doesn't provide vendor raw, nothing specific will display. "
            "Please review the correlation rule, alert mapping, and CrowdStrike dataset."
            f"\n\nException thrown by script: {str(exc)}"
        )
        return_results(error_statement)


if __name__ in ("builtins", "__builtin__", "__main__"):
    main()
