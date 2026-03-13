import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
"""Base Script for Cortex XSIAM
This is an empty script with some basic structure according
to the code conventions.
MAKE SURE YOU REVIEW/REPLACE ALL THE COMMENTS MARKED AS "TODO"
"""

from typing import Dict, Any
import traceback


''' STANDALONE FUNCTION '''


# TODO: REMOVE the following dummy function:
def basescript_dummy(dummy: str) -> Dict[str, str]:
    """Returns a simple python dict with the information provided
    in the input (dummy).
    :type dummy: ``str``
    :param dummy: string to add in the dummy dict that is returned
    :return: dict as {"dummy": dummy}
    :rtype: ``str``
    """

    return {"dummy": dummy}
# TODO: ADD HERE THE FUNCTIONS TO INTERACT WITH YOUR PRODUCT API


''' COMMAND FUNCTION '''


# TODO: REMOVE the following dummy command function
def basescript_dummy_command(args: Dict[str, Any]) -> CommandResults:

    dummy = args.get('dummy', 'example dummy')

    if not dummy:
        raise ValueError('dummy not specified')

    # Call the standalone function and get the raw response
    result = basescript_dummy(dummy)

    return CommandResults(
        outputs_prefix='BaseScript',
        outputs_key_field='',
        outputs=result,
    )
# TODO: ADD additional command functions that translate Cortex XSIAM inputs/outputs


''' MAIN FUNCTION '''


def main():
    try:
        # TODO: replace the invoked command function with yours
        return_results(basescript_dummy_command(demisto.args()))
    except Exception as ex:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute BaseScript. Error: {str(ex)}')


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()


# Helper for the "[BETA] CrowdStrike Endpoint Alert Layout".
# Renders the raw vendor alert/evidence for a CrowdStrike alert in an HTML table.
# Robust to different XSIAM shapes and field names.

import json
import html

DEBUG_MODE = False  # set True to include where the data came from

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
    # Top-level fallbacks (rare)
    (None, "rawevent"),
    (None, "raw_event"),
    (None, "rawlog"),
    (None, "original_event"),
]

def _maybe_parse_json(value):
    """If value is a JSON-looking string, parse it; otherwise return as-is."""
    if isinstance(value, str):
        s = value.strip()
        if (s.startswith("{") and s.endswith("}")) or (s.startswith("[") and s.endswith("]")):
            try:
                return json.loads(s)
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
                inner = ", ".join(f"{html.escape(str(k))}: {html.escape(str(v))}" for k, v in item.items())
                rendered.append("{" + inner + "}")
            else:
                rendered.append(html.escape(str(item)))
        return ", ".join(rendered)

    if value is None:
        return "<i>none</i>"

    return html.escape(str(value))

def _dict_to_html_table(d, title_left="Field", title_right="Value", note=None):
    table = (
        "<table style='border-collapse: collapse; width: 100%;'>"
        "<tr style='background-color: #01cc66;'>"
        f"<td style='text-align: center; vertical-align: top; width: 20%;'><b>{html.escape(title_left)}</b></td>"
        f"<td style='text-align: center; width: 80%;'><b>{html.escape(title_right)}</b></td>"
        "</tr>"
    )
    for key, value in d.items():
        key_html = (
            f"<span style='text-align: right; display: inline-block; font-weight: bold; vertical-align: top;'>"
            f"{html.escape(str(key))}:&nbsp;</span>"
        )
        val_html = f"<span style='display: inline-block;'>{_to_html_value(value)}</span>"
        table += f"<tr><td style='text-align: right; vertical-align: top;'>{key_html}</td><td>{val_html}</td></tr>"
    if note:
        note_html = f"<i>{html.escape(note)}</i>"
        table += f"<tr><td colspan='2' style='padding-top:8px;'>{note_html}</td></tr>"
    table += "</table>"
    return table

def _find_vendor_raw(parsed_alert):
    """
    Try multiple likely locations for the vendor raw blob.
    Returns (raw_object, where_found) or (None, reason)
    """
    # 1) Check CustomFields / top-level candidates
    custom = parsed_alert.get("CustomFields") or {}
    for parent, key in CANDIDATE_PATHS:
        source = custom if parent == "CustomFields" else parsed_alert
        if isinstance(source, dict) and key in source and source.get(key) not in (None, "", {}):
            return source.get(key), f"{parent or 'root'}.{key}"

    # 2) Some tenants put raw under a nested 'event' or 'original' field inside rawJSON
    for key in ("event", "original_event", "original_log", "vendor_original_event"):
        v = parsed_alert.get(key)
        if v not in (None, "", {}):
            return v, f"root.{key}"

    # 3) Not found
    return None, "not found"

def main():
    try:
        # Get the alert (issue) and parse rawJSON to a dict
        alert = demisto.alert() or {}
        raw_json = alert.get("rawJSON")
        if isinstance(raw_json, str):
            try:
                parsed = json.loads(raw_json)
            except Exception:
                # rawJSON is not valid JSON (edge), wrap it as a single field
                parsed = {"rawJSON": raw_json}
        elif isinstance(raw_json, dict):
            parsed = raw_json
        else:
            # Some environments don't set rawJSON; fall back to the alert dict itself
            parsed = alert

        # Try to find the vendor raw blob
        raw_blob, where = _find_vendor_raw(parsed)

        if raw_blob is None:
            # Fall back to the entire parsed alert if nothing else is available
            note = None
            if DEBUG_MODE:
                note = f"[DEBUG] No vendor raw field found ({where}). Showing parsed alert body."
            html_table = _dict_to_html_table(parsed, note=note)
        else:
            # Render just the vendor raw
            # Accept strings (possibly JSON) or dicts/lists
            value = _maybe_parse_json(raw_blob)
            if isinstance(value, dict):
                note = f"[Source: {where}]" if DEBUG_MODE else None
                html_table = _dict_to_html_table(value, note=note)
            else:
                # If it's a string or list, present it under a single field
                display = {"raw": value}
                note = f"[Source: {where}]" if DEBUG_MODE else None
                html_table = _dict_to_html_table(display, note=note)

        return_results({
            'ContentsFormat': EntryFormat.HTML,
            'Type': EntryType.NOTE,
            'Contents': html_table,
        })

    except Exception as e:
        error_statement = (
            "There seems to be an issue rendering this field.\n\n"
            "This script pulls data from the vendor raw event in the alert/issue context. "
            "If that key is missing or the alert source doesn't provide vendor raw, nothing specific will display. "
            "Please review the correlation rule, alert mapping, and CrowdStrike dataset."
            f"\n\nException thrown by script: {str(e)}"
        )
        return_results(error_statement)

if __name__ in ("builtins", "__builtin__", "__main__"):
    main()

