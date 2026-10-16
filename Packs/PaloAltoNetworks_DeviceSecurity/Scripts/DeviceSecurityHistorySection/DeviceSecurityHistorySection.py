import demistomock as demisto
from CommonServerPython import *

import json
from typing import Any

COLUMNS = [
    ("Timestamp", "timestamp"),
    ("Action", "action"),
    ("Evidence type", "evidence_type"),
    ("User email", "user_email"),
    ("Resolution type", "resolve_type"),
    ("Reopen type", "unresolve_type"),
    ("System event", "system_event"),
    ("Reason", "reason"),
    ("Evidence", "evidence"),
]


def format_cell(value: Any) -> str:
    """Keep structured values and Markdown delimiters within a single cell."""
    if value is None or value == "":
        return "-"
    if isinstance(value, (dict, list, bool)):
        value = json.dumps(value, ensure_ascii=False)
    return str(value).replace("|", r"\|").replace("\r", " ").replace("\n", " ")


def render_history(history: Any) -> str:
    """Render the JSON history field as a dynamic section table."""
    if isinstance(history, str):
        history = json.loads(history) if history.strip() else []
    if history is None or history == []:
        return "No detection or resolution history available."
    if isinstance(history, dict):
        history = [history]
    if not isinstance(history, list) or any(not isinstance(event, dict) for event in history):
        raise ValueError("Reason history must be a JSON object or a list of objects.")
    lines = [
        "| " + " | ".join(label for label, _ in COLUMNS) + " |",
        "| " + " | ".join("---" for _ in COLUMNS) + " |",
    ]
    lines.extend("| " + " | ".join(format_cell(event.get(key)) for _, key in COLUMNS) + " |" for event in history)
    return "\n".join(lines)


def main() -> None:
    try:
        incidents = demisto.incidents()
        custom_fields = (incidents[0].get("CustomFields") or {}) if incidents else {}
        return_results(CommandResults(readable_output=render_history(custom_fields.get("reasonhistory"))))
    except Exception as exc:
        return_error(f"Failed to display detection and resolution history: {exc}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
