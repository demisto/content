import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def _coerce_to_dict(raw_value):
    """Return the consolidated_findings payload as a dict.

    The classifier stores the value as a JSON string (Stringify transformer),
    but defensively also handle the case where it already arrived as a dict
    (e.g. older mappings or manual incident edits).
    """
    if not raw_value:
        return {}
    if isinstance(raw_value, dict):
        return raw_value
    if isinstance(raw_value, str):
        try:
            parsed = json.loads(raw_value)
        except (ValueError, TypeError):
            return {}
        return parsed if isinstance(parsed, dict) else {}
    return {}


def _format_value(value) -> str:
    """Format a payload value as a single Markdown-cell-friendly string.

    - Empty / None -> "-"
    - List         -> comma-separated formatted items
    - Dict         -> compact JSON
    - Scalar       -> str(value)
    """
    if value is None or value == "":
        return "-"
    if isinstance(value, list):
        if not value:
            return "-"
        return ", ".join(_format_value(item) for item in value)
    if isinstance(value, dict):
        return json.dumps(value)
    return str(value)


def main():
    incident = demisto.incident()
    if not incident:
        raise ValueError("Error - demisto.incident() expected to return current incident from context but returned None")

    raw_value = demisto.get(incident, "CustomFields.splunkconsolidatedfindings", "")
    payload = _coerce_to_dict(raw_value)
    md_output = tableToMarkdown("Splunk Consolidated Findings", payload, headerTransform=string_to_table_header)
    return CommandResults(readable_output=md_output)


if __name__ in ("__main__", "__builtin__", "builtins"):
    try:
        return_results(main())
    except Exception as e:
        return_error(f"Got an error while rendering Splunk consolidated findings: {e}")
