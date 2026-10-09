"""
Combine raw and display severity into one plain-text incident field.

Use this script as a mapper transformer, passing the parent customFields
object through the 'value' argument.

Example:
    Input:  {"severity": "info", "display_severity": "low"}
    Output: "info / low"

Missing or empty severity values are displayed as "N/A".
"""

import demistomock as demisto
from CommonServerPython import *


def main() -> None:
    # Read the source object containing both severity attributes.
    value = demisto.args().get("value")
    if not isinstance(value, dict):
        return_error("CombineSeverity requires the object containing " "severity and display_severity.")

    # Use N/A when either source value is missing or empty.
    raw_severity = value.get("severity") or "N/A"
    display_severity = value.get("display_severity") or "N/A"

    # Return the combined text for the destination incident field.
    return_results(f"{raw_severity} / {display_severity}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
