import demistomock as demisto
from CommonServerPython import *  # noqa: E402 lgtm [py/polluting-import]


def _get_incident():
    incidents = demisto.incidents()
    if not incidents:
        raise Exception("No incident found")
    return incidents[0]


def device_security_resolve_alert():
    incident = _get_incident()

    _id = ""
    for label in incident.get("labels", []):
        if label.get("type") == "id":
            _id = label.get("value", "")
            break

    if not _id:
        raise Exception("id was not found in the incident labels")

    args = demisto.args()
    close_reason = args.get("close_reason")

    result = demisto.executeCommand(
        "device-security-resolve-alert",
        {
            "id": _id,
            "reason": f'Resolved by XSOAR incident {incident.get("id", "")}',
            "reason_type": "Issue Mitigated" if close_reason == "Resolved" else "No Action Needed",
        },
    )
    if is_error(result):
        return_error(f"Failed to resolve the alert. Error: {get_error(result)}")


def main():
    try:
        device_security_resolve_alert()
    except Exception as ex:
        return_error(f"Failed to execute device-security-alert-post-processing. Error: {ex!s}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
