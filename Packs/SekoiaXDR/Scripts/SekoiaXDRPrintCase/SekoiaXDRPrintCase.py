import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def main():
    incident = demisto.incident()
    alert_uuid = incident.get("CustomFields", {}).get("alertuuid")
    readable_output = (
        "### {{color:green}}(There is no case information related to this alert.)"
    )

    try:
        cases = execute_command("sekoia-xdr-get-cases-alert", {"alert_id": alert_uuid})
    except Exception as e:
        return_error(f"Failed to get case information: {str(e)}")

    if cases:
        for case in cases:
            case_title = case["title"]  # type: ignore
            case_description = case["description"]  # type: ignore
            case_id = case["short_id"]  # type: ignore
            case_status = case["status"]  # type: ignore
            case_priority = case["priority"]  # type: ignore
            alerts = [alert["short_id"] for alert in case["alerts"]]  # type: ignore

        readable_output = f"### Case {case_id}:\n|Case title:|Case description:|Case status:\
            |Case priority:|Related Alerts:|\n|---|---|---|---|---|\n| \
            {case_title} | {case_description} | {case_status.capitalize()} | {case_priority.capitalize()} | {', '.join(alerts)}"

    command_results = CommandResults(readable_output=readable_output)
    return_results(command_results)


""" ENTRY POINT """

if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
