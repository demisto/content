import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def create_case_object(cases):
    return [
        {
            "title": case_item["title"],
            "description": case_item["description"],
            "status": case_item["status"].capitalize(),
            "priority": case_item["priority"].capitalize(),
            "related alerts": ", ".join(
                [alert["short_id"] for alert in case_item["alerts"]]
            ),
        }
        for case_item in cases
    ]


def get_case_info(alert_uuid: str):
    readable_output = ""
    try:
        cases = execute_command("sekoia-xdr-get-cases-alert", {"alert_id": alert_uuid})
    except Exception as e:
        return_error(f"Failed to get case information: {str(e)}")

    if cases:
        readable_cases = create_case_object(cases)
        headers = ["title", "description", "status", "priority", "related alerts"]
        readable_output = tableToMarkdown(
            "Cases information:", readable_cases, headers=headers
        )
    else:
        readable_output = (
            "### {{color:green}}(There is no case information related to this alert.)"
        )

    return readable_output


def main():
    incident = demisto.incident()
    alert_uuid = incident.get("CustomFields", {}).get("alertid")

    readable_output = get_case_info(alert_uuid)

    command_results = CommandResults(readable_output=readable_output)
    return_results(command_results)


""" ENTRY POINT """

if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
