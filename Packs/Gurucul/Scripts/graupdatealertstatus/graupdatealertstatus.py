import demistomock as demisto
from CommonServerPython import *  # noqa: E402 lgtm [py/polluting-import]


def _get_incident():
    return demisto.incidents()[0]


def close_alert():
    incident = _get_incident()
    close_reason = demisto.args().get("closeReason")
    close_notes = demisto.args().get("closeNotes", "")

    incident_type = "Incident"
    sub_status = "True Positive"

    if close_reason is not None and close_reason == "False Positive":
        incident_type = "Not An Incident"
        sub_status = "False Positive"
    elif close_reason is not None and close_reason == "Other":
        incident_type = "Not An Incident"
        sub_status = "Model Review"

    alert_id = ""
    for label in incident.get("labels", []):
        if label["type"] == "alertId":
            alert_id = label["value"]
            break

    if alert_id == "":
        gra_alert = (incident.get("CustomFields") or {}).get("graalert") or ""
        if gra_alert:
            alert_id = str(gra_alert).split("-")[-1]

    if alert_id == "":
        raise Exception("alertId was not found in the incident labels or graalert field")

    res = demisto.executeCommand("gra-validate-api", {"using": incident["sourceInstance"]})

    if res is not None and res[0]["Contents"] == "Error in service":
        raise Exception("Alert cannot be closed as GRA services are currently unavailable.")

    action_res = demisto.executeCommand(
        "gra-alert-action",
        {
            "action": "closeAlert",
            "alertId": alert_id,
            "alertComment": close_notes,
            "incidentType": incident_type,
            "subStatus": sub_status,
            "using": incident["sourceInstance"],
        },
    )
    if isError(action_res):
        raise Exception(get_error(action_res) or "GRA alert action failed.")


def main():
    try:
        close_alert()
    except Exception as ex:
        return_error(f"Failed to execute graupdatealertstatus. Error: {ex!s}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
