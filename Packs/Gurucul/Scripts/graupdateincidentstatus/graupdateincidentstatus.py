import demistomock as demisto
from CommonServerPython import *  # noqa: E402 lgtm [py/polluting-import]


def _get_incident():
    return demisto.incidents()[0]


def close_incident():
    incident = _get_incident()
    close_reason = demisto.args().get("closeReason")
    close_notes = demisto.args().get("closeNotes", "")
    action = "closeIncident"
    sub_option = "True Incident"

    if close_reason is not None and close_reason == "False Positive":
        action = "modelReviewIncident"
        sub_option = "Tuning Required"
    elif close_reason is not None and close_reason == "Other":
        action = "modelReviewIncident"
        sub_option = "Others"

    incident_id = ""
    for label in incident.get("labels", []):
        if label["type"] == "incidentId":
            incident_id = label["value"]
            break

    if incident_id == "":
        gra_incident = (incident.get("CustomFields") or {}).get("graincident") or ""
        if gra_incident:
            incident_id = str(gra_incident).split("-")[-1]

    if incident_id == "":
        raise Exception("incidentId was not found in the incident labels or graincident field")

    res = demisto.executeCommand("gra-validate-api", {"using": incident["sourceInstance"]})

    if res is not None and res[0]["Contents"] == "Error in service":
        raise Exception("Incident cannot be closed as GRA services are currently unavailable.")

    action_res = demisto.executeCommand(
        "gra-incident-action",
        {
            "action": action,
            "subOption": sub_option,
            "incidentId": incident_id,
            "incidentComment": close_notes,
            "using": incident["sourceInstance"],
        },
    )
    if isError(action_res):
        raise Exception(get_error(action_res) or "GRA incident action failed.")


def main():
    try:
        close_incident()
    except Exception as ex:
        return_error(f"Failed to execute graupdateincidentstatus. Error: {ex!s}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
