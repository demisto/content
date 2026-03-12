import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

incident = demisto.incident() or {}
custom_fields = incident.get("CustomFields") or {}

cypho_ticket_id = custom_fields.get("cyphoticketid")
owner = incident.get("owner")

all_users = demisto.executeCommand("getUsers", {})[0].get("Contents", []) or []
matched_user = next((user for user in all_users if user.get("username") == owner), None)
email = matched_user.get("email") if matched_user else None

old_value = demisto.args().get("old")
new_value = demisto.args().get("new")

if (not old_value) and new_value:
    demisto.executeCommand("pauseTimer", {"timerField": "cyphotimetoassignment"})
    demisto.executeCommand("startTimer", {"timerField": "cyphoremediationsla"})
    return_results(
        "Assignment of the incident was successful. "
        "Time to Assignment has been stopped, and the Remediation timer has been started."
    )

if old_value and (not new_value):
    demisto.executeCommand("pauseTimer", {"timerField": "cyphotimetoassignment"})
    demisto.executeCommand("pauseTimer", {"timerField": "cyphoremediationsla"})
    demisto.executeCommand("startTimer", {"timerField": "cyphotimetoassignment"})
    return_results("Incident has been unassigned, unpausing Time to Assignment, and pausing Remediation timer")
