import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
cypho_ticket_id = demisto.incident().get("CustomFields").get("cyphoticketid")
owner = demisto.incident().get("owner")

all_users = demisto.executeCommand("getUsers", {})[0].get("Contents", [])
matched_user = next((user for user in all_users if user.get("username") == owner), None)
email = matched_user.get("email")

if not demisto.args().get('old') and demisto.args().get('new'):
    demisto.executeCommand("pauseTimer", {"timerField": "cyphotimetoassignment"})
    demisto.executeCommand("startTimer", {"timerField": "cyphoremediationsla"})
    return_results(
        "Assignment of the incident was successful, Time to Assignment has been stopped, and the Remediation timer has been started")

if demisto.args().get('old') and not demisto.args().get('new'):
    demisto.executeCommand("pauseTimer", {"timerField": "cyphotimetoassignment"})
    demisto.executeCommand("startTimer", {"timerField": "cyphoremediationsla"})
    return_results("Incident has been unassigned, unpausing Time to Assignment, and pausing Remediation timer")

args = {"ticket_id": cypho_ticket_id, "user_email": email}

demisto.executeCommand("cypho-assign-incident", args)
