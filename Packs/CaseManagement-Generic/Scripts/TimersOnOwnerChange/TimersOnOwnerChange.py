import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


# This script stops the Time to Assignment timer when an Owner is assigned to an Incident, and starts the Remediation
# SLA Timer.

if not demisto.args().get('old') and demisto.args().get('new'):  # If owner was no-one and is now someone:
    demisto.executeCommand("stopTimer", {"timerField": "timetoassignment"})
    demisto.executeCommand("startTimer", {"timerField": "remediationsla"})
    demisto.results(
        "Assignment of the incident was successful, Time to Assignment has been stopped, and the Remediation timer has"
        " been started!")
