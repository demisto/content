import demistomock as demisto
from CommonServerPython import *  # noqa: F401

# takes in two paramaters from the demisto args
# @param alarm_id: A list of alarms associated with this case
# @param case_id: The case ID this alarm is being added to
#
# UpdateLinkedAlarms addes all linked alarms to an associated case


def main():
    alarm_ids = demisto.args()['list']
    case_id = demisto.args()['case_id']
    note = "Added to Case " + case_id + " by NTTS XSOAR."
    for alarm in alarm_ids:
        demisto.executeCommand('lr-update-alarm-status', {"alarm-id": alarm, "status": "Escalated", "comments": note})


main()
