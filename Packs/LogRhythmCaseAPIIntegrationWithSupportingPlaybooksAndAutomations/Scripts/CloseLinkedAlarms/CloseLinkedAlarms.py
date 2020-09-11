import demistomock as demisto
from CommonServerPython import *  # noqa: F401

# Closes all alarms linked to this incident.
# This function takes 3 paramaters
# @param list: a list of alarm Id's associated with this case
# @param inc_id: the id of the incident
# @param close_note: This is the note sent to the logrhythm platform
#
# closes all alarms linked to this XSOAR incident


def main():
    # Parse the arguments from the demisto platform.
    alarm_ids = demisto.args()['list']
    inc_id = demisto.args()['inc_id']
    close_notes = demisto.args()['close_notes']

    # create the closure note to be sent to the alarms on the logrhythm siem platform
    note = "XSOAR Incident " + inc_id + "-- Closed by NTT SOC:" + close_notes

    # iterate and closoe all of the associated alarms with the composed note
    for alarm in alarm_ids:
        demisto.executeCommand('lr-update-alarm-status', {"alarm-id": alarm, "status": "Closed", "comments": note})


main()
