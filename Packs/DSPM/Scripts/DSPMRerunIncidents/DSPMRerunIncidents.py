import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import json

from datetime import datetime

INCIDENT_LIST = "INCIDENT_LIST2"


def timeDifferenceInHours(given_timestamp, rerun_time):
    """
    Function will fetch the time difference and
    if the difference is more than 48 hours then
    we will re-open the investigation.
    """
    given_time = datetime.strptime(given_timestamp, "%Y-%m-%d %H:%M:%S.%f")
    current_time = datetime.now()
    difference = current_time - given_time
    hours_difference = difference.total_seconds() / 3600
    if hours_difference >= float(rerun_time):
        return True
    return False


def reopenInvestigation(incidentId):
    """
    Function will re-open the investigation
    and re-reun the same playbook.
    """
    resp = demisto.executeCommand("reopenInvestigation", {"id": incidentId})
    demisto.info(f"Response from reopenInvestigation command:- {resp}")
    if resp[0].get("Contents"):
        rerun = demisto.executeCommand("setPlaybook", {"incidentId": incidentId, "name": ""})
        demisto.info(f"Response from setPlaybook command:- {rerun}")
        if rerun[0].get("Contents") == "done":
            return True
    return False


def reopenIncident(args):
    """
    Function will fetch the incident list and
    get the count of total number of re-opened
    incidents.
    """
    count, status = 0, ""
    incident_ids = []
    rerun_time = args.get("rerun_time")
    incident_list = args.get("incident_list")
    if isinstance(incident_list, dict):
        incidentList = [incident_list]
    else:
        incident_list = "[" + incident_list + "]"
        incidentList = json.loads(incident_list)
    for incident in incidentList:
        differenceInHours = timeDifferenceInHours(incident.get("incident_created"), rerun_time)
        if differenceInHours:
            incident_ids.append(incident.get("incident_id"))
            result = reopenInvestigation(incident.get("incident_id"))
            if result:
                count += 1
    if count == 0:
        status = "No incidents were reopened."
    else:
        status = f"Successfully reopened {count} incidents."
    demisto.info(status)
    return count, status


def main():
    try:
        count, status = reopenIncident(demisto.args())
        reportSummary = {"Total Number of Reopened Incidents": count}
        return_results(
            CommandResults(
                readable_output=tableToMarkdown("Report Summary:", reportSummary, removeNull=True),
                outputs_prefix="dspm",
                outputs=status,
            )
        )
    except Exception as ex:
        demisto.error(traceback.format_exc())
        return_error(str(ex))


if __name__ == "__builtin__" or __name__ == "builtins":
    main()
