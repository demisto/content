import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

"""GLPIIncidentStatus Script for Cortex XSOAR (aka Demisto)"""

from CommonServerUserPython import *

import traceback


COLORS = {
    "1 - New": "#00CD33",  # (success green)
    "2 - Processing (assigned)": "#7995D4",  # (royal blue)
    "3 - Processing (planned)": "#FF9000",  # (warning orange)
    "4 - Pending": "#FF9000",  # (warning orange)
    "5 - Solved": "#FF9000",  # (warning orange)
    "6 - Closed": "#89A5C1",  # (polo)
}

TEXT = {
    "1 - New": "New",
    "2 - Processing (assigned)": "Processing (assigned)",
    "3 - Processing (planned)": "Processing (planned)",
    "4 - Pending": "Pending",
    "5 - Solved": "Solved",
    "6 - Closed": "Closed",
}


""" STANDALONE FUNCTION """


def glpi_incident_status():
    """glpi_incident_status function"""
    incident = demisto.incidents()
    glpi_state = incident[0].get("CustomFields", {}).get("glpistatus")

    try:
        text_color = COLORS[glpi_state]
        text_content = TEXT[glpi_state]
    except Exception as e:
        demisto.debug(f"GLPIIncidentStatus debug - state is: {glpi_state}\n{e}")
        text_color = "#000000"
        text_content = "Pending Update"

    return text_color, text_content


""" COMMAND FUNCTION """


def glpi_incident_status_command():
    """GLPIIncidentStatus command"""

    color, text = glpi_incident_status()
    html = f"<div style='color:{color};text-align:center;'><h2>{text}</h2></div>"

    return demisto.results({"ContentsFormat": formats["html"], "Type": entryTypes["note"], "Contents": html})


""" MAIN FUNCTION """


def main():
    try:
        return_results(glpi_incident_status_command())
    except Exception as ex:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f"Failed to execute GLPIIncidentStatus. Error: {str(ex)}")


""" ENTRY POINT """


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
