import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

"""
Sets administrative, operational, informative and change case types to the correct incident type
To be used by post-processing scripts
"""

import traceback


def set_incident_type():
    incident = demisto.incident()

    if "arguscaseservice" in incident["CustomFields"]:
        if incident["CustomFields"]["arguscaseservice"] == "Administrative":
            demisto.executeCommand("setIncident", {"id": incident["id"], "type": "Administrative"})
            demisto.executeCommand("setIncident", {"id": incident["id"], "rawType": "Administrative"})
            return "Done"

    if "arguscasetype" in incident["CustomFields"]:
        if (
            incident["CustomFields"]["arguscasetype"].lower() == "informational"
            or incident["CustomFields"]["arguscasetype"].lower() == "change"
        ):
            demisto.executeCommand(
                "setIncident", {"id": incident["id"], "type": incident["CustomFields"]["arguscasetype"].capitalize()}
            )
            demisto.executeCommand(
                "setIncident", {"id": incident["id"], "rawType": incident["CustomFields"]["arguscasetype"].capitalize()}
            )
            return "Done"

        if incident["CustomFields"]["arguscasetype"].lower() == "operationalincident":
            demisto.executeCommand("setIncident", {"id": incident["id"], "type": "Operational"})
            demisto.executeCommand("setIncident", {"id": incident["id"], "rawType": "Operational"})
            return "Done"


""" MAIN FUNCTION """


def main():
    try:
        return_results(set_incident_type())
    except Exception as ex:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f"Failed to execute BaseScript. Error: {str(ex)}")


""" ENTRY POINT """


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
