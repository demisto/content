import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

"""
Sets administrative, operational, informative and change case types to the correct incident type
To be used by post-processing scripts
"""

import traceback


def set_incident_type():
    incident = demisto.incident()

    if "arguscaseservice" in incident["CustomFields"]:  # noqa SIM102
        if incident["CustomFields"]["arguscaseservice"] == "Administrative":
            demisto.executeCommand("setIncident", {"id": incident["id"], "type": "Argus - Administrative"})
            demisto.executeCommand("setIncident", {"id": incident["id"], "rawType": "Argus - Administrative"})
            return "Done"

    if "arguscasetype" in incident["CustomFields"]:
        if incident["CustomFields"]["arguscasetype"].lower() == "informational":
            demisto.executeCommand("setIncident", {"id": incident["id"], "type": "Argus - Informational"})
            demisto.executeCommand("setIncident", {"id": incident["id"], "rawType": "Argus - Informational"})
            return "Done"

        if incident["CustomFields"]["arguscasetype"].lower() == "change":
            demisto.executeCommand("setIncident", {"id": incident["id"], "type": "Argus - Change"})
            demisto.executeCommand("setIncident", {"id": incident["id"], "rawType": "Argus - Change"})
            return "Done"

        if incident["CustomFields"]["arguscasetype"].lower() == "operationalincident":
            demisto.executeCommand("setIncident", {"id": incident["id"], "type": "Argus - Operational"})
            demisto.executeCommand("setIncident", {"id": incident["id"], "rawType": "Argus - Operational"})
            return "Done"

    return "Incident type not found"


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
