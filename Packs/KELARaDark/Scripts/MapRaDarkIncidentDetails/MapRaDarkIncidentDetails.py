import traceback

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

""" MAIN FUNCTION """


def main():
    try:
        # Map the incident_markdown parsed before to kelaradarkitems field.
        demisto.executeCommand("setIncident", {"kelaradarkdetails": demisto.args().get("itemDetails")["details"]})
    except Exception as ex:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f"Failed to execute CreateIndicators. Error: {ex!s}")


""" ENTRY POINT """


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
