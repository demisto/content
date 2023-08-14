import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def main():
    try:
        incid = demisto.args()['id']
        incident = demisto.executeCommand("getIncidents", {"id": incid})[0]["Contents"]["data"][0]
        # Set each incident field
        for key in incident.keys():
            if key != "name" and key != "type":
                demisto.executeCommand("setIncident", {key: incident[key]})
    except Exception as ex:
        demisto.error(traceback.format_exc())
        return_error(f"UnitTestLoadFields: Exception failed to execute. Error: {str(ex)}")


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
