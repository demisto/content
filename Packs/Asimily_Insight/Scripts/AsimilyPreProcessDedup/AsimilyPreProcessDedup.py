import demistomock as demisto  # noqa: F401
from CommonServerPython import *


def main():  # pragma: no cover
    try:
        incident = demisto.incidents()[0]
        incident_type = incident.get("type")
        mirror_id = incident.get("dbotMirrorId")

        if not incident_type or not mirror_id:
            return_results(True)  # Keep it if missing either value
            return

        if incident_type not in ["Asimily Anomaly", "Asimily CVE"]:
            return_results(True)
            return

        query = f'dbotMirrorId:"{mirror_id}" and type:"{incident_type}"'
        result = demisto.executeCommand("getIncidents", {"query": query, "size": 1})

        incidents = result[0].get("Contents", {}).get("data", []) if result and isinstance(result, list) else []

        if incidents:
            return_results(False)  # Drop
        else:
            return_results(True)  # Keep
    except Exception as ex:
        return_error(f"Failed to execute AsimilyPreProcessDedup. Error: {str(ex)}")


if __name__ in ("__main__", "__builtin__", "builtins"):  # pragma: no cover
    main()
