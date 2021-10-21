import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def prevent_duplication(current_incident):
    """
    This script checks if there is an existing incident with the same GIB ID as the incoming incident.
    If so, the script updates the already existing incident with the fields of the incoming incident, and returns False.
    If not, the script returns True.
    """
    result = True
    custom_fields = current_incident.get("CustomFields", {})
    if "CustomFields" in current_incident.keys():
        del current_incident["CustomFields"]
    if "labels" in current_incident.keys():
        del current_incident["labels"]
    if "occurred" in current_incident.keys():
        del current_incident["occurred"]
    if "sla" in current_incident.keys():
        del current_incident["sla"]
    current_incident.update(custom_fields)
    gibid = custom_fields.get('gibid')
    search_incident = demisto.executeCommand("getIncidents", {"query": "gibid: {0}".format(gibid)})
    if search_incident:
        total = int(search_incident[0].get("Contents", {}).get("total", 0))
        if total > 0:
            result = False
            incident_id = search_incident[0].get("Contents", {}).get("data", {})[total - 1].get("id")
            for key, value in current_incident.items():
                demisto.executeCommand('setIncident', {"id": incident_id, key: value})

    return result


def main():
    try:
        return_results(prevent_duplication(demisto.incident()))
    except Exception as e:
        return_error("Error: {0}".format(str(e)))


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
