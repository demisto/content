import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def prevent_duplication(current_incident):
    """
    This script checks if there is an existing incident with the same GIBDRP ID as the incoming incident.
    If so, the script updates the already existing incident with the fields of the incoming incident, and returns False.
    If not, the script returns True.
    """
    result = True
    custom_fields = current_incident.get("CustomFields", {})
    if "CustomFields" in current_incident:
        del current_incident["CustomFields"]
    if "labels" in current_incident:
        del current_incident["labels"]
    if "occurred" in current_incident:
        del current_incident["occurred"]
    if "sla" in current_incident:
        del current_incident["sla"]
    current_incident.update(custom_fields)
    gibdrpid = custom_fields.get('gibdrpid')
    search_incident = demisto.executeCommand("getIncidents", {"query": f"gibdrpid: {gibdrpid}"})
    if search_incident:
        total = int(search_incident[0].get("Contents", {}).get("total", 0))
        if total > 0:
            result = False
            incident_id = search_incident[0].get("Contents", {}).get("data", {})[total - 1].get("id")
            incident_gibdrpid = search_incident[0].get("Contents", {}).get("data", {})[total - 1].get("gibdrpid")
            for key, value in current_incident.items():
                demisto.debug(
                    f"Update incident key: {key} value: {value}"
                    f"DataUpdate incident id: {incident_id} incident_gibdrpid: {incident_gibdrpid}"
                )
                demisto.executeCommand('setIncident', {"id": incident_id, key: value})
            demisto.debug(f"Update incident id: {incident_id} incident_gibdrpid: {incident_gibdrpid}")

    return result


def main():
    try:
        return_results(prevent_duplication(demisto.incident()))
    except Exception as e:
        return_error(f"Error: {str(e)}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
