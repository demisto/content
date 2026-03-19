import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def _log(message: str):
    demisto.debug(message)
    demisto.info(message)
    demisto.error(message)


def _extract_incidents_from_query_result(search_incident) -> list[dict]:
    """
    Parse GetIncidentsByQuery response for different server/script versions.
    Supported formats:
      - Contents is list[dict]
      - Contents is JSON string
      - Contents is dict with "data" key (defensive fallback)
    """
    if not isinstance(search_incident, list) or not search_incident:
        return []

    first_entry = search_incident[0] if isinstance(search_incident[0], dict) else {}
    contents = first_entry.get("Contents")

    if isinstance(contents, list):
        return [item for item in contents if isinstance(item, dict)]

    if isinstance(contents, str):
        try:
            parsed = json.loads(contents)
            return [item for item in parsed if isinstance(item, dict)] if isinstance(parsed, list) else []
        except Exception as e:
            _log(f"[GIBIncidentUpdateAllTypes] Failed to parse Contents JSON string: {e!s}")
            return []

    if isinstance(contents, dict):
        data = contents.get("data", [])
        if isinstance(data, list):
            return [item for item in data if isinstance(item, dict)]

    return []


def prevent_duplication(current_incident):
    """
    This script checks if there is an existing incident with the same GIB ID as the incoming incident.
    If so, the script updates the already existing incident with the fields of the incoming incident, and returns False.
    If not, the script returns True.
    """
    _log("[GIBIncidentUpdateAllTypes] prevent_duplication: started")
    result = True
    custom_fields = current_incident.get("CustomFields", {})
    _log(
        f"[GIBIncidentUpdateAllTypes] Incoming incident keys={list(current_incident.keys())}, "
        f"custom_field_keys={list(custom_fields.keys()) if isinstance(custom_fields, dict) else type(custom_fields)}"
    )

    if "CustomFields" in current_incident:
        _log("[GIBIncidentUpdateAllTypes] Removing 'CustomFields' from incident before update payload")
        del current_incident["CustomFields"]
    if "labels" in current_incident:
        _log("[GIBIncidentUpdateAllTypes] Removing 'labels' from incident before update payload")
        del current_incident["labels"]
    if "occurred" in current_incident:
        _log("[GIBIncidentUpdateAllTypes] Removing 'occurred' from incident before update payload")
        del current_incident["occurred"]
    if "sla" in current_incident:
        _log("[GIBIncidentUpdateAllTypes] Removing 'sla' from incident before update payload")
        del current_incident["sla"]

    current_incident.update(custom_fields)
    _log(f"[GIBIncidentUpdateAllTypes] Payload keys after custom fields merge: {list(current_incident.keys())}")

    gibid = custom_fields.get("gibid") if isinstance(custom_fields, dict) else None
    if not gibid:
        _log("[GIBIncidentUpdateAllTypes] gibid is empty or missing in CustomFields. Incident will be created.")
        return True
    query = f"gibid: {gibid} and -status:Closed"
    _log(f"[GIBIncidentUpdateAllTypes] Searching existing incidents with query: {query}")
    search_incident = demisto.executeCommand("GetIncidentsByQuery", {"query": query, "limit": 200, "outputFormat": "json"})
    _log(
        f"[GIBIncidentUpdateAllTypes] Search command returned type={type(search_incident)}, "
        f"entries={len(search_incident) if isinstance(search_incident, list) else 'n/a'}"
    )

    if search_incident:
        first_entry = search_incident[0] if isinstance(search_incident[0], dict) else {}
        first_type = first_entry.get("Type", "n/a")
        first_brand = first_entry.get("Brand", "n/a")
        _log(f"[GIBIncidentUpdateAllTypes] Search first entry Type={first_type}, " f"Brand={first_brand}")
        incidents_data = _extract_incidents_from_query_result(search_incident)
        total = len(incidents_data)
        _log(f"[GIBIncidentUpdateAllTypes] Search total incidents found: {total}")
        if total > 0:
            result = False
            incident_id = incidents_data[total - 1].get("id")
            _log(f"[GIBIncidentUpdateAllTypes] Existing incident found, id={incident_id}. Updating incident in place.")
            update_args = {"id": incident_id, **current_incident}
            _log(
                f"[GIBIncidentUpdateAllTypes] setIncident payload keys={list(update_args.keys())}, "
                f"fields_count={len(update_args)}"
            )
            update_res = demisto.executeCommand("setIncident", update_args)
            _log(f"[GIBIncidentUpdateAllTypes] setIncident response: {update_res}")
        else:
            _log("[GIBIncidentUpdateAllTypes] No matching incidents found. New incident will be created.")
    else:
        _log("[GIBIncidentUpdateAllTypes] Search returned empty response. New incident will be created.")

    _log(f"[GIBIncidentUpdateAllTypes] prevent_duplication: finished with result={result}")
    return result


def main():
    try:
        _log("[GIBIncidentUpdateAllTypes] main: script started")
        return_results(prevent_duplication(demisto.incident()))
        _log("[GIBIncidentUpdateAllTypes] main: script finished successfully")
    except Exception as e:
        _log(f"[GIBIncidentUpdateAllTypes] main: script failed with error={e!s}")
        return_error(f"Error: {e!s}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
