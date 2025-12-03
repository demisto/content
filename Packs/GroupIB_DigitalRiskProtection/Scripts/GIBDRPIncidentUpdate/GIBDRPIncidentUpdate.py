import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import json
from typing import Any, Optional


IGNORE_UPDATE_KEYS = {
    "id",
    "investigationId",
}

REMOVE_BEFORE_UPDATE_KEYS = {
    "CustomFields",
    "labels",
    "occurred",
    "sla",
}


def _extract_gibdrp_id(current_incident: dict[str, Any]) -> Optional[str]:
    custom_fields = current_incident.get("CustomFields") or {}
    gibdrpid = custom_fields.get("gibdrpid")
    if gibdrpid:
        demisto.debug(f"GIBDRPIncidentUpdate: extracted gibdrpid from CustomFields: {gibdrpid}")
        return gibdrpid

    top_level = current_incident.get("gibdrpid")
    if top_level:
        demisto.debug(f"GIBDRPIncidentUpdate: extracted gibdrpid from top-level: {top_level}")
        return top_level

    raw_json_str = current_incident.get("rawJSON")
    if isinstance(raw_json_str, str) and raw_json_str:
        try:
            raw_obj = json.loads(raw_json_str)
            raw_id = raw_obj.get("id")
            if raw_id:
                demisto.debug(f"GIBDRPIncidentUpdate: extracted gibdrpid from rawJSON.id: {raw_id}")
                return raw_id
            raw_nested_id = (raw_obj.get("violation") or {}).get("id")
            if raw_nested_id:
                demisto.debug(f"GIBDRPIncidentUpdate: extracted gibdrpid from rawJSON.violation.id: {raw_nested_id}")
                return raw_nested_id
        except Exception as e:
            demisto.debug(f"GIBDRPIncidentUpdate: failed to parse rawJSON: {e!s}")

    mirror_id = current_incident.get("dbotMirrorId")
    if mirror_id:
        demisto.debug(f"GIBDRPIncidentUpdate: extracted gibdrpid from dbotMirrorId: {mirror_id}")
        return mirror_id

    demisto.debug("GIBDRPIncidentUpdate: gibdrpid not found in CustomFields, top-level, rawJSON or dbotMirrorId")
    return None


def _build_update_payload(current_incident: dict[str, Any]) -> dict[str, Any]:
    demisto.debug(f"GIBDRPIncidentUpdate: building update payload, incoming keys: {list(current_incident.keys())}")
    prepared: dict[str, Any] = {}
    base = dict(current_incident)
    custom_fields = base.get("CustomFields") or {}
    removed_keys: list[str] = []
    for key in REMOVE_BEFORE_UPDATE_KEYS:
        if key in base:
            base.pop(key, None)
            removed_keys.append(key)
    if removed_keys:
        demisto.debug(f"GIBDRPIncidentUpdate: removed transient keys before update: {removed_keys}")
    prepared.update(base)
    prepared.update(custom_fields)
    for forbidden in IGNORE_UPDATE_KEYS:
        prepared.pop(forbidden, None)
    demisto.debug(f"GIBDRPIncidentUpdate: prepared payload keys: {list(prepared.keys())}")
    return prepared


def _search_existing_incident_by_gibdrpid(gibdrpid: str) -> Optional[dict[str, Any]]:
    query = f'gibdrpid:"{gibdrpid}"'
    demisto.debug(f"GIBDRPIncidentUpdate: searching for duplicates with query: {query}")
    search_incident = demisto.executeCommand("getIncidents", {"query": query})
    if not search_incident:
        demisto.debug("GIBDRPIncidentUpdate: getIncidents returned empty result")
        return None
    contents = (search_incident[0] or {}).get("Contents") or {}
    total = int(contents.get("total", 0) or 0)
    data = contents.get("data") or []
    demisto.debug(f"GIBDRPIncidentUpdate: search results - total: {total}, items: {len(data) if isinstance(data, list) else 0}")
    if total <= 0 or not isinstance(data, list) or len(data) == 0:
        demisto.debug("GIBDRPIncidentUpdate: no existing incident found")
        return None
    chosen = data[-1]
    demisto.debug(f"GIBDRPIncidentUpdate: chosen existing incident id: {chosen.get('id')}")
    return chosen


def prevent_duplication(current_incident: dict[str, Any]) -> bool:
    demisto.debug(
        "GIBDRPIncidentUpdate: received incident for preprocessing - "
        f"type={current_incident.get('type')}, id={current_incident.get('id')}, "
        f"hasCustomFields={bool(current_incident.get('CustomFields'))}"
    )
    gibdrpid = _extract_gibdrp_id(current_incident)
    if not gibdrpid:
        demisto.debug("GIBDRPIncidentUpdate: gibdrpid not found on incoming incident; allowing creation.")
        return True

    existing = _search_existing_incident_by_gibdrpid(gibdrpid)
    if not existing:
        demisto.debug("GIBDRPIncidentUpdate: no duplicates found, creating new incident.")
        return True

    incident_id = existing.get("id")
    incident_gibdrpid = existing.get("gibdrpid")

    update_payload = _build_update_payload(current_incident)
    demisto.debug(f"GIBDRPIncidentUpdate: applying {len(update_payload)} fields to incident {incident_id}")
    for key, value in update_payload.items():
        demisto.debug(
            f"GIBDRPIncidentUpdate: Update incident key: {key} value: {value} "
            f"DataUpdate incident id: {incident_id} incident_gibdrpid: {incident_gibdrpid}"
        )
        demisto.executeCommand("setIncident", {"id": incident_id, key: value})
    demisto.debug(f"GIBDRPIncidentUpdate: Updated incident id: {incident_id} incident_gibdrpid: {incident_gibdrpid}")
    return False


def main():
    try:
        demisto.debug("GIBDRPIncidentUpdate: main invoked")
        return_results(prevent_duplication(demisto.incident()))
    except Exception as e:
        demisto.debug(f"GIBDRPIncidentUpdate: exception occurred: {e!s}")
        return_error(f"Error: {str(e)}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
