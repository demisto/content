"""Deprecated pre-processing script, superseded by GIBTIIncidentUpdate: updates the open incidents with the incoming
GIB ID and drops the incoming incident once one was updated."""

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

from typing import Any


# The built-in incident attributes carried from the incoming record onto its
# duplicate; every other attribute (`status`, `owner`, `severity`, `type`,
# `playbookId`, `created`, `investigationId`, `rawJSON`, `dbotMirrorId`,
# `sourceBrand`, `labels`) stays the target incident's own. The record's own
# data travels separately, as the flattened `CustomFields`.
_PROPAGATED_INCIDENT_KEYS: tuple[str, ...] = ("name", "occurred", "details")
_ENTRY_TYPE_ERROR: int = 4
QUERY_SUFFIX = " and -status:closed"


def _escape_lucene_phrase(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"')


def build_update_fields(incident: dict[str, Any]) -> dict[str, Any]:
    """Flattened CustomFields plus name/occurred/details without None or empty values: an empty `details` never wipes the
    duplicate's."""
    base: dict[str, Any] = {key: incident.get(key) for key in _PROPAGATED_INCIDENT_KEYS}
    custom_fields = incident.get("CustomFields") or {}
    if isinstance(custom_fields, dict):
        base.update({k: v for k, v in custom_fields.items() if k != "id"})
    return {k: v for k, v in base.items() if v not in (None, "", [], {})}


def _gibid(incident: dict[str, Any]) -> str | None:
    custom_fields = incident.get("CustomFields") or {}
    value = custom_fields.get("gibid") if isinstance(custom_fields, dict) else None
    value = value or incident.get("gibid")
    text = str(value).strip() if value is not None else ""
    return text or None


def _try_set_incident(incident_id: str, fields: dict[str, Any]) -> bool:
    result = demisto.executeCommand("setIncident", {"id": incident_id, **fields})
    if isinstance(result, list) and result and isinstance(result[0], dict) and result[0].get("Type") == _ENTRY_TYPE_ERROR:
        demisto.debug(f"[GIB-dedup] setIncident failed for {incident_id}: {result[0].get('Contents')!r}")
        return False
    return True


def _set_incident(incident_id: str, fields: dict[str, Any]) -> bool:
    """setIncident on one duplicate; when it rejects the full update, for example over a grid field value, the scalar
    fields are retried alone."""
    if _try_set_incident(incident_id, fields):
        return True
    scalar_fields = {key: value for key, value in fields.items() if not isinstance(value, list | dict)}
    if not scalar_fields or scalar_fields == fields:
        return False
    demisto.debug(f"[GIB-dedup] retrying {incident_id} with the scalar fields alone")
    return _try_set_incident(incident_id, scalar_fields)


def prevent_duplication(current_incident: dict[str, Any]) -> bool:
    """True when the incoming incident should be created, False when an existing
    incident with the same GIB ID was updated instead (or there was nothing to copy)."""
    gibid = _gibid(current_incident)
    if not gibid:
        return True
    query = f'gibid:"{_escape_lucene_phrase(gibid)}"{QUERY_SUFFIX}'
    search = demisto.executeCommand("getIncidents", {"query": query, "sort": "created.desc", "size": 200})
    if not search or not isinstance(search[0], dict) or search[0].get("Type") == _ENTRY_TYPE_ERROR:
        return True
    existing = (search[0].get("Contents") or {}).get("data") or []
    if not existing:
        return True

    update_fields = build_update_fields(current_incident)
    updated = 0
    for duplicate in existing:
        duplicate_id = duplicate.get("id")
        if not duplicate_id:
            continue
        if not update_fields:
            updated += 1
            continue
        if _set_incident(duplicate_id, update_fields):
            updated += 1
    # Keep the incoming incident when every update failed, so the new state is not lost.
    return updated == 0


def main():
    try:
        return_results(prevent_duplication(demisto.incident() or {}))
    except Exception as e:
        return_error(f"GIBIncidentUpdate failed: {e!s}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
