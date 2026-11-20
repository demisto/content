"""Pre-processing script for rules you create: copies a re-sent Group-IB record onto its duplicates, closed ones
included, and drops the incoming incident once one was updated."""

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

import json
from datetime import UTC, datetime
from typing import Any


# The built-in incident attributes carried from the incoming record onto its
# duplicate; every other attribute (`status`, `owner`, `severity`, `type`,
# `playbookId`, `created`, `investigationId`, `rawJSON`, `dbotMirrorId`,
# `sourceBrand`, `labels`) stays the target incident's own. The record's own
# data travels separately, as the flattened `CustomFields`.
_PROPAGATED_INCIDENT_KEYS: tuple[str, ...] = ("name", "occurred", "details")
_ENTRY_TYPE_ERROR: int = 4
QUERY_SUFFIX = ""

# Group-IB's quality flags of a phishing group, by record field and the incident field it maps to. The
# integration passes a flagged record only while its setting "Pass flagged phishing groups to the
# pre-processing rule" is on.
QUALITY_FLAGS: dict[str, str] = {"falsePositive": "gibfalsepositive", "whitelist": "giballowlisted"}


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


def _custom_field(incident: dict[str, Any], name: str) -> Any:
    custom_fields = incident.get("CustomFields") or {}
    return custom_fields.get(name) if isinstance(custom_fields, dict) else None


def _proxy_port(incident: dict[str, Any]) -> str | None:
    """The port of an open proxy's incident; an open proxy address can have several listings, each with its
    port. Port 0 is a value."""
    value = _custom_field(incident, "gibproxyport")
    if isinstance(value, float) and value.is_integer():
        value = int(value)
    text = "" if isinstance(value, bool) or value is None else str(value).strip()
    return text if text.isdigit() else None


def _is_flagged(incident: dict[str, Any]) -> bool:
    """Whether Group-IB flags the record as a false positive or allow-listed, by its incident fields or rawJSON."""
    if any(_custom_field(incident, field) is True for field in QUALITY_FLAGS.values()):
        return True
    raw = incident.get("rawJSON")
    try:
        parsed = json.loads(raw) if isinstance(raw, str) and raw else None
    except ValueError:
        return False
    return isinstance(parsed, dict) and any(parsed.get(flag) is True for flag in QUALITY_FLAGS)


def _upload_time(incident: dict[str, Any]) -> datetime | None:
    """When a breached record entered Group-IB; a credential comes back in one leak with every upload of
    it, each an exposure of its own. A zero timestamp (year 1) means no upload time."""
    text = str(_custom_field(incident, "gibuploadtime") or "").strip()
    try:
        moment = datetime.fromisoformat(text) if text else None
    except ValueError:
        return None
    if moment is None or moment.year <= 1:
        return None
    return moment if moment.tzinfo else moment.replace(tzinfo=UTC)


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
    """True when the incoming incident should be created, False when an existing incident of the same type
    with the same GIB ID was updated instead (or there was nothing to copy) or Group-IB flagged the record."""
    flagged = _is_flagged(current_incident)
    gibid = _gibid(current_incident)
    if not gibid:
        return not flagged
    clauses = [f'gibid:"{_escape_lucene_phrase(gibid)}"']
    incident_type = str(current_incident.get("type") or "").strip()
    if incident_type:
        clauses.append(f'type:"{_escape_lucene_phrase(incident_type)}"')
    # A breached record's GIB ID names the credential, which appears in several leaks: the incident of
    # one leak is never the duplicate of another's.
    leak_name = str(_custom_field(current_incident, "gibleakname") or "").strip()
    if leak_name:
        clauses.append(f'gibleakname:"{_escape_lucene_phrase(leak_name)}"')
    port = _proxy_port(current_incident)
    if port is not None:
        clauses.append(f"gibproxyport:{port}")
    query = " and ".join(clauses) + QUERY_SUFFIX
    search = demisto.executeCommand("getIncidents", {"query": query, "sort": "created.desc", "size": 200})
    if not search or not isinstance(search[0], dict) or search[0].get("Type") == _ENTRY_TYPE_ERROR:
        return not flagged
    upload_time = _upload_time(current_incident)
    # The quoted phrase also finds a longer leak name ("Leak A 2013" for "Leak A").
    existing = [
        incident
        for incident in (search[0].get("Contents") or {}).get("data") or []
        if (not leak_name or str(_custom_field(incident, "gibleakname") or "").strip() == leak_name)
        and (not upload_time or _upload_time(incident) == upload_time)
    ]
    if not existing:
        return not flagged

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
    # Keep the incoming incident when every update failed, so the new state is not lost, unless Group-IB flagged it.
    return updated == 0 and not flagged


def main():
    try:
        return_results(prevent_duplication(demisto.incident() or {}))
    except Exception as e:
        return_error(f"GIBTIIncidentUpdateIncludingClosed failed: {e!s}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
