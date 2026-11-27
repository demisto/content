"""Deprecated pre-processing script, superseded by GIBTIIncidentUpdateAllTypes: updates the open incidents with the
incoming GIB ID and drops the incoming incident once one was updated."""

import json
from collections.abc import Iterator
from typing import Any

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


# EntryType.ERROR of CommonServerPython.
_ENTRY_TYPE_ERROR: int = 4

# The built-in incident attributes carried from the incoming record onto its
# duplicate; every other attribute (`status`, `owner`, `severity`, `type`,
# `playbookId`, `created`, `investigationId`, `rawJSON`, `dbotMirrorId`,
# `sourceBrand`, `labels`) stays the target incident's own. The record's own
# data travels separately, as the flattened `CustomFields`.
_PROPAGATED_INCIDENT_KEYS: tuple[str, ...] = ("name", "occurred", "details")

# The largest number of open incidents one pre-processing call reads from getIncidents.
MAX_INCIDENTS: int = 1000

PAGE_SIZE: int = 200


def _normalize(value: Any) -> str | None:
    """Return a stripped non-empty string representation of `value`, else None."""
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def get_gibid(incident: dict) -> str | None:
    """The GIB ID of the incoming incident: its custom field, its top-level field, an id or gibid label, or the rawJSON id."""
    cf = incident.get("CustomFields") or {}
    if isinstance(cf, dict) and cf.get("gibid"):
        return _normalize(cf["gibid"])

    if incident.get("gibid"):
        return _normalize(incident["gibid"])

    for label in incident.get("labels") or []:
        if isinstance(label, dict) and label.get("type") in ("gibid", "id") and label.get("value"):
            return _normalize(label["value"])

    raw = incident.get("rawJSON")
    if isinstance(raw, str) and raw:
        try:
            parsed = json.loads(raw)
            if isinstance(parsed, dict) and parsed.get("id"):
                return _normalize(parsed["id"])
        except Exception:
            # A malformed rawJSON carries no id to read.
            pass

    return None


def _escape_lucene_phrase(value: str) -> str:
    """Escape backslashes and double quotes so any GIB ID forms a valid quoted query phrase."""
    return value.replace("\\", "\\\\").replace('"', '\\"')


def build_update_fields(incident: dict[str, Any]) -> dict[str, Any]:
    """Flattened CustomFields plus name/occurred/details without None or empty values: an empty `details` never wipes the
    duplicate's."""
    base: dict[str, Any] = {key: incident.get(key) for key in _PROPAGATED_INCIDENT_KEYS}

    cf = incident.get("CustomFields") or {}
    if isinstance(cf, dict):
        # `id` names the incident setIncident updates.
        base.update({k: v for k, v in cf.items() if k != "id"})

    return {k: v for k, v in base.items() if v not in (None, "", [], {})}


def iter_existing_incidents(
    gibid: str,
    max_total: int = MAX_INCIDENTS,
    page_size: int = PAGE_SIZE,
) -> Iterator[dict[str, Any]]:
    """Open incidents matching the GIB ID, page by page, at most `max_total`."""
    if max_total <= 0 or page_size <= 0:
        return

    query = f'gibid:"{_escape_lucene_phrase(gibid)}" and -status:closed'
    yielded = 0
    page = 0

    while yielded < max_total:
        res = demisto.executeCommand(
            "getIncidents",
            {"query": query, "sort": "created.desc", "size": page_size, "page": page},
        )
        if not res or (isinstance(res[0], dict) and res[0].get("Type") == _ENTRY_TYPE_ERROR):
            demisto.debug(f"[GIB-dedup] getIncidents error or empty on page={page}: {res!r}")
            return

        data = (res[0].get("Contents") or {}).get("data") or []
        if not data:
            return

        for existing in data:
            yield existing
            yielded += 1
            if yielded >= max_total:
                demisto.debug(f"[GIB-dedup] reached max_total={max_total} for gibid={gibid}; " "remaining duplicates skipped")
                return

        if len(data) < page_size:
            return
        page += 1


def _try_set_incident(incident_id: str, fields: dict[str, Any]) -> bool:
    res = demisto.executeCommand("setIncident", {"id": incident_id, **fields})
    if isinstance(res, list) and res and isinstance(res[0], dict) and res[0].get("Type") == _ENTRY_TYPE_ERROR:
        demisto.debug(f"[GIB-dedup] setIncident failed for {incident_id}: {res[0].get('Contents')!r}")
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


def main() -> None:
    try:
        incident = demisto.incident() or {}

        gibid = get_gibid(incident)
        demisto.debug(f"[GIB-dedup] gibid={gibid}")

        if not gibid:
            return_results(True)
            return

        update_fields = build_update_fields(incident)

        considered = 0
        updated = 0
        for existing in iter_existing_incidents(gibid):
            existing_id = _normalize(existing.get("id"))
            if not existing_id:
                continue
            considered += 1
            if update_fields and _set_incident(existing_id, update_fields):
                updated += 1

        if considered == 0:
            return_results(True)
            return

        demisto.debug(f"[GIB-dedup] updated {updated}/{considered} existing duplicates")
        if update_fields and updated == 0:
            # The record's new state is kept when no duplicate took it.
            return_results(True)
            return
        return_results(False)
    except Exception as exc:  # noqa: BLE001 - top-level XSOAR script handler
        demisto.error(f"[GIB-dedup] failed: {exc}")
        return_error(f"GIBIncidentUpdateAllTypes failed: {exc}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
