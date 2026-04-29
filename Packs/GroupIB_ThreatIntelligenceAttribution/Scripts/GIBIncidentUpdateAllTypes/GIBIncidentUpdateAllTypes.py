"""
GIBIncidentUpdateAllTypes
=========================

Pre-Processing Rule script for Group-IB TI integrations.

For each incoming Group-IB incident the script:

1. Extracts the Group-IB business identifier (`gibid`) from the incoming
   incident in a defensive way (CustomFields -> top-level -> labels -> rawJSON).
2. Streams already-open XSOAR incidents that share the same `gibid` page by
   page, never holding more than one page in memory at a time.
3. Copies all fields from the incoming incident onto every existing duplicate
   via `setIncident` (with the minimal technical guards required for the call
   to be well-formed: see `_RESERVED_UPDATE_KEYS`).
4. Tells XSOAR to drop the incoming incident if at least one real duplicate
   was found, otherwise keeps it.

Memory & blast-radius are bounded by:
    * `PAGE_SIZE`     - upper bound on RAM per `getIncidents` call.
    * `MAX_INCIDENTS` - hard ceiling on how many duplicates one pre-processing
      call is allowed to touch (circuit-breaker against gibid collisions or
      misconfigured queries).
"""

import json
from collections.abc import Iterator
from typing import Any

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


# `EntryType.ERROR` resolves to 4 in the production XSOAR runtime. The local
# `CommonServerPython` stub used by `pytest-in-docker` does not expose
# `EntryType`, so we depend on the numeric literal here. Keep this in sync
# with `EntryType.ERROR` in CommonServerPython.
_ENTRY_TYPE_ERROR: int = 4

# `id` is the target identifier for `setIncident`; if it leaked into the
# update payload, Python's kwargs override would silently redirect the call
# to the incoming incident instead of the duplicate, breaking deduplication.
# `CustomFields` is intentionally flattened into top-level kwargs, so we do
# not pass the container itself a second time.
_RESERVED_UPDATE_KEYS: frozenset[str] = frozenset({"id", "CustomFields"})

# Hard ceiling: how many duplicate incidents one pre-processing call is
# allowed to update. Circuit-breaker for `gibid` collisions or misconfigured
# queries that would otherwise flood the worker with thousands of setIncidents.
MAX_INCIDENTS: int = 1000

# Page size for `getIncidents`. Streaming RAM cost is O(PAGE_SIZE),
# independent of MAX_INCIDENTS.
PAGE_SIZE: int = 200


def _normalize(value: Any) -> str | None:
    """Return a stripped non-empty string representation of `value`, else None."""
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def get_gibid(incident: dict) -> str | None:
    """Extract the Group-IB business identifier from the incoming incident.

    Looked up in priority order: CustomFields.gibid -> top-level gibid ->
    labels[type in {gibid, id}] -> rawJSON.id. Returns None if absent.
    """
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
            # rawJSON may legitimately be missing/malformed; ignore silently.
            pass

    return None


def build_update_fields(incident: dict[str, Any]) -> dict[str, Any]:
    """Build the kwargs payload for `setIncident` on a duplicate.

    Propagates every field from the incoming incident with only two
    technical guards:

    * Keys in `_RESERVED_UPDATE_KEYS` are dropped to keep the `setIncident`
      call well-formed.
    * `None` values are filtered out so a missing field on the incoming
      side never wipes a populated value on the duplicate.
    """
    base: dict[str, Any] = {k: v for k, v in incident.items() if k not in _RESERVED_UPDATE_KEYS}

    cf = incident.get("CustomFields") or {}
    if isinstance(cf, dict):
        # CustomFields are passed as flat named arguments, not as a nested
        # container; only `id` collisions are stripped.
        base.update({k: v for k, v in cf.items() if k != "id"})

    return {k: v for k, v in base.items() if v is not None}


def iter_existing_incidents(
    gibid: str,
    max_total: int = MAX_INCIDENTS,
    page_size: int = PAGE_SIZE,
) -> Iterator[dict[str, Any]]:
    """Stream open XSOAR incidents matching `gibid`, page by page.

    Memory stays at O(page_size) regardless of the total number of duplicates.
    Iteration stops cleanly on: empty page, partial page (no further pages),
    XSOAR error response, or `max_total` reached.
    """
    if max_total <= 0 or page_size <= 0:
        return

    query = f"gibid: {gibid} and -status:Closed"
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


def _set_incident(incident_id: str, fields: dict[str, Any]) -> bool:
    """Invoke `setIncident` for one duplicate; return True on success."""
    res = demisto.executeCommand("setIncident", {"id": incident_id, **fields})
    if isinstance(res, list) and res and isinstance(res[0], dict) and res[0].get("Type") == _ENTRY_TYPE_ERROR:
        demisto.debug(f"[GIB-dedup] setIncident failed for {incident_id}: {res[0].get('Contents')!r}")
        return False
    return True


def main() -> None:
    try:
        incident = demisto.incident() or {}
        if not isinstance(incident, dict):
            raise Exception("Incoming incident is missing from the pre-processing context.")

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
            # No real duplicates -> let XSOAR create the incoming incident.
            return_results(True)
            return

        demisto.debug(f"[GIB-dedup] updated {updated}/{considered} existing duplicates")
        # Real duplicates exist -> drop the incoming incident.
        return_results(False)
    except Exception as exc:  # noqa: BLE001 - top-level XSOAR script handler
        demisto.error(f"[GIB-dedup] failed: {exc}")
        return_error(f"GIBIncidentUpdateAllTypes failed: {exc}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
