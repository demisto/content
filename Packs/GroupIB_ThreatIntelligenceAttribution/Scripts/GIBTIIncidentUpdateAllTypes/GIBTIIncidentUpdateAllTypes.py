"""Pre-processing script of GIB Rule All Types: updates the open duplicates of a re-sent Group-IB record and drops the
incoming incident once one was updated."""

import json
from collections.abc import Iterator
from datetime import UTC, datetime
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

# Group-IB's quality flags of a phishing group, by record field and the
# incident field it maps to. The integration passes a flagged record only
# while its setting "Pass flagged phishing groups to the pre-processing rule"
# is on.
QUALITY_FLAGS: dict[str, str] = {"falsePositive": "gibfalsepositive", "whitelist": "giballowlisted"}


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


def _custom_field(incident: dict, name: str) -> Any:
    cf = incident.get("CustomFields") or {}
    return cf.get(name) if isinstance(cf, dict) else None


def get_leak_name(incident: dict) -> str | None:
    """The leak of a breached-database incident (*GIB Leak Name*), or None.

    A breached record's GIB ID names the credential, and the same credential appears in several
    leaks: the incident of one leak is never the duplicate of another's.
    """
    return _normalize(_custom_field(incident, "gibleakname"))


def get_upload_time(incident: dict) -> datetime | None:
    """When a breached-database record entered Group-IB (*GIB Upload Time*), or None.

    A credential comes back in one leak with every upload of it, each an exposure of its own
    (id, leakName and uploadTime name the record). A zero timestamp (year 1) means no upload time.
    """
    text = _normalize(_custom_field(incident, "gibuploadtime"))
    try:
        moment = datetime.fromisoformat(text) if text else None
    except ValueError:
        return None
    if moment is None or moment.year <= 1:
        return None
    return moment if moment.tzinfo else moment.replace(tzinfo=UTC)


def get_proxy_port(incident: dict) -> str | None:
    """The port of an incoming open-proxy incident (*GIB Proxy Port*), or None.

    An open proxy address can have several listings, each with its port: the incident of one port is
    never the duplicate of another's. Port 0 is a value.
    """
    value = _custom_field(incident, "gibproxyport")
    if isinstance(value, float) and value.is_integer():
        value = int(value)
    text = "" if isinstance(value, bool) else (_normalize(value) or "")
    return text if text.isdigit() else None


def is_flagged(incident: dict) -> bool:
    """Whether Group-IB flags the incoming record as a false positive or allow-listed, by its incident
    fields or its rawJSON."""
    if any(_custom_field(incident, field) is True for field in QUALITY_FLAGS.values()):
        return True
    raw = incident.get("rawJSON")
    try:
        parsed = json.loads(raw) if isinstance(raw, str) and raw else None
    except ValueError:
        return False
    return isinstance(parsed, dict) and any(parsed.get(flag) is True for flag in QUALITY_FLAGS)


def _escape_lucene_phrase(value: str) -> str:
    """Escape backslashes and double quotes so any value forms a valid quoted query phrase."""
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
    leak_name: str | None = None,
    incident_type: str | None = None,
    proxy_port: str | None = None,
) -> Iterator[dict[str, Any]]:
    """Open incidents matching the GIB ID and, when given, the type, leak name and proxy port, page by page, at most
    `max_total`."""
    if max_total <= 0 or page_size <= 0:
        return

    clauses = [f'gibid:"{_escape_lucene_phrase(gibid)}"']
    if incident_type:
        clauses.append(f'type:"{_escape_lucene_phrase(incident_type)}"')
    if leak_name:
        clauses.append(f'gibleakname:"{_escape_lucene_phrase(leak_name)}"')
    if proxy_port is not None:
        clauses.append(f"gibproxyport:{proxy_port}")
    query = " and ".join([*clauses, "-status:closed"])
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
        flagged = is_flagged(incident)
        demisto.debug(f"[GIB-dedup] gibid={gibid} flagged={flagged}")

        if not gibid:
            return_results(not flagged)
            return

        update_fields = build_update_fields(incident)
        leak_name = get_leak_name(incident)
        upload_time = get_upload_time(incident)

        considered = 0
        updated = 0
        existing_incidents = iter_existing_incidents(
            gibid,
            leak_name=leak_name,
            incident_type=_normalize(incident.get("type")),
            proxy_port=get_proxy_port(incident),
        )
        for existing in existing_incidents:
            existing_id = _normalize(existing.get("id"))
            # The quoted phrase also finds a longer leak name ("Leak A 2013" for "Leak A").
            if not existing_id or (leak_name and get_leak_name(existing) != leak_name):
                continue
            if upload_time and get_upload_time(existing) != upload_time:
                continue
            considered += 1
            if update_fields and _set_incident(existing_id, update_fields):
                updated += 1

        if considered == 0:
            return_results(not flagged)
            return

        demisto.debug(f"[GIB-dedup] updated {updated}/{considered} existing duplicates")
        if update_fields and updated == 0:
            # The record's new state is kept when no duplicate took it, unless Group-IB flagged the record.
            return_results(not flagged)
            return
        return_results(False)
    except Exception as exc:  # noqa: BLE001 - top-level XSOAR script handler
        demisto.error(f"[GIB-dedup] failed: {exc}")
        return_error(f"GIBTIIncidentUpdateAllTypes failed: {exc}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
