"""
GIBDRPIncidentUpdate
====================

Pre-Processing Rule script for the Group-IB Digital Risk Protection (DRP)
integration.

For each incoming Group-IB DRP violation incident the script:

1. Extracts the Group-IB DRP business identifier (`gibdrpid`) from the
   incoming incident in a defensive way:
   CustomFields -> top-level -> labels -> rawJSON.id ->
   rawJSON.violation.id -> dbotMirrorId.
2. Streams the XSOAR incidents that already carry the same `gibdrpid`
   page by page, never holding more than one page in memory at a time.
3. Copies the violation's fields onto every existing duplicate via a
   single `setIncident` call per duplicate.
4. Closes a duplicate once the work on the violation is over: DRP reports it
   as resolved (`resolved`, spelled `solved` by older API versions) or handed
   to legal (`legal`), which closes as *Resolved*; or DRP found it false
   (`false_status`) or the customer rejected it (`approveState=rejected`),
   which closes as *False Positive*. When the incident asks for it (**GIB DRP
   Expire Indicator On Close**), the indicator created from the violation
   URI is expired with the close.
5. Tells XSOAR to drop the incoming incident if at least one real
   duplicate was found, otherwise keeps it.

The fetch passes every change of a violation it created an incident for
through to this rule, whatever the instance's status and approval filters
say, so the close arrives here as an ordinary update.

Both the search in step 2 and the payload in step 3 are deliberately
narrow, because both used to produce duplicates rather than prevent them:

    * The search covers **closed** incidents as well. Restricted to open
      ones, every violation whose incident had already been closed came
      back as a brand-new incident on its next DRP update.
    * The payload carries the violation's own fields plus a small
      allow-list of built-ins (`_PROPAGATED_INCIDENT_KEYS`). Forwarding
      the whole incoming incident sent `setIncident` arguments it does
      not accept - which failed the call for every duplicate, and a
      duplicate that cannot be updated is deliberately kept, so the
      incoming incident was created after all. It also copied `status`,
      which would have reopened a closed incident.

Memory & blast-radius are bounded by:
    * `PAGE_SIZE`     - upper bound on RAM per `getIncidents` call.
    * `MAX_INCIDENTS` - hard ceiling on how many duplicates one
      pre-processing call is allowed to touch (circuit-breaker against
      gibdrpid collisions or misconfigured queries).
"""

import json
from collections.abc import Iterator
from typing import Any
from urllib.parse import urlsplit

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


# `EntryType.ERROR` resolves to 4 in the production XSOAR runtime. The
# local `CommonServerPython` stub used by `pytest-in-docker` does not
# expose `EntryType`, so we depend on the numeric literal here. Keep
# this in sync with `EntryType.ERROR` in CommonServerPython.
_ENTRY_TYPE_ERROR: int = 4

# `IncidentStatus.DONE` in the production runtime: the `status` value
# `getIncidents` reports for an incident that is already closed.
_INCIDENT_STATUS_CLOSED: int = 2

# The built-in incident attributes worth carrying from the incoming
# violation onto its duplicate. Everything outside this set is either
# XSOAR bookkeeping that belongs to the target incident (`status`,
# `owner`, `phase`, `created`, `investigationId`, ...) or an argument
# `setIncident` does not accept (`rawJSON`, `dbotMirrorId`,
# `sourceBrand`, ...). `severity` is deliberately absent: it is set by
# the instance that created the incident (one instance per severity is
# how violations are graded) and may have been raised by an analyst
# since, and an update arriving through another instance must not undo
# either. The violation's own data travels separately, as the flattened
# `CustomFields`.
_PROPAGATED_INCIDENT_KEYS: tuple[str, ...] = ("name", "occurred", "details")

# `violation.status` values in which DRP considers the violation finished:
# the take-down succeeded (`resolved` on the live API, `solved` in older API
# versions and in the API specification) or the case moved to legal (`legal`).
# Reaching any of them closes the XSOAR incident as Resolved.
RESOLVED_VIOLATION_STATUSES: frozenset[str] = frozenset({"resolved", "solved", "legal"})
CLOSE_REASON: str = "Resolved"

# The other way a violation ends: DRP found it false (`false_status`), or the
# customer rejected it (`approveState` = `rejected`). DRP does nothing more
# with either, so the incident closes as False Positive. Approving does not
# close: the take-down is still ahead.
FALSE_VIOLATION_STATUSES: frozenset[str] = frozenset({"false_status"})
REJECTED_APPROVE_STATE: str = "rejected"
CLOSE_REASON_FALSE_POSITIVE: str = "False Positive"

# Hard ceiling: how many duplicate incidents one pre-processing call is
# allowed to update. Circuit-breaker for `gibdrpid` collisions or
# misconfigured queries that would otherwise flood the worker with
# thousands of setIncidents.
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


def _escape_lucene_phrase(value: str) -> str:
    """Escape characters that would otherwise break a quoted Lucene phrase.

    `gibdrpid` values come from the Group-IB API and are expected to be
    URL-safe hashes, but the script must not break if a future schema
    change introduces special characters.
    """
    text = str(value)
    text = text.replace("\x00", "")
    text = text.replace("\r", " ").replace("\n", " ")
    return text.replace("\\", "\\\\").replace('"', '\\"')


def _raw_json(incident: dict[str, Any]) -> dict[str, Any]:
    """Parse the incoming incident's `rawJSON`, or return an empty dict.

    `rawJSON` may legitimately be missing, already parsed, or malformed.
    """
    raw = incident.get("rawJSON")
    if isinstance(raw, dict):
        return raw
    if isinstance(raw, str) and raw:
        try:
            parsed = json.loads(raw)
        except Exception:
            return {}
        if isinstance(parsed, dict):
            return parsed
    return {}


def get_gibdrpid(incident: dict[str, Any]) -> str | None:
    """Extract the Group-IB DRP business identifier from the incoming incident.

    Looked up in priority order:
      CustomFields.gibdrpid -> top-level gibdrpid ->
      labels[type in {gibdrpid, id}] -> rawJSON.id ->
      rawJSON.violation.id -> dbotMirrorId.

    Returns None if absent.
    """
    cf = incident.get("CustomFields") or {}
    if isinstance(cf, dict) and cf.get("gibdrpid"):
        return _normalize(cf["gibdrpid"])

    if incident.get("gibdrpid"):
        return _normalize(incident["gibdrpid"])

    for label in incident.get("labels") or []:
        if isinstance(label, dict) and label.get("type") in ("gibdrpid", "id") and label.get("value"):
            return _normalize(label["value"])

    raw = _raw_json(incident)
    if raw.get("id"):
        return _normalize(raw["id"])
    violation = raw.get("violation")
    if isinstance(violation, dict) and violation.get("id"):
        return _normalize(violation["id"])

    if incident.get("dbotMirrorId"):
        return _normalize(incident["dbotMirrorId"])

    return None


def get_violation_status(incident: dict[str, Any]) -> str | None:
    """Extract `violation.status` from the incoming incident, lower-cased.

    Mirrors `get_gibdrpid`: the mapped incident field first, then the raw
    payload, so the script still works on an instance with a custom mapper.
    """
    cf = incident.get("CustomFields") or {}
    if isinstance(cf, dict) and cf.get("gibdrpstatus"):
        status = _normalize(cf["gibdrpstatus"])
    elif incident.get("gibdrpstatus"):
        status = _normalize(incident["gibdrpstatus"])
    else:
        raw = _raw_json(incident)
        violation = raw.get("violation")
        status = _normalize(raw.get("violation_status") or (violation.get("status") if isinstance(violation, dict) else None))
    return status.lower() if status else None


def get_approve_state(incident: dict[str, Any]) -> str | None:
    """Extract `violation.approveState` from the incoming incident, lower-cased."""
    cf = incident.get("CustomFields") or {}
    if isinstance(cf, dict) and cf.get("gibdrpapprovestate"):
        state = _normalize(cf["gibdrpapprovestate"])
    elif incident.get("gibdrpapprovestate"):
        state = _normalize(incident["gibdrpapprovestate"])
    else:
        raw = _raw_json(incident)
        violation = raw.get("violation")
        state = _normalize(raw.get("approve_state") or (violation.get("approveState") if isinstance(violation, dict) else None))
    return state.lower() if state else None


def close_reason_for(violation_status: str | None, approve_state: str | None) -> str | None:
    """The close reason the violation's state calls for, or None while the work goes on."""
    if approve_state == REJECTED_APPROVE_STATE or violation_status in FALSE_VIOLATION_STATUSES:
        return CLOSE_REASON_FALSE_POSITIVE
    if violation_status in RESOLVED_VIOLATION_STATUSES:
        return CLOSE_REASON
    return None


def _flag(incident: dict[str, Any], cli_name: str) -> bool:
    cf = incident.get("CustomFields") or {}
    value = cf.get(cli_name) if isinstance(cf, dict) else None
    if value is None:
        value = incident.get(cli_name)
    return str(value).strip().lower() in ("true", "1", "yes") if value is not None else False


def wants_indicator_expired(incoming: dict[str, Any], existing: dict[str, Any]) -> bool:
    """Whether the instance that created the incident, or the one updating it, asked for the expiry."""
    return _flag(incoming, "gibdrpexpireindicatoronclose") or _flag(existing, "gibdrpexpireindicatoronclose")


def violation_uri(incoming: dict[str, Any], existing: dict[str, Any]) -> str | None:
    for incident in (incoming, existing):
        cf = incident.get("CustomFields") or {}
        value = _normalize(cf.get("gibdrpviolationuri")) if isinstance(cf, dict) else None
        if value:
            return value
    return None


def build_update_fields(incident: dict[str, Any]) -> dict[str, Any]:
    """Build the kwargs payload for `setIncident` on a duplicate.

    The payload is the violation's own data - `CustomFields` flattened into
    named arguments, which is how `setIncident` takes custom fields - plus the
    built-ins listed in `_PROPAGATED_INCIDENT_KEYS`.

    `None` values are filtered out so a missing field on the incoming side
    never wipes a populated value on the duplicate.
    """
    base: dict[str, Any] = {key: incident.get(key) for key in _PROPAGATED_INCIDENT_KEYS}

    cf = incident.get("CustomFields") or {}
    if isinstance(cf, dict):
        # `id` is the target identifier of `setIncident`; had it leaked into
        # CustomFields, it would silently redirect the update to the incoming
        # incident instead of the duplicate.
        base.update({k: v for k, v in cf.items() if k != "id"})

    return {k: v for k, v in base.items() if v is not None}


def iter_existing_incidents(
    gibdrpid: str,
    max_total: int = MAX_INCIDENTS,
    page_size: int = PAGE_SIZE,
) -> Iterator[dict[str, Any]]:
    """Stream the XSOAR incidents matching `gibdrpid`, page by page.

    Closed incidents are included on purpose: a violation whose incident was
    already closed must update that incident, not spawn a new one on its next
    DRP update.

    Memory stays at O(page_size) regardless of the total number of
    duplicates. Iteration stops cleanly on: empty page, partial page
    (no further pages), XSOAR error response, or `max_total` reached.
    """
    if max_total <= 0 or page_size <= 0:
        return

    query = f'gibdrpid:"{_escape_lucene_phrase(gibdrpid)}"'
    yielded = 0
    page = 0

    while yielded < max_total:
        res = demisto.executeCommand(
            "getIncidents",
            {"query": query, "sort": "created.desc", "size": page_size, "page": page},
        )
        if not res or (isinstance(res[0], dict) and res[0].get("Type") == _ENTRY_TYPE_ERROR):
            demisto.debug(f"[GIB-DRP-dedup] getIncidents error or empty on page={page}: {res!r}")
            return

        data = (res[0].get("Contents") or {}).get("data") or []
        if not data:
            return

        for existing in data:
            yield existing
            yielded += 1
            if yielded >= max_total:
                demisto.debug(
                    f"[GIB-DRP-dedup] reached max_total={max_total} for gibdrpid={gibdrpid}; " "remaining duplicates skipped"
                )
                return

        if len(data) < page_size:
            return
        page += 1


def _set_incident(incident_id: str, fields: dict[str, Any]) -> bool:
    """Invoke `setIncident` for one duplicate; return True on success."""
    res = demisto.executeCommand("setIncident", {"id": incident_id, **fields})
    if isinstance(res, list) and res and isinstance(res[0], dict) and res[0].get("Type") == _ENTRY_TYPE_ERROR:
        demisto.debug(f"[GIB-DRP-dedup] setIncident failed for {incident_id}: {res[0].get('Contents')!r}")
        return False
    return True


def _close_incident(incident_id: str, close_reason: str, violation_status: str | None, approve_state: str | None) -> bool:
    """Close one duplicate because the work on the violation is over."""
    if close_reason == CLOSE_REASON_FALSE_POSITIVE and approve_state == REJECTED_APPROVE_STATE:
        why = "The violation was rejected in Group-IB DRP"
    else:
        why = f"Group-IB DRP reports the violation as '{violation_status}'"
    res = demisto.executeCommand(
        "closeInvestigation",
        {
            "id": incident_id,
            "closeReason": close_reason,
            # The violation id is deliberately not repeated here: it is a 64-hex string, which
            # XSOAR auto-extracts from close notes as a SHA256 File indicator. The id stays in
            # the GIB DRP ID field of the incident.
            "closeNotes": (
                f"{why}, so the incident was closed automatically. The violation is identified by the GIB DRP ID field."
            ),
        },
    )
    if isinstance(res, list) and res and isinstance(res[0], dict) and res[0].get("Type") == _ENTRY_TYPE_ERROR:
        demisto.debug(f"[GIB-DRP-dedup] closeInvestigation failed for {incident_id}: {res[0].get('Contents')!r}")
        return False
    return True


def indicator_value(uri: str) -> str | None:
    """The value GIBDRPCreateViolationIndicator gave the indicator made from this violation URI.

    Mirrors that automation's `classify`: a bare `//host/path` became an https URL, a bare
    `host/path` got an https scheme, a bare host was lower-cased; anything with a scheme other
    than http or https (`mail://`, `tg://`) never became an indicator, so there is nothing to expire.
    """
    candidate = uri.strip()
    if not candidate:
        return None
    if candidate.startswith("//"):
        candidate = "https:" + candidate
    if "://" in candidate:
        parts = urlsplit(candidate)
        if parts.scheme.lower() not in ("http", "https") or not parts.hostname:
            return None
        return candidate
    if "/" in candidate or "?" in candidate:
        return "https://" + candidate if urlsplit("https://" + candidate).hostname else None
    return candidate.rstrip(".").lower()


def _expire_indicator(uri: str) -> bool:
    """Expire the indicator created from the violation URI; the indicator itself is kept."""
    value = indicator_value(uri)
    if not value:
        demisto.debug(f"[GIB-DRP-dedup] {uri!r} never became an indicator; nothing to expire")
        return False
    # Cortex XSOAR 8 reads the builtin's list from `indicatorsValues` ("Provide indicator(s) value(s)"
    # otherwise); `value` is the name older builtin documentation uses, so both are passed.
    res = demisto.executeCommand("expireIndicators", {"indicatorsValues": value, "value": value})
    if isinstance(res, list) and res and isinstance(res[0], dict) and res[0].get("Type") == _ENTRY_TYPE_ERROR:
        demisto.info(f"[GIB-DRP-dedup] expireIndicators failed for {value!r}: {res[0].get('Contents')!r}")
        return False
    return True


def main() -> None:
    try:
        incident = demisto.incident() or {}
        if not isinstance(incident, dict):
            raise Exception("Incoming incident is missing from the pre-processing context.")

        gibdrpid = get_gibdrpid(incident)
        violation_status = get_violation_status(incident)
        approve_state = get_approve_state(incident)
        demisto.debug(f"[GIB-DRP-dedup] gibdrpid={gibdrpid} violation_status={violation_status} approve_state={approve_state}")

        if not gibdrpid:
            return_results(True)
            return

        update_fields = build_update_fields(incident)
        close_reason = close_reason_for(violation_status, approve_state)

        considered = 0
        updated = 0
        closed = 0
        expired = False
        for existing in iter_existing_incidents(gibdrpid):
            existing_id = _normalize(existing.get("id"))
            if not existing_id:
                continue
            considered += 1
            if update_fields and _set_incident(existing_id, update_fields):
                updated += 1
            # A duplicate that is already closed stays closed; nothing here reopens it.
            should_close = close_reason is not None and existing.get("status") != _INCIDENT_STATUS_CLOSED
            if should_close and close_reason and _close_incident(existing_id, close_reason, violation_status, approve_state):
                closed += 1
                uri = violation_uri(incident, existing)
                if uri and not expired and wants_indicator_expired(incident, existing):
                    expired = _expire_indicator(uri)

        if considered == 0:
            # No real duplicates -> let XSOAR create the incoming incident.
            return_results(True)
            return

        demisto.debug(
            f"[GIB-DRP-dedup] updated {updated}/{considered} existing duplicates, closed {closed}, "
            f"indicator_expired={expired}"
        )
        if update_fields and updated == 0:
            # Every setIncident failed: keep the incoming incident so the new
            # violation state is not silently lost.
            return_results(True)
            return
        # Duplicates exist and were updated (or needed no update) -> drop the
        # incoming incident.
        return_results(False)
    except Exception as exc:  # noqa: BLE001 - top-level XSOAR script handler
        demisto.error(f"[GIB-DRP-dedup] failed: {exc}")
        return_error(f"GIBDRPIncidentUpdate failed: {exc}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
