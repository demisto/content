"""
Run-after-update script for Taegis Requested Assignee (taegisrequestedassignee).

When the user changes the requested assignee, sets Taegis Requested Status so that
pushing to Taegis uses the correct status. Uses taegisxdrassigneeid (primary) and
taegisxdrassignee (fallback) to distinguish handoff vs take-from-queue vs customer
take-ownership.

Assignment behaviors (Taegis Requested Status):
- Requested = @secureworks -> AWAITING_ACTION (queue for Secureworks).
- Requested = @customer and current != @customer -> AWAITING_ACTION (queue for customer).
- Current = @customer (by ID or display "customer") and Requested != @secureworks -> ACTIVE
  (customer taking ownership: user selects a specific user or @customer).
- Requested = specific user, Current = specific user (UUID in Taegis) -> AWAITING_ACTION (handoff).
- Otherwise (e.g. current = @secureworks, requested = specific user) -> ACTIVE (take from queue).
"""

STATUS_AWAITING_ACTION = "AWAITING_ACTION"
STATUS_ACTIVE = "ACTIVE"
REQUESTED_ASSIGNEE_FIELD = "taegisrequestedassignee"
REQUESTED_STATUS_FIELD = "taegisrequestedstatus"
CURRENT_ASSIGNEE_FIELD = "taegisxdrassignee"
CURRENT_ASSIGNEE_ID_FIELD = "taegisxdrassigneeid"
PLACEHOLDER_ASSIGNEE = "Select Assignee"

AWAITING_ACTION_ASSIGNEES = {"@secureworks", "@customer"}
# Non-empty assignee ID that is not the symbolic queue -> real user in Taegis
_ID_SPECIFIC_MARKER = "__specific_user__"


def _get_incident():
    """Return the incident dict, unwrapping incident/Incident if present."""
    raw = demisto.incident()
    if not raw or not isinstance(raw, dict):
        return {}
    if "incident" in raw and isinstance(raw.get("incident"), dict):
        return raw["incident"]
    if "Incident" in raw and isinstance(raw.get("Incident"), dict):
        return raw["Incident"]
    return raw


def _get_incident_id(incident):
    if not isinstance(incident, dict):
        return None
    return incident.get("id")


def _fetch_latest_incident(incident_id):
    """Re-fetch incident so we see the new taegisrequestedassignee value."""
    if not incident_id:
        return None
    try:
        res = demisto.executeCommand("getIncident", {"id": incident_id})
        if not res or not isinstance(res, list) or len(res) == 0:
            return None
        entry = res[0]
        if not isinstance(entry, dict):
            return None
        contents = entry.get("Contents")
        if isinstance(contents, dict) and contents.get("id"):
            return contents
        if isinstance(contents, list) and len(contents) > 0 and isinstance(contents[0], dict):
            return contents[0]
        return None
    except Exception as e:
        demisto.debug("TaegisXDRSetRequestedStatusFromRequestedAssignee: getIncident failed: {}".format(e))
        return None


def _get_field(incident, field_name):
    """Get field from incident or CustomFields."""
    if not isinstance(incident, dict):
        return None
    v = incident.get(field_name)
    if v is not None and str(v).strip():
        return str(v).strip()
    cf = incident.get("CustomFields") or incident.get("customFields") or {}
    if isinstance(cf, dict):
        v = cf.get(field_name)
        if v is not None and str(v).strip():
            return str(v).strip()
    return None


def _normalize_assignee_id_raw(assignee_id_str):
    """
    Classify Taegis assignee ID from API / incident field.
    Returns '@customer', '@secureworks', _ID_SPECIFIC_MARKER, or None (empty - use display fallback).
    """
    if assignee_id_str is None or not str(assignee_id_str).strip():
        return None
    t = str(assignee_id_str).strip().replace("(@)", "@").strip()
    tl = t.lower()
    if tl == "@customer" or tl == "customer":
        return "@customer"
    if tl == "@secureworks" or tl == "secureworks":
        return "@secureworks"
    return _ID_SPECIFIC_MARKER


def _resolve_current_assignee_queue(incident):
    """
    Return '@customer', '@secureworks', or None.
    None means current assignee is a specific user (UUID) or unknown - use handoff vs take logic.
    Primary: taegisxdrassigneeid. Fallback: taegisxdrassignee display (e.g. 'customer' without @).
    """
    raw_id = _get_field(incident, CURRENT_ASSIGNEE_ID_FIELD)
    nid = _normalize_assignee_id_raw(raw_id)
    if nid in ("@customer", "@secureworks"):
        return nid
    if nid == _ID_SPECIFIC_MARKER:
        return None
    # Empty assignee ID - mirror may only have filled display name
    disp = _get_field(incident, CURRENT_ASSIGNEE_FIELD) or ""
    dl = disp.strip().lower()
    if dl in ("customer", "@customer"):
        return "@customer"
    if dl in ("secureworks", "@secureworks"):
        return "@secureworks"
    return None


def _is_specific_user(assignee):
    """True if request target is a specific person (dropdown label), not @secureworks or @customer."""
    if not assignee or not str(assignee).strip():
        return False
    return str(assignee).lower().strip() not in AWAITING_ACTION_ASSIGNEES


def main():
    incident = _get_incident()
    incident_id = _get_incident_id(incident)
    if incident_id:
        latest = _fetch_latest_incident(incident_id)
        if latest is not None:
            incident = latest

    new_assignee = _get_field(incident, REQUESTED_ASSIGNEE_FIELD)
    if not new_assignee or new_assignee == PLACEHOLDER_ASSIGNEE:
        demisto.debug("TaegisXDRSetRequestedStatusFromRequestedAssignee: no assignee or placeholder; skipping")
        return

    current_queue = _resolve_current_assignee_queue(incident)
    new_normalized = new_assignee.lower().strip()

    if current_queue == "@customer" and new_normalized != "@secureworks":
        # Customer queue: user picks a named user or @customer (not handing to Sophos) -> ACTIVE
        new_status = STATUS_ACTIVE
    elif new_normalized in AWAITING_ACTION_ASSIGNEES:
        new_status = STATUS_AWAITING_ACTION
    elif _is_specific_user(new_assignee) and current_queue is None:
        # Both sides are specific users (current had real ID on case) -> handoff
        new_status = STATUS_AWAITING_ACTION
    else:
        # e.g. @secureworks + specific user -> take from queue
        new_status = STATUS_ACTIVE

    demisto.executeCommand("setIncident", {REQUESTED_STATUS_FIELD: new_status})
    demisto.debug(
        "TaegisXDRSetRequestedStatusFromRequestedAssignee: set {} to {} (requested_assignee={}, "
        "current_queue={}, assignee_id={})".format(
            REQUESTED_STATUS_FIELD,
            new_status,
            new_assignee,
            current_queue,
            _get_field(incident, CURRENT_ASSIGNEE_ID_FIELD),
        )
    )


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
