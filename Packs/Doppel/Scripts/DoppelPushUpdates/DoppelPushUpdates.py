import traceback
from datetime import UTC, datetime
from typing import Any

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401,F403

""" CONSTANTS """

CURSOR_LIST_NAME = "Doppel Push Updates Cursor"
TIMESTAMP_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
INCIDENT_SEARCH_PAGE_SIZE = 100
DOPPEL_INCIDENT_TYPES = (
    "Doppel Alert Crypto",
    "Doppel Alert Domains",
    "Doppel Alert Ecommerce",
    "Doppel Alert Email",
    "Doppel Alert Mobile_Apps",
    "Doppel Alert Paid_Ads",
    "Doppel Alert Social_Media",
    "Doppel Alert Telco",
    "Doppel_Incident",
)

""" HELPER FUNCTIONS """


def _execute(command: str, args: dict[str, Any]) -> list:
    """Run a command through the server and raise on error entries."""
    results = demisto.executeCommand(command, args)
    if is_error(results):
        raise DemistoException(f"Doppel - {command} failed: {get_error(results)}")
    return results or []


def _contents(results: list) -> Any:
    """Return the Contents of the first non-error entry."""
    for entry in results:
        if entry.get("Type") != EntryType.ERROR:
            return entry.get("Contents")
    return None


def _load_cursor(lookback: str) -> str:
    """Read the last successful sweep timestamp, falling back to the lookback window."""
    results = demisto.executeCommand("getList", {"listName": CURSOR_LIST_NAME})
    if not is_error(results):
        value = str(_contents(results) or "").strip()
        parsed = arg_to_datetime(value, required=False) if value else None
        if parsed:
            return parsed.strftime(TIMESTAMP_FORMAT)
    start = arg_to_datetime(lookback, required=False)
    if not start:
        raise DemistoException(f"Doppel - Could not parse the lookback value: {lookback!r}")
    return start.strftime(TIMESTAMP_FORMAT)


def _save_cursor(value: str) -> None:
    """Persist the sweep timestamp, creating the list on first use."""
    results = demisto.executeCommand("setList", {"listName": CURSOR_LIST_NAME, "listData": value})
    if is_error(results):
        _execute("createList", {"listName": CURSOR_LIST_NAME, "listData": value})


def _closed_incidents_query(cursor: str) -> str:
    types = " or ".join(f'type:"{incident_type}"' for incident_type in DOPPEL_INCIDENT_TYPES)
    return f'({types}) and closed:>="{cursor}"'


def _get_closed_incidents(cursor: str, max_incidents: int) -> tuple[list[dict], bool]:
    """
    Page through incidents/issues closed at or after the cursor.

    Returns the incidents and whether the result set was fully drained. When the cap is
    hit with more data remaining, the caller must not advance the cursor.
    """
    query = _closed_incidents_query(cursor)
    incidents: list[dict] = []
    page = 0
    while len(incidents) < max_incidents:
        contents = _contents(_execute("getIncidents", {"query": query, "page": page, "size": INCIDENT_SEARCH_PAGE_SIZE}))
        data = (contents or {}).get("data") or []
        incidents.extend(data)
        # The API's `total` field is unreliable on some tenants; stop on a short page.
        if len(data) < INCIDENT_SEARCH_PAGE_SIZE:
            return incidents[:max_incidents], True
        page += 1
    return incidents[:max_incidents], False


def _should_push(incident: dict) -> bool:
    """Duplicate closures come from incident cleanup, not analyst dispositions; a live
    incident for the same Doppel alert usually remains open, so archiving would be wrong."""
    return str(incident.get("closeReason") or "").strip().lower() != "duplicate"


def _get_live_alert(mirror_id: str, instance_name: str | None) -> dict | None:
    args: dict[str, Any] = {"id": mirror_id}
    if instance_name:
        args["using"] = instance_name
    contents = _contents(_execute("doppel-get-alert", args))
    return contents if isinstance(contents, dict) else None


def _archive_alert(mirror_id: str, close_notes: str, push_close_notes: bool, instance_name: str | None) -> None:
    args: dict[str, Any] = {"alert_id": mirror_id, "queue_state": "archived"}
    if push_close_notes and close_notes:
        args["comment"] = close_notes
    if instance_name:
        args["using"] = instance_name
    _execute("doppel-update-alert", args)


""" MAIN """


def main():
    try:
        args = demisto.args()
        lookback = args.get("lookback") or "1 hour"
        max_incidents = arg_to_number(args.get("max_incidents")) or 500
        push_close_notes = argToBoolean(args.get("push_close_notes") or "true")
        dry_run = argToBoolean(args.get("dry_run") or "false")
        instance_name = args.get("instance_name")

        sweep_start = datetime.now(UTC).strftime(TIMESTAMP_FORMAT)
        cursor = _load_cursor(lookback)

        incidents, drained = _get_closed_incidents(cursor, max_incidents)

        pushed = 0
        already_archived = 0
        skipped = 0
        errors: list[str] = []
        pushed_ids: set[str] = set()
        for incident in incidents:
            mirror_id = str(incident.get("dbotMirrorId") or "")
            if not mirror_id or not _should_push(incident) or mirror_id in pushed_ids:
                skipped += 1
                continue
            pushed_ids.add(mirror_id)
            try:
                alert = _get_live_alert(mirror_id, instance_name)
                if alert and str(alert.get("queue_state") or "") == "archived":
                    already_archived += 1
                    continue
                if not dry_run:
                    _archive_alert(mirror_id, str(incident.get("closeNotes") or ""), push_close_notes, instance_name)
                pushed += 1
            except Exception as exc:
                errors.append(f"{mirror_id}: {exc}")

        # Advance the cursor only after a clean, fully-drained sweep. Re-processing on the
        # next sweep is safe because already-archived alerts are skipped.
        cursor_advanced = bool(not dry_run and drained and not errors)
        if cursor_advanced:
            _save_cursor(sweep_start)

        summary = {
            "ClosedIncidents": len(incidents),
            "AlertsArchived": pushed,
            "AlreadyArchived": already_archived,
            "Skipped": skipped,
            "Errors": len(errors),
            "CursorAdvanced": cursor_advanced,
            "Cursor": sweep_start if cursor_advanced else cursor,
            "DryRun": dry_run,
        }
        readable = tableToMarkdown("Doppel Push Updates", summary)
        if errors:
            readable += "\n" + tableToMarkdown("Errors (first 20)", [{"Error": error} for error in errors[:20]])
        return_results(
            CommandResults(
                outputs_prefix="Doppel.PushUpdates",
                outputs=summary,
                readable_output=readable,
                raw_response=summary,
            )
        )
    except Exception as exc:
        demisto.error(traceback.format_exc())
        return_error(f"DoppelPushUpdates failed: {exc}")


if __name__ in ("__main__", "__builtin__", "builtins"):  # pragma: no cover
    main()
