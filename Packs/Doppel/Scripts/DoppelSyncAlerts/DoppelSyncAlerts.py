import traceback
from datetime import UTC, datetime
from typing import Any

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401,F403

""" CONSTANTS """

CURSOR_LIST_NAME = "Doppel Sync Alerts Cursor"
TIMESTAMP_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
DOPPEL_MAX_PAGE_SIZE = 200
INCIDENT_SEARCH_BATCH = 20
INCIDENT_SEARCH_PAGE_SIZE = 100
SEVERITY_MAP = {"low": 1, "medium": 2, "high": 3, "critical": 4}

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


def _get_modified_alerts(cursor: str, max_pages: int, instance_name: str | None) -> tuple[list[dict], bool]:
    """
    Page through Doppel alerts whose last activity is at or after the cursor.

    Returns the alerts and whether the result set was fully drained. When the page cap
    is hit with more data remaining, the caller must not advance the cursor, so the
    remaining updates are picked up by the next sweep (updates are idempotent).
    """
    alerts: list[dict] = []
    seen_ids: set[str] = set()
    page = 0
    while page < max_pages:
        args: dict[str, Any] = {
            "last_activity_timestamp": cursor,
            "page": page,
            "page_size": DOPPEL_MAX_PAGE_SIZE,
        }
        if instance_name:
            args["using"] = instance_name
        contents = _contents(_execute("doppel-get-alerts", args))
        batch = contents.get("alerts") if isinstance(contents, dict) else None
        if not batch:
            return alerts, True
        for alert in batch:
            alert_id = str(alert.get("id") or "")
            if alert_id and alert_id not in seen_ids:
                seen_ids.add(alert_id)
                alerts.append(alert)
        if len(batch) < DOPPEL_MAX_PAGE_SIZE:
            return alerts, True
        page += 1
    return alerts, False


def _find_incidents_by_mirror_ids(mirror_ids: list[str]) -> dict[str, list[dict]]:
    """Search existing incidents/issues by dbotMirrorId, batching the queries."""
    found: dict[str, list[dict]] = {}
    for start in range(0, len(mirror_ids), INCIDENT_SEARCH_BATCH):
        chunk = mirror_ids[start : start + INCIDENT_SEARCH_BATCH]
        query = " or ".join(f'dbotMirrorId:"{mirror_id}"' for mirror_id in chunk)
        page = 0
        while True:
            contents = _contents(_execute("getIncidents", {"query": query, "page": page, "size": INCIDENT_SEARCH_PAGE_SIZE}))
            data = (contents or {}).get("data") or []
            for incident in data:
                mirror_id = str(incident.get("dbotMirrorId") or "")
                if mirror_id:
                    found.setdefault(mirror_id, []).append(incident)
            # The API's `total` field is unreliable on some tenants; stop on a short page.
            if len(data) < INCIDENT_SEARCH_PAGE_SIZE:
                break
            page += 1
    return found


def _build_custom_fields(alert: dict) -> dict[str, Any]:
    """Map the mutable Doppel alert fields to their incident field cliNames."""
    fields: dict[str, Any] = {
        "doppelqueuestate": alert.get("queue_state"),
        "doppelentitystate": alert.get("entity_state"),
        "doppelnotes": alert.get("notes"),
    }
    audit_logs = alert.get("audit_logs")
    if isinstance(audit_logs, list) and audit_logs and all(isinstance(log, dict) for log in audit_logs):
        fields["doppelauditlogs"] = audit_logs
    return {key: value for key, value in fields.items() if value is not None}


def _alert_severity(alert: dict) -> int:
    return SEVERITY_MAP.get(str(alert.get("severity") or "").strip().lower(), 0)


def _use_alert_commands() -> bool:
    """On XSIAM and the unified Cortex platform, alert commands replace incident commands."""
    return bool(is_xsiam() or is_platform())


def _update_incident(incident_id: str, custom_fields: dict[str, Any], severity: int, use_alert_commands: bool) -> None:
    args: dict[str, Any] = {"id": incident_id, "customFields": custom_fields}
    if severity:
        args["severity"] = severity
    if use_alert_commands:
        results = demisto.executeCommand("setAlert", args)
        if not is_error(results):
            return
        demisto.debug(f"Doppel - setAlert failed for {incident_id}, falling back to setIncident: {get_error(results)}")
    _execute("setIncident", args)


def _is_closed(incident: dict) -> bool:
    if arg_to_number(incident.get("status")) == IncidentStatus.DONE:
        return True
    closed = str(incident.get("closed") or "")
    return bool(closed) and not closed.startswith("0001-01-01")


def _close_incident(incident_id: str, alert_id: str) -> None:
    _execute(
        "closeInvestigation",
        {
            "id": incident_id,
            "closeReason": "Resolved",
            "closeNotes": f"Doppel alert {alert_id} was archived in Doppel.",
        },
    )


""" MAIN """


def main():
    try:
        args = demisto.args()
        lookback = args.get("lookback") or "1 hour"
        max_pages = arg_to_number(args.get("max_pages")) or 5
        close_archived = argToBoolean(args.get("close_archived") or "false")
        dry_run = argToBoolean(args.get("dry_run") or "false")
        instance_name = args.get("instance_name")

        sweep_start = datetime.now(UTC).strftime(TIMESTAMP_FORMAT)
        cursor = _load_cursor(lookback)
        use_alert_commands = _use_alert_commands()

        alerts, drained = _get_modified_alerts(cursor, max_pages, instance_name)
        matched = _find_incidents_by_mirror_ids([str(alert.get("id")) for alert in alerts]) if alerts else {}

        updated = 0
        closed = 0
        unmatched = 0
        errors: list[str] = []
        for alert in alerts:
            alert_id = str(alert.get("id"))
            incidents = matched.get(alert_id) or []
            if not incidents:
                unmatched += 1
                continue
            custom_fields = _build_custom_fields(alert)
            severity = _alert_severity(alert)
            for incident in incidents:
                incident_id = str(incident.get("id"))
                try:
                    if not dry_run:
                        _update_incident(incident_id, custom_fields, severity, use_alert_commands)
                    updated += 1
                    if close_archived and str(alert.get("queue_state")) == "archived" and not _is_closed(incident):
                        if not dry_run:
                            _close_incident(incident_id, alert_id)
                        closed += 1
                except Exception as exc:
                    errors.append(f"{alert_id} -> incident {incident_id}: {exc}")

        # Advance the cursor only after a clean, fully-drained sweep. Re-processing on the
        # next sweep is safe because every update is idempotent.
        cursor_advanced = bool(not dry_run and drained and not errors)
        if cursor_advanced:
            _save_cursor(sweep_start)

        summary = {
            "ModifiedAlerts": len(alerts),
            "IncidentsUpdated": updated,
            "IncidentsClosed": closed,
            "AlertsWithoutIncident": unmatched,
            "Errors": len(errors),
            "CursorAdvanced": cursor_advanced,
            "Cursor": sweep_start if cursor_advanced else cursor,
            "DryRun": dry_run,
        }
        readable = tableToMarkdown("Doppel Sync Alerts", summary)
        if errors:
            readable += "\n" + tableToMarkdown("Errors (first 20)", [{"Error": error} for error in errors[:20]])
        return_results(
            CommandResults(
                outputs_prefix="Doppel.SyncAlerts",
                outputs=summary,
                readable_output=readable,
                raw_response=summary,
            )
        )
    except Exception as exc:
        demisto.error(traceback.format_exc())
        return_error(f"DoppelSyncAlerts failed: {exc}")


if __name__ in ("__main__", "__builtin__", "builtins"):  # pragma: no cover
    main()
