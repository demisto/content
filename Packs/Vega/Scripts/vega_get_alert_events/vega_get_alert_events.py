import json

import demistomock as demisto
from CommonServerPython import *


VEGA_INTEGRATION_BRAND = "Vega"
VEGA_FETCH_ALERT_EVENTS_COMMAND = "vega-fetch-alert-events"
DEFAULT_ALERT_EVENTS_PAGE_SIZE = 200
VEGA_ALERT_INCIDENT_TYPE = "Vega Alert"
MIRROR_ENTITY_SUFFIX_ALERT = "alert"


def _return_alert_events_table(markdown_table: str, outputs: dict[str, Any]) -> None:
    """Return alert events as a rendered markdown table in the war room and layout widget."""
    return_results(
        CommandResults(
            readable_output=markdown_table,
            outputs_prefix="Vega.AlertEvents",
            outputs_key_field="AlertId",
            outputs=outputs,
        )
    )


def _collect_custom_fields(incident: dict) -> dict[str, Any]:
    """Merge incident CustomFields with flattened custom-field keys."""
    custom_fields: dict[str, Any] = dict(incident.get("CustomFields") or incident.get("customFields") or {})
    for field_name in (
        "vegaalertid",
        "dbotmirrorid",
        "vegaalerteventsloadedfor",
        "vegaalertevents",
        "vegaalerteventsoffset",
        "vegaalerteventstotal",
    ):
        if field_name not in custom_fields and incident.get(field_name) is not None:
            custom_fields[field_name] = incident.get(field_name)
    return custom_fields


def _load_current_incident() -> dict:
    """Load the current investigation incident, fetching full fields when needed."""
    incident = demisto.incident() or {}
    if not incident.get("id"):
        try:
            incidents = demisto.incidents()
            if incidents:
                incident = incidents[0] or {}
        except Exception as exc:
            demisto.debug(f"vega-get-alert-events: demisto.incidents() failed: {exc}")

    incident_id = incident.get("id")
    if not incident_id:
        return incident

    try:
        response = demisto.executeCommand("getIncidents", {"id": str(incident_id)})
        if is_error(response):
            demisto.debug(f"vega-get-alert-events: getIncidents failed: {get_error(response)}")
            return incident

        contents = response[0].get("Contents", {})
        if isinstance(contents, str):
            contents = json.loads(contents)
        data = contents.get("data") if isinstance(contents, dict) else None
        if isinstance(data, list) and data:
            return data[0]
    except Exception as exc:
        demisto.debug(f"vega-get-alert-events: failed to load incident {incident_id}: {exc}")

    return incident


def _get_incident_custom_fields(incident: dict) -> dict:
    custom_fields = _collect_custom_fields(incident)
    return custom_fields if isinstance(custom_fields, dict) else {}


def _extract_readable_output(command_entry: dict) -> str:
    """Return rendered markdown table output from an integration command entry."""
    human_readable = command_entry.get("HumanReadable")
    if human_readable and str(human_readable).strip():
        return str(human_readable)
    contents = command_entry.get("Contents", "")
    if isinstance(contents, str) and contents.strip():
        return contents
    return ""


def _extract_alert_events_context(command_entry: dict) -> dict:
    """Extract Vega.AlertEvents context from an integration command entry."""
    entry_context = command_entry.get("EntryContext")
    if not isinstance(entry_context, dict):
        return {}

    alert_events = dict_safe_get(entry_context, ("Vega", "AlertEvents"))
    if alert_events is None:
        for key, value in entry_context.items():
            if isinstance(key, str) and key.startswith("Vega.AlertEvents") and isinstance(value, dict):
                alert_events = value
                break

    if isinstance(alert_events, list):
        return alert_events[0] if alert_events else {}
    if isinstance(alert_events, dict):
        return alert_events
    return {}


def _build_persisted_custom_fields(alert_id: str, readable_output: str, total: Any, offset: int) -> dict[str, Any]:
    """Build incident CustomFields for the alert-events layout section."""
    custom_fields: dict[str, Any] = {
        "vegaalerteventsloadedfor": alert_id,
        "vegaalertevents": readable_output,
        "vegaalerteventsoffset": offset,
    }
    if total is not None and str(total).strip() != "":
        try:
            custom_fields["vegaalerteventstotal"] = int(total)
        except (TypeError, ValueError):
            custom_fields["vegaalerteventstotal"] = total
    return custom_fields


def _persist_custom_fields_on_incident(incident_id: str, custom_fields: dict[str, Any]) -> None:
    """Save alert-event CustomFields on the open incident."""
    set_result = demisto.executeCommand(
        "setIncident",
        {
            "id": incident_id,
            "customFields": custom_fields,
            "version": -1,
        },
    )
    if is_error(set_result):
        return_error(f"Failed to save alert events on the incident: {get_error(set_result)}")


def _parse_alert_id_from_mirror_id(mirror_id: str) -> str | None:
    """Extract a Vega alert ID from a mirrored alert entity ID."""
    suffix = f"-{MIRROR_ENTITY_SUFFIX_ALERT}"
    if mirror_id.endswith(suffix):
        return mirror_id[: -len(suffix)]
    return None


def _resolve_alert_id(args: dict, incident: dict, custom_fields: dict) -> str | None:
    """Resolve Vega alert ID from args or the current Vega Alert incident."""
    alert_id = args.get("alert_id")
    if alert_id is not None and str(alert_id).strip():
        return str(alert_id).strip()

    vega_alert_id = custom_fields.get("vegaalertid")
    if vega_alert_id is not None and str(vega_alert_id).strip():
        return str(vega_alert_id).strip()

    loaded_for = custom_fields.get("vegaalerteventsloadedfor")
    if loaded_for is not None and str(loaded_for).strip():
        return str(loaded_for).strip()

    mirror_id = custom_fields.get("dbotmirrorid") or custom_fields.get("dbotMirrorId")
    if mirror_id is not None and str(mirror_id).strip():
        parsed_alert_id = _parse_alert_id_from_mirror_id(str(mirror_id).strip())
        if parsed_alert_id:
            return parsed_alert_id

    incident_type = str(incident.get("type") or incident.get("Type") or "").strip()
    raw_json = incident.get("rawJSON") or incident.get("rawJson")
    if raw_json:
        try:
            raw = json.loads(raw_json) if isinstance(raw_json, str) else raw_json
            if isinstance(raw, dict):
                if incident_type and incident_type != VEGA_ALERT_INCIDENT_TYPE:
                    return None
                if not incident_type and raw.get("vegaEntityType") not in (None, VEGA_ALERT_INCIDENT_TYPE):
                    return None
                raw_id = raw.get("id")
                if raw_id is not None and str(raw_id).strip():
                    return str(raw_id).strip()
        except (json.JSONDecodeError, TypeError, ValueError):
            pass

    return None


def _resolve_offset(args: dict, custom_fields: dict) -> int:
    """Resolve the display offset from args or persisted incident fields."""
    current_offset = arg_to_number(args.get("offset"))
    if current_offset is None:
        current_offset = arg_to_number(custom_fields.get("vegaalerteventsoffset")) or 0
    return max(0, int(current_offset))


def main() -> None:
    try:
        args = demisto.args()
        incident = _load_current_incident()
        incident_id = incident.get("id")
        custom_fields = _get_incident_custom_fields(incident)
        alert_id = _resolve_alert_id(args, incident, custom_fields)

        if not alert_id:
            incident_type = str(incident.get("type") or incident.get("Type") or "unknown")
            return_error(
                "alert_id is required when the script is not run from a Vega Alert incident. "
                f"Could not resolve alert ID from incident id={incident_id or 'none'}, type={incident_type}. "
                "Open a Vega Alert investigation or pass alert_id explicitly."
            )

        alert_id = str(alert_id).strip()
        page_size = arg_to_number(args.get("limit")) or DEFAULT_ALERT_EVENTS_PAGE_SIZE
        page_size = max(1, int(page_size))
        offset = _resolve_offset(args, custom_fields)

        command_args: dict[str, str] = {
            "alert_id": alert_id,
            "limit": str(page_size),
            "offset": str(offset),
            "using-brand": VEGA_INTEGRATION_BRAND,
        }

        command_result = demisto.executeCommand(VEGA_FETCH_ALERT_EVENTS_COMMAND, command_args)
        if is_error(command_result):
            return_error(get_error(command_result))

        command_entry = command_result[0]
        if command_entry.get("Brand") == "Scripts":
            return_error(
                f"{VEGA_FETCH_ALERT_EVENTS_COMMAND} resolved to the automation script instead of the Vega integration. "
                "Ensure a Vega integration instance is configured."
            )

        readable_output = _extract_readable_output(command_entry)
        alert_events_context = _extract_alert_events_context(command_entry)

        fields_to_set = alert_events_context.get("CustomFields")
        if not isinstance(fields_to_set, dict) or not str(fields_to_set.get("vegaalertevents", "")).strip():
            fields_to_set = _build_persisted_custom_fields(
                alert_id,
                readable_output,
                alert_events_context.get("Total"),
                arg_to_number(alert_events_context.get("Offset")) or offset,
            )

        if incident_id and str(fields_to_set.get("vegaalertevents", "")).strip():
            _persist_custom_fields_on_incident(str(incident_id), fields_to_set)
        elif not str(fields_to_set.get("vegaalertevents", "")).strip():
            return_error("Vega returned no alert events to display.")

        _return_alert_events_table(
            readable_output,
            alert_events_context or {"AlertId": alert_id, "Cached": False},
        )
    except Exception as exc:
        return_error(f"Failed to execute vega-get-alert-events. Error: {str(exc)}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
