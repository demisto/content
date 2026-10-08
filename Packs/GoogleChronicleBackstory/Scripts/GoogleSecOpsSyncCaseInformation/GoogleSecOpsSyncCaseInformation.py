import time
from datetime import UTC, datetime, timedelta

import demistomock as demisto
from CommonServerPython import *

HR_DATE_FORMAT = "%Y-%m-%d %H:%M:%S UTC"

DEFAULT_ALERT_PAGE_SIZE = "1000"
DEFAULT_ENTITY_PAGE_SIZE = "1000"
ALERT_LOOP_TIMEOUT_SECONDS = 540
MAX_PAGE_SIZE = 1000

MAPPER_NAME = "Google SecOps Cases - Incoming Mapper"
INCIDENT_TYPE = "Google SecOps Case"

ERROR_MESSAGES = {
    "MISSING_ARGUMENT": "Please provide correct input for '{}' argument.",
    "FAILED_COMMAND": "Failed to execute '{}' command. Error: {}",
    "FAILED_ALERTS": "Failed to retrieve alerts for case '{}'. Error: {}",
    "FAILED_ENTITIES": "Failed to retrieve entities for alert '{}'. Error: {}",
    "INVALID_INT_RANGE": "Invalid value '{}' for argument '{}'. Expected a value between {} and {}.",
}

""" HELPER FUNCTIONS """


def trim_spaces_from_args(args: dict[str, Any]) -> dict[str, Any]:
    """
    Trim leading and trailing whitespace from all string argument values.

    :type args: dict[str, Any]
    :param args: Command arguments dictionary.

    :return: Arguments dictionary with string values stripped.
    :rtype: dict[str, Any]
    """
    for key, value in args.items():
        if isinstance(value, str):
            args[key] = value.strip()
    return args


def validate_page_size(value: int | None, arg_name: str) -> int | None:
    """
    Validate a page size argument falls within the allowed range.

    :type value: int or None
    :param value: Parsed page size value.

    :type arg_name: str
    :param arg_name: Argument name, used in the error message.

    :return: The validated value.
    :rtype: int or None

    :raises ValueError: If value is not between 1 and MAX_PAGE_SIZE (inclusive).
    """
    if value is not None and (value < 1 or value > MAX_PAGE_SIZE):
        raise ValueError(ERROR_MESSAGES["INVALID_INT_RANGE"].format(value, arg_name, 1, MAX_PAGE_SIZE))
    return value


def epoch_ms_to_datestring(epoch_ms: int | str, date_format: str = HR_DATE_FORMAT) -> str:
    """
    Convert a UTC epoch timestamp in milliseconds to a formatted date string.

    :type epoch_ms: int or str
    :param epoch_ms: UTC epoch timestamp in milliseconds.

    :type date_format: str
    :param date_format: Output format; defaults to HR_DATE_FORMAT.

    :return: Formatted UTC date string.
    :rtype: str
    """
    return datetime.fromtimestamp(int(epoch_ms) / 1000, tz=UTC).strftime(date_format)


def epoch_ms_to_time_delta(ms: int) -> str:
    """
    Convert a duration in milliseconds to a human-readable string.

    :type ms: int
    :param ms: Duration in milliseconds.

    :return: Duration as 'X days, X hours, X minutes, X seconds'.
    :rtype: str
    """
    delta = timedelta(milliseconds=ms)
    total_seconds = int(delta.total_seconds())
    days, remainder = divmod(total_seconds, 86400)
    hours, remainder = divmod(remainder, 3600)
    minutes, seconds = divmod(remainder, 60)
    labels = [(days, "days"), (hours, "hours"), (minutes, "minutes"), (seconds, "seconds")]
    parts = [f"{value} {unit}" for value, unit in labels if value]
    return ", ".join(parts) or "0 seconds"


def prepare_alert_sla(sla: dict[str, Any]) -> str:
    """
    Format an alert SLA dict into a multiline string for the XSOAR incident field.

    Converts epoch millisecond timestamp fields (expirationTime, criticalExpirationTime)
    to HR date strings and remainingTimeSinceLastPause to a human-readable duration.
    Always includes Status; remaining fields appended only if present.

    :type sla: dict[str, Any]
    :param sla: Raw SLA object from the Google SecOps API response.

    :return: Multiline string with SLA fields in 'Label - Value' format.
    :rtype: str
    """
    parts = [f"Status - {sla.get('expirationStatus', '')}"]
    expiration_time = sla.get("expirationTime")
    if expiration_time:
        parts.append(f"Expiration Time - {epoch_ms_to_datestring(expiration_time, date_format=HR_DATE_FORMAT)}")
    critical_expiration_time = sla.get("criticalExpirationTime")
    if critical_expiration_time:
        parts.append(f"Critical Expiration Time - {epoch_ms_to_datestring(critical_expiration_time, date_format=HR_DATE_FORMAT)}")
    remaining_time = sla.get("remainingTimeSinceLastPause")
    if remaining_time:
        parts.append(f"Remaining Time Since Last Pause - {epoch_ms_to_time_delta(remaining_time)}")
    return "\n".join(parts)


def get_command_result(command_results: list) -> dict:
    """
    Return the first non-error result from an executeCommand output list.

    :type command_results: list
    :param command_results: Raw list returned by demisto.executeCommand.

    :return: First successful result entry, or an empty dict if all entries are errors.
    :rtype: dict
    """
    for result in command_results:
        if not isError(result):
            return result
    return {}


def execute_command_safe(command: str, args: dict) -> tuple[dict, Any]:
    """
    Execute a demisto command and return a (result, error) tuple.

    :type command: str
    :param command: Name of the demisto command to execute.

    :type args: dict
    :param args: Arguments to pass to the command.

    :return: (result_dict, None) on success; ({}, error_contents) on failure.
             The error value is the raw Contents field from the error entry, which may be str, dict, or list.
    :rtype: tuple[dict, Any]
    """
    raw = demisto.executeCommand(command, args)
    if not isinstance(raw, list):
        raw = [raw]
    result = get_command_result(raw)
    if not result:
        error = raw[0].get("Contents", "Unknown error") if raw else "Unknown error"
        return {}, error
    return result, None


def apply_mapper(data: dict) -> dict:
    """
    Apply the Google SecOps Cases incoming mapper to the provided data dict and
    normalise the resulting keys to lowercase with spaces removed so they match
    XSOAR incident custom field names accepted by setIncident.

    :type data: dict
    :param data: Raw case data to map.

    :return: Mapped incident fields with normalised lowercase no-space keys.
    :rtype: dict
    """
    mapped = demisto.mapObject(data, MAPPER_NAME, INCIDENT_TYPE) or {}
    return {"".join(field_name.lower().split()): field_value for field_name, field_value in mapped.items()}


def get_case_information(case_id: str) -> tuple[dict, dict]:
    """
    Execute gcb-case-get and return the raw result and case data.

    :type case_id: str
    :param case_id: The ID of the Google SecOps Case.

    :return: (raw_result, case_data) where case_data is the Contents dict.
    :rtype: tuple[dict, dict]

    :raises ValueError: If the command returns an error.
    """
    result, err = execute_command_safe("gcb-case-get", {"case_id": case_id})
    if err:
        raise ValueError(ERROR_MESSAGES["FAILED_COMMAND"].format("gcb-case-get", err))
    return result, result.get("Contents") or {}


def get_alert_list(case_id: str, page_size: int | None) -> tuple[dict, list]:
    """
    Execute gcb-case-alert-list and return the raw result and alerts list.

    :type case_id: str
    :param case_id: The ID of the Google SecOps Case.

    :type page_size: int | None
    :param page_size: Maximum number of alerts to retrieve.

    :return: (raw_result, alerts) where alerts is a list of alert dicts.
    :rtype: tuple[dict, list]

    :raises ValueError: If the command returns an error.
    """
    result, err = execute_command_safe("gcb-case-alert-list", {"case_id": case_id, "page_size": str(page_size)})
    if err:
        raise ValueError(ERROR_MESSAGES["FAILED_ALERTS"].format(case_id, err))
    alerts_data = result.get("Contents") or {}
    alerts = alerts_data.get("caseAlerts", [])
    if alerts_data.get("nextPageToken"):
        demisto.debug(
            f"More than {page_size} alerts present for case '{case_id}'. Only the first {page_size} alerts were fetched."
        )
    return result, alerts


def get_alert_entity_list(case_id: str, alert_id: str, page_size: int | None) -> tuple[dict, list] | tuple[None, None]:
    """
    Execute gcb-case-alert-entity-list for a single alert.

    :type case_id: str
    :param case_id: The ID of the Google SecOps Case.

    :type alert_id: str
    :param alert_id: The ID of the Case Alert.

    :type page_size: int | None
    :param page_size: Maximum number of entities to retrieve.

    :return: (raw_result, entities) on success, or (None, None) if the command fails.
    :rtype: tuple[dict, list] | tuple[None, None]
    """
    result, err = execute_command_safe(
        "gcb-case-alert-entity-list", {"case_id": case_id, "alert_id": alert_id, "page_size": str(page_size)}
    )
    if err:
        demisto.debug(ERROR_MESSAGES["FAILED_ENTITIES"].format(alert_id, err))
        return None, None
    entities_data = result.get("Contents") or {}
    entities = entities_data.get("involvedEntities", [])
    return result, entities


""" COMMAND FUNCTION """


def sync_case_information(args: dict[str, Any]) -> list:
    """
    Sync the latest case information, related alerts, and alert entities
    from Google SecOps and update the XSOAR incident data.

    Execution order:
        1. gcb-case-get — fetch case details and update incident fields via setIncident.
        2. gcb-case-alert-list — fetch alerts linked to the case.
        3. gcb-case-alert-entity-list — fetch entities for each alert (failures are logged and skipped).

    :type args: dict[str, Any]
    :param args: Script arguments.
        - case_id (str): ID of the Google SecOps Case. Falls back to the
          incident custom field 'googlesecopscaseid' when not provided.
        - alert_page_size (str|int): Maximum number of alerts to retrieve per sync. Default is 1000.
        - entity_page_size (str|int): Maximum number of entities to retrieve per alert per sync. Default is 1000.

    Note: Alert entity fetching is time-bounded. If iterating over alerts takes longer than 9 minutes (540 seconds),
    the loop exits early and remaining alerts are skipped to avoid exceeding XSOAR's script execution timeout.

    :return: List of raw command results plus a final CommandResults with a
             human-readable sync confirmation message.
    :rtype: list

    :raises ValueError: If case_id cannot be resolved, if alert_page_size/entity_page_size fall outside 1-1000,
        or if gcb-case-get, gcb-case-alert-list return an error.
    """
    remove_nulls_from_dictionary(args)

    incident_info = demisto.incident()
    incident_case_id = demisto.get(incident_info, "CustomFields.googlesecopscaseid")
    case_id = args.get("case_id") or incident_case_id

    if not case_id:
        raise ValueError(ERROR_MESSAGES["MISSING_ARGUMENT"].format("case_id"))

    alert_page_size = validate_page_size(arg_to_number(args.get("alert_page_size", DEFAULT_ALERT_PAGE_SIZE)), "alert_page_size")
    entity_page_size = validate_page_size(
        arg_to_number(args.get("entity_page_size", DEFAULT_ENTITY_PAGE_SIZE)), "entity_page_size"
    )

    results: list = []

    case_result, case_data = get_case_information(case_id)
    results.append(case_result)

    alert_result, alerts = get_alert_list(case_id, alert_page_size)
    results.append(alert_result)

    entities: list = []
    loop_start_time = time.time()
    for alert in alerts:
        if time.time() - loop_start_time > ALERT_LOOP_TIMEOUT_SECONDS:
            demisto.debug("Alert processing loop exceeded 9 minutes. Breaking early.")
            break

        if "alertId" not in alert:
            parts = alert.get("name", "").split("caseAlerts/")
            alert["alertId"] = parts[1] if len(parts) >= 2 else ""
        raw_create_time = alert.get("createTime")
        if raw_create_time:
            alert["createTimeFormatted"] = epoch_ms_to_datestring(raw_create_time)
        alert["slaFormatted"] = prepare_alert_sla(alert.get("sla", {}))
        alert_id = alert.get("alertId")

        if not alert_id:
            demisto.debug(f"Skipping alert with missing alertId. Alert name: {alert.get('name')}")
            continue
        entity_result, alert_entities = get_alert_entity_list(case_id, alert_id, entity_page_size)
        if entity_result and alert_entities is not None:
            results.append(entity_result)
            for entity in alert_entities:
                entity["alertId"] = alert_id
            entities.extend(alert_entities)

    for task in case_data.get("tasks", []):
        raw_create_time = task.get("createTime")
        if raw_create_time:
            task["createTimeFormatted"] = epoch_ms_to_datestring(raw_create_time)
        raw_due_time = task.get("dueTime")
        if raw_due_time:
            task["dueTimeFormatted"] = epoch_ms_to_datestring(raw_due_time)

    case_data["caseId"] = case_id
    case_data["alertDetails"] = alerts
    case_data["entityDetails"] = entities
    mapped_case = apply_mapper(case_data)
    if mapped_case:
        demisto.executeCommand("setIncident", mapped_case)

    results.append(CommandResults(readable_output=f"#### Case {case_id} information has been synchronized successfully."))

    return results


""" MAIN FUNCTION """


def main():
    """
    Entry point. Reads script arguments, executes sync_case_information,
    and returns results. Catches all exceptions and surfaces them via return_error.
    """
    try:
        return_results(sync_case_information(trim_spaces_from_args(demisto.args())))
    except Exception as ex:
        demisto.error(traceback.format_exc())
        return_error(f"Failed to execute GoogleSecOpsSyncCaseInformation. Error: {ex!s}")


""" ENTRY POINT """


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
