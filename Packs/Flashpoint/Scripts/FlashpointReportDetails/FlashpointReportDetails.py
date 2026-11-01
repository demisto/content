import demistomock as demisto
from CommonServerPython import *

REPORT_GET_COMMAND = "flashpoint-ignite-intelligence-report-get"
SET_INCIDENT_COMMAND = "setIncident"

ALERT_TEXT_FIELD = "flashpointreportbody"

EMPTY_DATA = "No report body available."

ERROR_MESSAGES = {
    "MISSING_ARGUMENT": "Please provide correct input for '{}' argument.",
    "FAILED_COMMAND": "Failed to execute '{}' command. Error: {}",
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


""" COMMAND FUNCTION """


def get_report_details(args: dict[str, Any]) -> dict:
    """
    Set the report body on the incident and return the raw report entry.

    :type args: dict[str, Any]
    :param args: Script arguments.
        - report_id (str): ID of the report. Falls back to the incident custom field 'flashpointsourceid' when not provided.

    :return: Raw entry returned by the report-get command, or an empty dict when the command fails. The report body is
        written to the 'flashpointreportbody' incident field, falling back to a placeholder message when the report has
        no body.
    :rtype: dict

    :raises ValueError: If report_id cannot be resolved.
    """
    remove_nulls_from_dictionary(args)

    incident_info = demisto.incident()
    incident_report_id = demisto.get(incident_info, "CustomFields.flashpointsourceid")
    report_id = args.get("report_id") or incident_report_id

    if not report_id:
        raise ValueError(ERROR_MESSAGES["MISSING_ARGUMENT"].format("report_id"))

    result, err = execute_command_safe(REPORT_GET_COMMAND, {"report_id": report_id})
    if err:
        demisto.error(ERROR_MESSAGES["FAILED_COMMAND"].format(REPORT_GET_COMMAND, err))

    body = demisto.get(result, "Contents.body") or EMPTY_DATA

    execute_command_safe(SET_INCIDENT_COMMAND, {ALERT_TEXT_FIELD: body})

    return result


""" MAIN FUNCTION """


def main():
    """
    Entry point. Reads script arguments, executes get_report_details,
    and returns results. Catches all exceptions and surfaces them via return_error.
    """
    try:
        return_results(get_report_details(trim_spaces_from_args(demisto.args())))
    except Exception as ex:
        demisto.error(traceback.format_exc())
        return_error(f"Failed to execute FlashpointReportDetails. Error: {ex!s}")


""" ENTRY POINT """


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
