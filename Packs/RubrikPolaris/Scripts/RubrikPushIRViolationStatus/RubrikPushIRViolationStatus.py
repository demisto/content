import demistomock as demisto
from CommonServerPython import *

ERROR_MESSAGES = {"MISSING_ARGUMENT": "Please provide correct input for '{}' argument."}

""" COMMAND FUNCTION """


def sync_the_violation_status(args: dict[str, Any]) -> dict[str, Any]:
    """
    Push the IR Violation Status information from XSOAR to RSC.

    :type args: ``Dict[str, Any]``
    :param args: Arguments provided by user.

    :rtype: ``Dict[str, Any]``
    :return: command result.
    """
    remove_nulls_from_dictionary(args)

    incident_info = demisto.incident()
    incident_violation_id = demisto.get(incident_info, "CustomFields.rubrikviolationid")
    incident_violation_status = demisto.get(incident_info, "CustomFields.rubrikirviolationstatus")
    violation_id = args.get("violation_id") or incident_violation_id
    violation_status = args.get("violation_status") or incident_violation_status

    if not violation_id:
        raise ValueError(ERROR_MESSAGES["MISSING_ARGUMENT"].format("violation_id"))
    if not violation_status:
        raise ValueError(ERROR_MESSAGES["MISSING_ARGUMENT"].format("violation_status"))

    command_args = {"violation_id": violation_id, "status": violation_status}

    command_results = demisto.executeCommand("rubrik-identity-resilience-violation-status-update", command_args)
    if not isinstance(command_results, list):
        command_results = [command_results]

    command_result = {}
    for cmd_result in command_results:
        if not isError(cmd_result):
            command_result = cmd_result
            break

    if not command_result:
        raise ValueError(f"Failed to update violation status: {command_results[0].get('Contents')}")

    return command_result


""" MAIN FUNCTION """


def main() -> None:
    try:
        return_results(sync_the_violation_status(demisto.args()))
    except Exception as ex:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f"Failed to execute RubrikPushIRViolationStatus-RubrikSecurityCloud. Error: {ex!s}")


""" ENTRY POINT """


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
