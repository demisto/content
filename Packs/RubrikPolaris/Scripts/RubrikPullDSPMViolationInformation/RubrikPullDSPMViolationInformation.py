import demistomock as demisto
from CommonServerPython import *

ERROR_MESSAGES = {"MISSING_ARGUMENT": "Please provide correct input for '{}' argument."}

""" COMMAND FUNCTION """


def sync_the_violation_information(args: dict[str, Any]) -> list:
    """
    Sync the DSPM Violation infromation from RSC.

    :type args: ``Dict[str, Any]``
    :param args: Arguments provided by user.

    :rtype: ``list``
    :return: command result.
    """
    remove_nulls_from_dictionary(args)

    incident_info = demisto.incident()
    incident_violation_id = demisto.get(incident_info, "CustomFields.rubrikviolationid")
    violation_id = args.get("violation_id") or incident_violation_id

    if not violation_id:
        raise ValueError(ERROR_MESSAGES["MISSING_ARGUMENT"].format("violation_id"))

    command_args = {"violation_id": violation_id}

    command_results = demisto.executeCommand("rubrik-data-security-violation-get", command_args)
    if not isinstance(command_results, list):
        command_results = [command_results]

    command_result = {}
    for cmd_result in command_results:
        if not isError(cmd_result):
            command_result = cmd_result
            break

    if not command_result:
        return_error(command_results[0].get("Contents"))

    response = command_result.get("Contents")
    violation_data = demisto.get(response, "data.policyViolation", {})
    mapped_object = demisto.mapObject(violation_data, "Rubrik Polaris Radar - Mapping", "Rubrik DSPM Violation")
    updated_mapped_data = {}

    for key, value in mapped_object.items():
        new_key = "".join(key.lower().split())
        updated_mapped_data[new_key] = value

    results: list = [command_result]
    if updated_mapped_data:
        demisto.executeCommand("setIncident", updated_mapped_data)

    results.append(
        CommandResults(readable_output=f"#### Violation {violation_id} information has been synchronized successfully.")
    )

    return results


""" MAIN FUNCTION """


def main():
    try:
        return_results(sync_the_violation_information(demisto.args()))
    except Exception as ex:
        return_error(f"Failed to execute RubrikPullDSPMViolationInformation-RubrikSecurityCloud. Error: {ex!s}")


""" ENTRY POINT """


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
