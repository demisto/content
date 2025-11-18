import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def extract_ids(case_extra_data: dict) -> list:
    """
    Extract a list of IDs from a command result.

    Args:
        command_res: The result of a command. It can be either a dictionary or a list.
        field_name: The name of the field that contains the ID.

    Returns:
        A list of the IDs extracted from the command result.
    """
    if not case_extra_data:
        return []

    field_name = "issue_id"
    issues = case_extra_data.get("issues", {})
    issues_data = issues.get("data", {}) if issues else {}
    issue_ids = [c.get(field_name) for c in issues_data if isinstance(c, dict) and field_name in c]
    demisto.debug(f"Extracted issue ids: {issue_ids}")
    return issue_ids


def get_case_extra_data(args):
    """
    Calls the core-get-case-extra-data command and parses the output to a standard structure.

    Args:
        args: The arguments to pass to the core-get-case-extra-data command.

    Returns:
        A dictionary containing the case data with the following keys:
            issue_ids: A list of IDs of issues in the case.
            network_artifacts: A list of network artifacts in the case.
            file_artifacts: A list of file artifacts in the case.
    """
    demisto.debug(f"Calling core-get-case-extra-data, {args=}")
    case_extra_data = execute_command("core-get-case-extra-data", args)
    demisto.debug(f"After calling core-get-case-extra-data, {case_extra_data=}")
    issue_ids = extract_ids(case_extra_data)
    case_data = case_extra_data.get("case", {})
    notes = case_data.get("notes")
    xdr_url = case_data.get("xdr_url")
    starred_manually = case_data.get("starred_manually")
    manual_description = case_data.get("manual_description")
    detection_time = case_data.get("detection_time")
    manual_description = case_extra_data.get("manual_description")
    network_artifacts = case_extra_data.get("network_artifacts")
    file_artifacts = case_extra_data.get("file_artifacts")
    extra_data = {
        "issue_ids": issue_ids,
        "network_artifacts": network_artifacts,
        "file_artifacts": file_artifacts,
        "notes": notes,
        "detection_time": detection_time,
        "xdr_url": xdr_url,
        "starred_manually": starred_manually,
        "manual_description": manual_description,
    }
    return extra_data


def add_cases_extra_data(case_data):
    # for each case id in the entry context, get the case extra data
    for case in case_data:
        case_id = case.get("case_id")
        extra_data = get_case_extra_data({"case_id": case_id, "limit": 1000})
        case.update({"CaseExtraData": extra_data})

    return case_data


def prepare_time_range(args: dict, start_key: str, end_key: str, gte_key: str, lte_key: str, time_type: str):
    """
    Prepare and validate start and end time parameters for a specific time range type.

    Args:
        args (dict): Dictionary containing time parameters
        start_key (str): Key for start time in args
        end_key (str): Key for end time in args
        gte_key (str): Key to set for greater-than-or-equal time
        lte_key (str): Key to set for less-than-or-equal time
        time_type (str): Type of time for error messages (e.g., "creation", "modification")

    Raises:
        DemistoException: If end_time is provided without start_time
    """
    start_time = args.get(start_key, "")
    end_time = args.get(end_key, "")

    if end_time and not start_time:
        raise DemistoException(f"When {time_type} end time is provided {time_type}_start_time must be provided as well.")

    if start_time := dateparser.parse(start_time):
        start_time = start_time.strftime("%Y-%m-%dT%H:%M:%S")

    if end_time := dateparser.parse(end_time):
        end_time = end_time.strftime("%Y-%m-%dT%H:%M:%S")

    if start_time and not end_time:
        # Set end_time to default now.
        end_time = datetime.now().strftime("%Y-%m-%dT%H:%M:%S")

    if start_time and end_time:
        args[gte_key] = start_time
        args[lte_key] = end_time


def prepare_start_end_time(args: dict):
    """
    Prepare and validate start and end time parameters from args dictionary.

    Parses start_time and end_time from string format to ISO format and validates
    that when end_time is provided, start_time must also be provided. If only start_time
    is provided, sets end_time to current time. Sets time_frame to 'custom' when both
    times are specified.

    Args:
        args (dict): Dictionary containing start_time and end_time parameters

    Raises:
        DemistoException: If end_time is provided without start_time

    Side Effects:
        Modifies the args dictionary in place by:
        - Converting start_time and end_time to ISO format
        - Setting time_frame to 'custom' when both times are present
        - Setting end_time to current time if only start_time is provided

    """
    prepare_time_range(args, "creation_start_time", "creation_end_time", "gte_creation_time", "lte_creation_time", "creation")
    prepare_time_range(
        args, "modification_start_time", "modification_end_time", "gte_modification_time", "lte_modification_time", "modification"
    )


def main():  # pragma: nocover
    """
    Gets cases using the core-get-cases command with the given arguments.
    """
    args: dict = demisto.args()
    prepare_start_end_time(args)
    args["limit"] = args.pop("page_size", 100)
    try:
        demisto.debug(f"Calling core-get-cases with arguments: {args}")
        results: dict = demisto.executeCommand("core-get-cases", args)  # type: ignore
        demisto.debug(f"core-get-cases command results: {results}")
        resultsContent = demisto.get(results[0], "Contents")

        if is_error(results):
            error = get_error(results)
            demisto.debug("error: " + error)
            raise DemistoException(f"Failed to execute the core-get-cases command {error}")

        # In case enriched case data was requested
        if argToBoolean(args.get("get_enriched_case_data", "false")):
            if isinstance(resultsContent, dict):
                resultsContent = [resultsContent]

            case_extra_data = add_cases_extra_data(resultsContent)

            return_results(
                CommandResults(
                    readable_output=tableToMarkdown("Cases", case_extra_data, headerTransform=string_to_table_header),
                    outputs_prefix="Core.Case",
                    outputs_key_field="case_id",
                    outputs=case_extra_data,
                    raw_response=case_extra_data,
                )
            )

        return_results(
            CommandResults(
                readable_output=tableToMarkdown("Cases", resultsContent, headerTransform=string_to_table_header),
                outputs_prefix="Core.Case",
                outputs_key_field="case_id",
                outputs=resultsContent,
                raw_response=resultsContent,
            )
        )

    except DemistoException as error:
        return_error(f"Failed to execute SearchCases. Error:\n{error}", error)


if __name__ in ("__main__", "__builtin__", "builtins"):  # pragma: no cover
    main()
