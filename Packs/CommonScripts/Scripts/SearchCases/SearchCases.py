import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def extract_ids(command_res, field_name):
    """
    Extract a list of IDs from a command result.

    Args:
        command_res: The result of a command. It can be either a dictionary or a list.
        field_name: The name of the field that contains the ID.

    Returns:
        A list of the IDs extracted from the command result.
    """
    ids = []
    if command_res:
        if isinstance(command_res, dict):
            ids = [command_res.get(field_name)] if field_name in command_res else []
        elif isinstance(command_res, list):
            ids = [c.get(field_name) for c in command_res if isinstance(c, dict) and field_name in c]
    return ids


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
    case = case_extra_data.get("case", {})
    issues = case_extra_data.get("issues", {}).get("data")
    issue_ids = extract_ids(issues, "issue_id")
    network_artifacts = case_extra_data.get("network_artifacts")
    file_artifacts = case_extra_data.get("file_artifacts")
    case.update({"issue_ids": issue_ids, "network_artifacts": network_artifacts, "file_artifacts": file_artifacts})
    return case

def add_case_extra_data(results):
    raw_response = results.get("Contents", {})
    if isinstance(raw_response, dict):
        raw_response = [raw_response]
    if len(raw_response) > 10:
        raise DemistoException("Up to 10 cases are allowed when requesting enriched case data.")
    # for each case id in the entry context, get the case extra data
    for case in raw_response:
        case_id = case.get("case_id")
        case_extra_data = get_case_extra_data({"case_id": case_id, "limit": 1000})
        case.update(case_extra_data)

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
    start_time = args.get("start_time", "")
    end_time = args.get("end_time", "")

    if end_time and not start_time:
        raise DemistoException("When end time is provided start_time must be provided as well.")

    if start_time := dateparser.parse(start_time):
        start_time = start_time.strftime("%Y-%m-%dT%H:%M:%S")

    if end_time := dateparser.parse(end_time):
        end_time = end_time.strftime("%Y-%m-%dT%H:%M:%S")

    if start_time and not end_time:
        # Set end_time to default now.
        end_time = datetime.now().strftime("%Y-%m-%dT%H:%M:%S")

    if start_time and end_time:
        args["gte_creation_time"] = start_time
        args["lte_creation_time"] = end_time


def main():  # pragma: nocover
    """
    Gets cases using the core-get-cases command with the given arguments.
    """
    args: dict = demisto.args()
    prepare_start_end_time(args)
    args["limit"] = args.pop("page_size", 100)
    try:
        demisto.debug(f"Calling core-get-cases with arguments: {args}")
        results: dict = demisto.executeCommand("core-get-cases", args)[0]  # type: ignore
        demisto.debug(f"core-get-cases command results {results}")

        if is_error(results):
            error = get_error(results)
            demisto.debug("error: " + error)
            raise DemistoException(f"Failed to execute the core-get-cases command {error}")

        # If enriched case data was requested, validate the number of returned cases (max 10)
        # by checking the length of the entry context of the results object
        if argToBoolean(args.get("get_enriched_case_data", "false")):
            
 
        return_results(results)

    except DemistoException as error:
        return_error(f"Failed to execute SearchCases. Error:\n{error}", error)


if __name__ in ("__main__", "__builtin__", "builtins"):  # pragma: no cover
    main()
