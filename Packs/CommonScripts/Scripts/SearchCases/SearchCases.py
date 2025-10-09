import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


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

        return_results(results)

    except DemistoException as error:
        return_error(f"Failed to execute SearchCases. Error:\n{error}", error)


if __name__ in ("__main__", "__builtin__", "builtins"):  # pragma: no cover
    main()
