from datetime import datetime
import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import dateparser

OUTPUT_KEYS = [
    "internal_id",
    "severity",
    "Identity_type",
    "alert_name",
    "alert_source",
    "actor_process_image_sha256",
    "causality_actor_process_image_sha256",
    "action_process_image_sha256",
    "alert_category",
    "alert_domain",
    "alert_description",
    "os_actor_process_image_sha256",
    "action_file_macro_sha256",
    "status.progress",
    "assetid",
    "assigned_to_pretty",
    "assigned_to",
    "source_insert_ts",
]


def remove_empty_string_values(args):
    """Remove empty string values from the args dictionary."""
    return {key: value for key, value in args.items() if value != ""}


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
        # When working with start time and end time need to specify time_frame custom.
        args["time_frame"] = "custom"
        args["start_time"] = start_time
        args["end_time"] = end_time


def main():  # pragma: no cover
    try:
        args: dict = demisto.args()
        prepare_start_end_time(args)

        if additional_output_fields := args.pop("additional_output_fields", []):
            OUTPUT_KEYS.extend(additional_output_fields)

        # Return only specific fields to the context.
        args["output_keys"] = ",".join(OUTPUT_KEYS)
        args = remove_empty_string_values(args)

        demisto.debug(f"Calling core-get-issues with arguments: {args}")
        results: dict = demisto.executeCommand("core-get-issues", args)[0]  # type: ignore

        if is_error(results):
            error = get_error(results)
            demisto.debug("error: " + error)
            raise DemistoException(f"Failed to execute the core-get-issues command {error}")

        context = results.get("EntryContext", {}).get("Core.Issue(val.internal_id && val.internal_id == obj.internal_id)")
        human_readable: str = results.get("HumanReadable", "")

        return_results(CommandResults(outputs=context, outputs_prefix="Core.Issue", readable_output=human_readable))

    except DemistoException as error:
        return_error(f"Error from search issuess {error}", str(error))


if __name__ in ("__main__", "__builtin__", "builtins"):  # pragma: no cover
    main()
