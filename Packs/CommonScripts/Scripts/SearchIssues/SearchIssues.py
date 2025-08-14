from datetime import datetime
import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

OUTPUT_KEYS = [
    "alert_id",
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
    "asset_ids",
    "assigned_to_pretty",
]


def remove_empty_string_values(args):
    """Remove empty string values from the args dictionary."""
    return {key: value for key, value in args.items() if value != ""}


def main():  # pragma: no cover
    try:
        args: dict = demisto.args()

        if args.get("end_time") and not args.get("start_time"):
            raise DemistoException("When end time is provided start_time must be provided as well.")

        if args.get("start_time") and not args.get("end_time"):
            args["end_time"] = datetime.now().strftime("%Y-%m-%dT%H:%M:%S")

        if args.get("start_time") and args.get("end_time"):
            # When working with start time and end time need to specify time_frame custom.
            args["time_frame"] = "custom"

        # Return only specific fields to the context.
        args["output_keys"] = ",".join(OUTPUT_KEYS)
        args = remove_empty_string_values(args)

        demisto.debug(f"Calling core-get-issues with arguments: {args}")
        results = demisto.executeCommand("core-get-issues", args)[0]

        if is_error(results):
            error = get_error(results)
            demisto.debug("error: " + error)
            raise DemistoException("Failed to execute the core-get-issues command")

        context = results.get("EntryContext", {}).get("Core.Issue(val.internal_id && val.internal_id == obj.internal_id)")
        human_readable = results.get("HumanReadable")

        return_results(CommandResults(outputs=context, outputs_prefix="Core.Issue", readable_output=human_readable))

    except DemistoException as error:
        return_error(f"Error from search issuess {error}", str(error))


if __name__ in ("__main__", "__builtin__", "builtins"):  # pragma: no cover
    main()
