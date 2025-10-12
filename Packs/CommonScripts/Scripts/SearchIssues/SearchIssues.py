import json
from datetime import datetime
import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import dateparser

EQ = "EQ"
OUTPUT_KEYS = [
    "internal_id",
    "severity",
    "Identity_type",
    "issue_name",
    "issue_source",
    "actor_process_image_sha256",
    "causality_actor_process_image_sha256",
    "action_process_image_sha256",
    "issue_category",
    "issue_domain",
    "issue_description",
    "os_actor_process_image_sha256",
    "action_file_macro_sha256",
    "status.progress",
    "assetid",
    "assigned_to_pretty",
    "assigned_to",
    "source_insert_ts",
]

SEARCH_SHA256_FIELDS = [
    "actor_process_image_sha256",
    "causality_actor_process_image_sha256",
    "action_process_image_sha256",
    "os_actor_process_image_sha256",
    "action_file_macro_sha256",
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


def create_sha_search_field_query(sha_search_field: str, search_type: str, sha_list: list[str]) -> Optional[dict]:
    """
    Given a list of sha256 values, builds a query of this form: { "AND": [ { {"OR": [{"SEARCH_FIELD": sha_search_field,
    "SEARCH_TYPE": search_type ,"SEARCH_VALUE": sha_list[0]} , .... , {"SEARCH_FIELD": sha_search_field,"SEARCH_TYPE":
    search_type ,"SEARCH_VALUE": sha_list[-1]} ]} } ] }

    """
    if not sha_list:
        return None
    or_operator_list = []
    for sha in sha_list:
        or_operator_list.append({"SEARCH_FIELD": sha_search_field, "SEARCH_TYPE": search_type, "SEARCH_VALUE": sha})
    return {"AND": [{"OR": or_operator_list}]}


def prepare_sha256_custom_field(args: dict) -> Optional[str]:
    """
    Builds a structured query from a list of SHA256 values and assigns it to the 'custom_filter' field in the given args.

    The function:
    - Extracts the 'sha256' argument (as a string or list).
    - For each predefined SHA256 search field, constructs a query block:
        - Uses 'EQ'
        - Each SHA is mapped to an OR clause per field.
    - Combines all field-specific queries under a top-level OR.
    - Adds the final query as a JSON string to args['custom_filter'].

    Example structure added to args["custom_filter"]:
    {
        "OR": [
            {
                "AND": [
                    {
                        "OR": [
                            {
                                "SEARCH_FIELD": "actor_process_image_sha256",
                                "SEARCH_TYPE": "EQ",
                                "SEARCH_VALUE": "abc"
                            }
                        ]
                    }
                ]
            },
            {
                "AND": [
                    {
                        "OR": [
                            {
                                "SEARCH_FIELD": "causality_actor_process_image_sha256",
                                "SEARCH_TYPE": "EQ",
                                "SEARCH_VALUE": "xyz"
                            }
                        ]
                    }
                ]
            }
        ]
    }
    """
    sha256 = argToList(args.pop("sha256", ""))
    if not sha256:
        return None
    or_operator_list: list[dict] = []
    for sha_search_field in SEARCH_SHA256_FIELDS:
        sha_search_field_query = create_sha_search_field_query(sha_search_field, EQ, sha256)
        if sha_search_field_query:
            or_operator_list.append(sha_search_field_query)
    return json.dumps({"OR": or_operator_list})


def main():  # pragma: no cover
    try:
        args: dict = demisto.args()
        prepare_start_end_time(args)

        if additional_output_fields := args.pop("additional_output_fields", []):
            OUTPUT_KEYS.extend(additional_output_fields)

        # Return only specific fields to the context.
        args["output_keys"] = ",".join(OUTPUT_KEYS)
        sha256_custom_field = prepare_sha256_custom_field(args)
        if sha256_custom_field:
            args["custom_filter"] = sha256_custom_field

        if issue_domain := args.get("issue_domain"):
            args["issue_domain"] = f"DOMAIN_{issue_domain.upper().replace(' ', '_')}"

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
        return_error(f"Failed to execute SearchIssues. Error:\n{error}", error)


if __name__ in ("__main__", "__builtin__", "builtins"):  # pragma: no cover
    main()
