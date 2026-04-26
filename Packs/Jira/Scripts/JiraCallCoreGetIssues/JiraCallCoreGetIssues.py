import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

INTEGRATION_COMMAND = "core-get-issues"


def build_args(args: dict[str, Any]) -> dict[str, Any]:
    """
    Build the arguments for the core-get-issues command by passing through
    all provided arguments directly.

    Args:
        args: The script arguments from demisto.args().

    Returns:
        A dict of arguments to pass to core-get-issues.
    """
    command_args: dict[str, Any] = {}

    # Pass through all provided arguments directly to the command
    passthrough_args = [
        "issue_id",
        "severity",
        "custom_filter",
        "Identity_type",
        "agent_id",
        "action_external_hostname",
        "rule_id",
        "rule_name",
        "issue_name",
        "issue_source",
        "user_name",
        "actor_process_image_name",
        "causality_actor_process_image_command_line",
        "actor_process_image_command_line",
        "action_process_image_command_line",
        "actor_process_image_sha256",
        "causality_actor_process_image_sha256",
        "action_process_image_sha256",
        "action_file_image_sha256",
        "action_registry_name",
        "action_registry_key_data",
        "host_ip",
        "action_local_ip",
        "action_remote_ip",
        "issue_action_status",
        "action_local_port",
        "action_remote_port",
        "dst_action_external_hostname",
        "sort_field",
        "sort_order",
        "page",
        "page_size",
        "start_time",
        "end_time",
        "starred",
        "mitre_technique_id_and_name",
        "issue_category",
        "issue_domain",
        "issue_description",
        "os_actor_process_image_sha256",
        "action_file_macro_sha256",
        "status",
        "not_status",
        "asset_ids",
        "assignee",
        "output_keys",
    ]

    for arg_name in passthrough_args:
        if (value := args.get(arg_name)) is not None:
            command_args[arg_name] = value

    return command_args


def call_core_get_issues(args: dict[str, Any]) -> list[dict[str, Any]]:
    """
    Execute the core-get-issues command and return the results.

    Args:
        args: The arguments to pass to core-get-issues.

    Returns:
        The list of command results entries.
    """
    command_args = build_args(args)
    demisto.debug(f"Calling {INTEGRATION_COMMAND} with args: {command_args}")

    res = demisto.executeCommand(INTEGRATION_COMMAND, command_args)
    if not res or not isinstance(res, list):
        raise DemistoException(
            f"Unexpected response from {INTEGRATION_COMMAND}. "
            f"Expected a list but got: {type(res)}. Response: {res}"
        )

    for entry in res:
        if isError(entry):
            raise DemistoException(
                f"Error returned from {INTEGRATION_COMMAND}: {entry.get('Contents', '')}"
            )

    return res


def main():  # pragma: no cover
    try:
        demisto.debug("JiraCallCoreGetIssues is being called")
        results = call_core_get_issues(demisto.args())
        return_results(results)
    except Exception as ex:
        return_error(f"Failed to execute JiraCallCoreGetIssues. Error: {ex!s}")


if __name__ in ["__builtin__", "builtins", "__main__"]:
    main()
