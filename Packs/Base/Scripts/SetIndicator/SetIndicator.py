import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *


def set_indicator_if_exist(args: dict):
    """
    Sets an indicator in the system only if it already exists.
    Args:
        args (dict): Args of the script.

    Returns:
        str: The result of setting the indicator or an error message.
    """
    if not any(key in args for key in ["type", "verdict", "tags", "related_issues"]):
        return_error("Please provide at lease one argument to update: type, verdict, tags, or related_issues.")

    indicator_value = args.get("value")
    demisto.debug(f"Checking if {indicator_value} exists by running findIndicators.")
    exists = demisto.executeCommand("findIndicators", {"value": indicator_value})
    if not exists:
        return_error("Indicator does not exist.")

    if any(key in args for key in ["type", "verdict", "tags"]):
        demisto.debug("running setIndicator command.")
        execute_command("setIndicator", args)

    if related_issues := argToList(args.get("related_issues")):
        issue_result_count = execute_command("core-get-issues", {"issue_id": related_issues}).get("result_count")
        demisto.debug(f"Number issues found: {issue_result_count}.")
        if issue_result_count < len(related_issues):
            return_error("One or more related issues do not exist.")

        for issue in related_issues:
            demisto.debug(f"running associateIndicatorsToIssue command with issue id {issue}.")
            execute_command("associateIndicatorsToIssue", {"issueId": issue, "indicatorsValues": indicator_value})

    return CommandResults(readable_output="Successfully set indicator.")


def main():
    try:
        return_results(set_indicator_if_exist(demisto.args()))
    except Exception as ex:
        return_error(f"Failed to execute SetIndicator. Error: {str(ex)}")


if __name__ in ("__main__", "__builtin__", "builtins"):  # pragma: no cover
    main()
