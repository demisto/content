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

    # Check if indicator exists
    indicator_value = args.get("value")
    demisto.debug(f"Checking if {indicator_value} exists by running findIndicators.")
    exists = execute_command("findIndicators", {"value": indicator_value})
    if not exists:
        return_error("Indicator does not exist.")

    success_results = ""
    error_result = ""

    related_issues = argToList(args.pop("related_issues", ""))

    # Set indicator with provided properties
    if any(key in args for key in ["type", "verdict", "tags"]):
        demisto.debug("running setIndicator command.")
        execute_command("setIndicator", args)
        success_results += "Successfully set indicator properties.\n"

    # Associate the indicator to the provided related issues and alert if don't exist.
    if related_issues:
        issues_found = execute_command("core-get-issues", {"issue_id": related_issues}).get("alerts", [])
        existing_issues_ids = []
        for existing_issue in issues_found:
            issue_id = existing_issue.get("alert_fields", {}).get("internal_id")
            if issue_id:
                existing_issues_ids.append(issue_id)

        demisto.debug(f"Found the following issues: {existing_issues_ids}.")
        existing_set = set(existing_issues_ids)
        related_issues = set(related_issues)
        diff_issues = related_issues - existing_set
        demisto.debug(f"The following issues were provided as related issues but don't exist: {diff_issues}.")
        if diff_issues:
            error_result = f"The following issues were provided as related issues but don't exist: {diff_issues}."

        issues_associated = []
        for issue in existing_issues_ids:
            demisto.debug(f"running associateIndicatorsToIssue command with issue id {issue}.")
            execute_command("associateIndicatorsToAlert", {"issueId": issue, "indicatorsValues": indicator_value})
            issues_associated.append(issue)

        if issues_associated:
            success_results += f"Successfully associated indicator to the following issues {issues_associated}. "

    final_outputs = success_results + error_result
    outputs = {"Value": indicator_value, "Result": final_outputs}
    final_results = []
    if success_results:
        final_results.append(
            CommandResults(
                readable_output=success_results, outputs=outputs, outputs_key_field="Value", outputs_prefix="SetIndicator"
            )
        )
    if error_result:
        final_results.append(CommandResults(readable_output=error_result, entry_type=4))

    return final_results


def main():
    try:
        return_results(set_indicator_if_exist(demisto.args()))
    except Exception as ex:
        return_error(f"Failed to execute SetIndicator. Error: {str(ex)}")


if __name__ in ("__main__", "__builtin__", "builtins"):  # pragma: no cover
    main()
