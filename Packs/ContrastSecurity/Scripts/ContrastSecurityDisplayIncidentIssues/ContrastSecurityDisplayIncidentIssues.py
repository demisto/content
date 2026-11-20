import traceback
from datetime import UTC, datetime
from typing import Any

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

# Maximum page_size accepted by contrastsecurity-issue-list
ISSUE_LIST_PAGE_SIZE = 200
# Stop paging after 4 minutes so the script finishes before the automation timeout
PAGINATION_TIMEOUT_SECONDS = 240


def handle_error(command_result: list[dict[str, Any]]) -> None:
    """Handle error in command result and exit."""
    if is_error(command_result):
        return_error(get_error(command_result))


def get_issues_grid_data(issues_data: list) -> list:
    """
    Convert incident issues into grid field format for XSOAR incident layout.

    Args:
        issues_data (list): List of issue objects from the issue list command response.

    Returns:
        list: List of dicts with keys matching the grid field column IDs.
    """
    grid_rows = []
    for issue in issues_data:
        grid_rows.append(
            {
                "severity": (issue.get("severity") or "").title(),
                "score": issue.get("score", ""),
                "title": issue.get("title", ""),
                "issueId": issue.get("issueId", ""),
                "status": (issue.get("status") or "").title(),
                "applicationName": issue.get("applicationName", ""),
                "applicationId": issue.get("applicationId", ""),
                "observationCount": str(issue.get("observationCount", "")),
                "lastObservedTime": issue.get("lastObservedTime", ""),
                "environments": ", ".join(issue.get("environments") or []),
                "issueLink": issue.get("issueLink", ""),
            }
        )
    return remove_empty_elements(grid_rows)


def main():
    try:
        incident_id = demisto.getArg("incident_id")

        if not incident_id:
            return_results(CommandResults(readable_output="##### Contrast Security Incident ID not found."))
            return

        all_issues: list = []
        next_page_cursor = ""
        loop_start_time = datetime.now(UTC).isoformat()

        while True:
            if has_passed_time_threshold(loop_start_time, PAGINATION_TIMEOUT_SECONDS):
                demisto.debug(
                    f"Pagination timeout reached after {PAGINATION_TIMEOUT_SECONDS} seconds. Received {len(all_issues)} issues."
                )
                break

            previous_cursor = next_page_cursor
            command_args = {"incident_id": incident_id, "page_size": ISSUE_LIST_PAGE_SIZE}
            if next_page_cursor:
                command_args["next_page_cursor"] = next_page_cursor
            command_result = demisto.executeCommand("contrastsecurity-issue-list", command_args)
            handle_error(command_result)

            contents = command_result[0].get("Contents") if command_result else None
            if not isinstance(contents, dict):
                # The command returns plain text when no issues are found
                contents = {}
            issues = contents.get("content") or []
            next_page_cursor = contents.get("cursor", "") if contents.get("hasMore") else ""

            all_issues.extend(issues)

            if len(issues) == 0 or not next_page_cursor or next_page_cursor == previous_cursor:
                break

        demisto.executeCommand("setIncident", {"contrastsecurityincidentrelatedissues": get_issues_grid_data(all_issues)})

        if not all_issues:
            return_results(CommandResults(readable_output=f"No issues found for incident ID: {incident_id}"))
        else:
            return_results(
                CommandResults(readable_output=f"Successfully retrieved {len(all_issues)} issue(s) for incident {incident_id}.")
            )

    except Exception as ex:
        demisto.error(traceback.format_exc())
        return_error(f"Failed to execute ContrastSecurityDisplayIncidentIssues. Error: {str(ex)}")


if __name__ in ("__main__", "__builtin__", "builtins"):  # pragma: no cover
    main()
