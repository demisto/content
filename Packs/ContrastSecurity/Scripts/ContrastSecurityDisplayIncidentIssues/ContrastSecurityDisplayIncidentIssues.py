import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import traceback
import json
from datetime import datetime, UTC
from typing import Any


def handle_error(command_result: dict[str, Any]) -> None:
    """Handle error in command result and exit."""
    if is_error(command_result):
        return_error(command_result.get("Contents", "Unknown error"))


def get_issues_grid_data(issues_data: list) -> list:
    """
    Convert incident issues into grid field format for XSOAR incident layout.

    Args:
        issues_data (list): List of issue objects from the API response.

    Returns:
        list: List of dicts with keys matching the grid field column IDs.
    """
    grid_rows = []
    for issue in issues_data:
        grid_rows.append(
            {
                "cvssScore": issue.get("cvssScore", ""),
                "title": issue.get("title", ""),
                "issueId": issue.get("issueId", ""),
                "issueLink": issue.get("issueLink", ""),
                "status": issue.get("status", ""),
                "applicationName": issue.get("applicationName", ""),
                "observationCount": str(issue.get("observationCount", "")),
                "lastAttackedAt": issue.get("lastAttackedAt", ""),
                "lastObservationAt": issue.get("lastObservationAt", ""),
                "cvssVector": issue.get("cvssVector", ""),
                "ruleId": issue.get("ruleId", ""),
                "deploymentTier": ", ".join(issue.get("deploymentTier", [])) if issue.get("deploymentTier") else "",
            }
        )
    return grid_rows


def main():
    try:
        incident_id = demisto.getArg("incident_id")

        if not incident_id:
            return_results(CommandResults(readable_output="##### Contrast Security Incident ID not found."))
            return

        all_issues: list = []
        current_page = 0
        page_size = 100
        timeout_seconds = 240
        loop_start_time = datetime.now(UTC).isoformat()

        while True:
            if has_passed_time_threshold(loop_start_time, timeout_seconds):
                demisto.debug(
                    f"Pagination timeout reached after {timeout_seconds} seconds. "
                    f"Received {len(all_issues)} issues from {current_page} page(s)."
                )
                break

            command_args = {"incident_id": incident_id, "page_size": page_size, "page": current_page}
            command_result = demisto.executeCommand("contrastsecurity-issue-list", command_args)
            handle_error(command_result)

            issues = []
            page_info = {}
            if command_result and len(command_result) > 0:
                entry = command_result[0]
                contents = entry.get("Contents") or {}
                issues = contents.get("content", [])
                page_info = contents.get("page", {})

            all_issues.extend(issues)

            total_pages = page_info.get("totalPages", 1)
            total_elements = page_info.get("totalElements", 0)
            if current_page >= total_pages - 1 or len(issues) == 0 or total_elements == len(all_issues):
                break

            current_page += 1

        demisto.executeCommand(
            "setIncident", {"contrastsecurityincidentrelatedissues": json.dumps(get_issues_grid_data(all_issues))}
        )

        if not all_issues:
            return_results(CommandResults(readable_output=f"No issues found for incident ID: {incident_id}"))
        else:
            return_results(
                CommandResults(readable_output=f"Successfully retrieved {len(all_issues)} issue(s) for incident {incident_id}.")
            )

    except Exception as ex:
        demisto.error(traceback.format_exc())
        return_error(f"Failed to execute ContrastSecurityDisplayIncidentIssues. Error: {str(ex)}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
