import ast
import json

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

def core_fill_support_ticket(args: dict[str, Any]) -> CommandResults:
    """
    Validates arguments and maps them to the support ticket context.
    Includes dependent validation for problem_concentration based on the issue_category.
    """

    demisto.debug(f"core_fill_support_ticket : {args}")
    start_time = args.get("most_recent_issue_start_time")

    issue_category = args.get("issue_category")
    problem_concentration = args.get("problem_concentration")

    start_time_dt = arg_to_datetime(start_time) if start_time else None
    data = {
        "description": args.get("description"),
        "contactNumber": args.get("contact_number"),
        "OngoingIssue": args.get("issue_frequency"),
        "DateTimeOfIssue": start_time_dt.timestamp() if start_time_dt else None,
        "IssueImpact": args.get("issue_impact"),
        "smeArea": issue_category,
        "subGroupName": problem_concentration,
    }

    return CommandResults(
        outputs_prefix="Core.SupportTicket",
        outputs=data,
        raw_response=data,
    )

def main():  # pragma: no cover
    try:
        args = demisto.args()
        result = core_fill_support_ticket(args)
        return_results(result)
    except Exception as e:
        return_error(f"Failed to fill support ticket: {e}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
