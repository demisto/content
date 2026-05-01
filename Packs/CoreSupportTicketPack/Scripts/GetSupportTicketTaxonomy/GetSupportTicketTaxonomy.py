import json

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def get_support_ticket_taxonomy() -> CommandResults:
    """Retrieves the complete support ticket taxonomy: all issue categories, their problem concentrations,
    and the questionnaire items for every combination.

    This is a single command that aggregates data from:
      1. /sfdc_support/get_sme_areas_and_sub_groups/

    Returns a nested structure grouped by issue_category → problem_concentration

    Args:
        client (Client): The client instance used to send the request.
        args (dict): Command arguments (none required).

    Returns:
        CommandResults: Object containing the full nested taxonomy data.

    """
    response = demisto._apiCall(
        method="GET",
        path="/api/webapp/sfdc_support/get_sme_areas_and_sub_groups",
    )

    reply = json.loads(response.get("data", "")).get("reply", {})

    taxonomy: list[dict] = []
    for area in reply:
        area_value = area.get("value", "")
        suggested_values = area.get("suggestedValues", [])

        # Extract only the 'value' string from each suggestedValue object
        problem_concentrations = [sg.get("value") for sg in suggested_values if sg.get("value")]

        category_entry = {area_value: problem_concentrations}

        taxonomy.append(category_entry)

    return CommandResults(
        outputs_prefix="Core.SupportTicketTaxonomy",
        outputs=str(taxonomy),
        raw_response=taxonomy,
    )


def main():  # pragma: no cover
    """Entry point for the GetSupportTicketTaxonomy script."""
    try:
        results = get_support_ticket_taxonomy()
        return_results(results)
    except Exception as e:
        return_error(f"Failed to get support ticket taxonomy: {e}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
