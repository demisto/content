import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

"""
Analyzes layouts to identify custom layout usage and dynamic script dependencies.
Uses /xsoar/sessionDataSync/layouts
"""
try:
    # Fetching all layouts
    res = demisto.executeCommand(
        "core-api-get",
        {"uri": "/sessionDataSync/layouts", "body": {}},
    )

    if is_error(res):
        return_error(f"Failed to fetch layouts: {get_error(res)}")

    layouts = res[0].get("Contents", {}).get("response", [])
    if not isinstance(layouts, list):
        # Fallback if response structure varies
        layouts = res[0].get("Contents", {}).get("response", {}).get("reply", [])

    total_issue_layouts = 0
    total_case_layouts = 0
    custom_issue_layouts_count = 0
    custom_case_layouts_count = 0

    for layout in layouts:
        group = layout.get("group", "").lower()

        if group == "incident":
            total_issue_layouts += 1
        elif group == "case":
            total_case_layouts += 1
        elif group == "indicator":
            continue

        # Identifying Custom vs System
        # Following the logic: system == False and not part of a content pack/built-in
        is_system = layout.get("system", True)
        has_pack = bool(layout.get("packID"))

        if not is_system and not has_pack:
            if group == "incident":
                custom_issue_layouts_count += 1
            elif group == "case":
                custom_case_layouts_count += 1

    # Calculations
    percentage_custom_issue = (custom_issue_layouts_count / total_issue_layouts * 100) if total_issue_layouts > 0 else 0
    percentage_custom_case = (custom_case_layouts_count / total_case_layouts * 100) if total_case_layouts > 0 else 0

    health_details = []
    health_details.append({"field": "Total Issue Layouts", "value": total_issue_layouts})
    health_details.append({"field": "Custom Issue Layouts Count", "value": custom_issue_layouts_count})
    health_details.append({"field": "Custom Issue Layouts Percentage", "value": f"{round(percentage_custom_issue, 2)}%"})
    health_details.append({"field": "Total Case Layouts", "value": total_case_layouts})
    health_details.append({"field": "Custom Case Layouts Count", "value": custom_case_layouts_count})
    health_details.append({"field": "Custom Case Layouts Percentage", "value": f"{round(percentage_custom_case, 2)}%"})

    demisto.executeCommand("setIncident", {"healthcheckcustomlayoutdetails": health_details})

    return_results(CommandResults(readable_output="HealthCheckCustomLayouts Done"))

except Exception as e:
    return_error(f"Error in Custom Layouts health logic: {str(e)}")
