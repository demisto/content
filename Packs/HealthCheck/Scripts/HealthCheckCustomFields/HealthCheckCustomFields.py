import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

"""
Analyzes incident fields to identify custom field usage and script dependencies.
Uses /xsoar/sessionDataSync/incidentFields
"""
try:
    # Fetching all incident fields
    res = demisto.executeCommand(
        "core-api-get",
        {"uri": "/sessionDataSync/incidentFields", "body": {}},
    )

    if is_error(res):
        return_error(f"Failed to fetch incident fields: {get_error(res)}")

    fields = res[0].get("Contents", {}).get("response", [])
    if not isinstance(fields, list):
        # Fallback if response structure varies
        fields = res[0].get("Contents", {}).get("response", {}).get("reply", [])

    total_issue_fields = 0
    total_case_fields = 0
    custom_issue_fields_count = 0
    custom_case_fields_count = 0
    fields_with_scripts = 0

    for field in fields:
        field_name = field.get("id")

        if field_name.startswith("incident_"):
            total_issue_fields += 1
        elif field_name.startswith("case_"):
            total_case_fields += 1
        elif field_name.startswith("indicator_"):
            continue

        # Identifying Custom vs System
        is_system = field.get("system", True)
        is_xdr_builtin = field.get("XDRBuiltInField", True)
        is_content = field.get("content", True)

        if not is_system and not is_xdr_builtin and not is_content:
            if field_name.startswith("incident_"):
                custom_issue_fields_count += 1
            elif field_name.startswith("case_"):
                custom_case_fields_count += 1

        # Identifying Trigger Scripts
        change_script = field.get("script", "")

        if change_script:
            fields_with_scripts += 1

    # Calculations
    percentage_custom_issue = (custom_issue_fields_count / total_issue_fields * 100) if total_issue_fields > 0 else 0
    percentage_custom_case = (custom_case_fields_count / total_case_fields * 100) if total_case_fields > 0 else 0

    health_details = []
    health_details.append({"field": "Total Issue Fields", "value": total_issue_fields})
    health_details.append({"field": "Custom Issue Fields Count", "value": custom_issue_fields_count})
    health_details.append({"field": "Custom Issue Fields Percentage", "value": f"{round(percentage_custom_issue, 2)}%"})
    health_details.append({"field": "Total Case Fields", "value": total_case_fields})
    health_details.append({"field": "Custom Case Fields Count", "value": custom_case_fields_count})
    health_details.append({"field": "Custom Case Fields Percentage", "value": f"{round(percentage_custom_case, 2)}%"})
    health_details.append({"field": "Issue and Case Fields with Trigger Scripts", "value": fields_with_scripts})

    demisto.executeCommand("setIncident", {"healthcheckcustomfielddetails": health_details})

    return_results(CommandResults(readable_output="HealthCheckCustomFields Done"))

except Exception as e:
    return_error(f"Error in Custom Fields health logic: {str(e)}")
