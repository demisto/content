import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

"""
Analyzes automation scripts to identify custom script usage.
Uses /xsoar/cm/automation/search
"""
try:
    # Fetching all scripts using the search endpoint
    res = demisto.executeCommand(
        "core-api-post",
        {"uri": "/cm/automation/search", "body": {}},
    )

    if is_error(res):
        return_error(f"Failed to fetch scripts: {get_error(res)}")

    # The search endpoint returns a dictionary containing a 'scripts' list
    contents = res[0].get("Contents", {}).get("response", {})
    scripts = contents.get("scripts", [])
    if not isinstance(scripts, list):
        return_error("Unexpected response format: 'scripts' key not found or is not a list.")

    total_scripts = len(scripts)
    custom_scripts_count = 0
    detached_scripts_count = 0

    for script in scripts:
        is_system = script.get("system", True)
        is_detached = script.get("detached", True)

        if not is_system:
            custom_scripts_count += 1

        if is_detached:
            detached_scripts_count += 1

        # TBD - optional to filter by script tags (e.g., field-change, AI generated)

    # Calculations
    percentage_custom = (custom_scripts_count / total_scripts * 100) if total_scripts > 0 else 0
    percentage_detached = (detached_scripts_count / total_scripts * 100) if total_scripts > 0 else 0

    health_details = []
    health_details.append({"field": "Total Automation Scripts", "value": total_scripts})
    health_details.append({"field": "Custom Scripts Count", "value": custom_scripts_count})
    health_details.append({"field": "Custom Scripts Percentage", "value": f"{round(percentage_custom, 2)}%"})
    health_details.append({"field": "Detached Scripts Count", "value": detached_scripts_count})
    health_details.append({"field": "Detached Scripts Percentage", "value": f"{round(percentage_detached, 2)}%"})

    demisto.executeCommand("setIncident", {"healthcheckcustomscriptdetails": health_details})

    return_results(CommandResults(readable_output="HealthCheckCustomScripts Done"))

except Exception as e:
    return_error(f"Error in Custom Scripts health logic: {str(e)}")
