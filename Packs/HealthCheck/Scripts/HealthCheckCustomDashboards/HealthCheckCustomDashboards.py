import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

"""
Analyzes dashboards to count the number of custom dashboards in the system.
Uses /public_api/v1/dashboards/get
"""
try:
    # Fetching all dashboards
    res = demisto.executeCommand(
        "core-api-post",
        {"uri": "/public_api/v1/dashboards/get", "body": {"request_data": {}}},
    )

    if is_error(res):
        return_error(f"Failed to fetch dashboards: {get_error(res)}")

    # The response is expected to contain the dashboards in the reply field
    response = res[0].get("Contents", {}).get("response") or {}
    dashboards = response.get("reply", {}) if isinstance(response, dict) else response

    if not isinstance(dashboards, dict):
        return_error("Unexpected response format: dashboards list not found.")

    total_dashboards = dashboards.get("objects_count")

    health_details = total_dashboards

    demisto.executeCommand("setIncident", {"healthcheckcustomdashboardcount": health_details})

    return_results(CommandResults(readable_output="HealthCheckDashboards Done"))

except Exception as e:
    return_error(f"Error in Dashboards health logic: {str(e)}")
