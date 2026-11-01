import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

"""
Analyzes widgets to count the number of custom widgets in the system.
Uses /public_api/v1/widgets/get
"""
try:
    # Fetching all widgets
    res = demisto.executeCommand(
        "core-api-post",
        {"uri": "/public_api/v1/widgets/get", "body": {"request_data": {}}},
    )

    if is_error(res):
        return_error(f"Failed to fetch widgets: {get_error(res)}")

    # The response is expected to contain the widget in the reply field
    response = res[0].get("Contents", {}).get("response") or {}
    widgets = response.get("reply", {}) if isinstance(response, dict) else response

    if not isinstance(widgets, dict):
        return_error("Unexpected response format: widgets list not found.")

    total_widgets = widgets.get("objects_count")

    health_details = total_widgets

    demisto.executeCommand("setIncident", {"healthcheckcustomwidgetcount": health_details})

    return_results(CommandResults(readable_output="HealthCheckWidgets Done"))

except Exception as e:
    return_error(f"Error in Widgets health logic: {str(e)}")
