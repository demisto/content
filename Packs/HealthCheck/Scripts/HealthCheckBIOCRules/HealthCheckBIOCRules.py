import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

"""
Count the number of BIOC Rules in the system.
Uses /public_api/v1/bioc/get
"""
try:
    # Fetching all BIOCs
    res = demisto.executeCommand(
        "core-api-post",
        {"uri": "/public_api/v1/bioc/get", "body": {"request_data": {}}},
    )

    if is_error(res):
        return_error(f"Failed to fetch BIOCs: {get_error(res)}")

    # The response is expected to contain the BIOC in the reply field
    biocs = res[0].get("Contents", {}).get("response", {})

    if not isinstance(biocs, dict):
        # Fallback for alternative response structures
        biocs = res[0].get("Contents", {}).get("response", {}).get("reply", {})
        if not isinstance(biocs, dict):
            return_error("Unexpected response format: BIOCs list not found.")

    total_biocs = biocs.get("objects_count")

    health_details = total_biocs

    demisto.executeCommand("setIncident", {"healthcheckbiocscount": health_details})

    return_results(CommandResults(readable_output="HealthCheckBIOCs Done"))

except Exception as e:
    return_error(f"Error in BIOC health logic: {str(e)}")
