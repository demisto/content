
import json

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def get_access_token(cloud_type: str, scopes: list = None) -> str:
    """
    Retrieves a valid access token for the specified cloud provider from CTS.

    Args:
        cloud_type (str, optional): Cloud provider type ("GCP", "AWS", "Azure"). Defaults to "GCP".
        scopes (list, optional): Authorization scopes to request. Uses defaults if not provided.

    Returns:
        str: Access token for the specified cloud provider.

    Raises:
        DemistoException: If token retrieval fails.
    """
    # Get context values
    context = demisto.callingContext.get("context", {})
    request_data = {
        "connector_id": context.get("connector_id"),
        "account_id": context.get("account_id"),
        "outpost_id": context.get("outpost_id"),
        "cloud_type": cloud_type,
        "scopes": scopes or []
    }
    # Add region_name for AWS if available in context
    if cloud_type == "AWS" and context.get("region_name"):
        request_data["region_name"] = context.get("region_name")

    # Make the API call to get the token
    result = demisto._platformAPICall(
        "/cts/accounts/token",
        "POST",
        {
            "request_data": request_data
        }
    )

    if result.get("status_code") != 200:
        raise DemistoException(
            f'Failed to get token from CTS for {cloud_type}. Error code: {result.get("status_code")}')  # TODO - Add error details

    try:
        return json.loads(result.get("data")).get("access_token")
    except json.JSONDecodeError as e:
        raise DemistoException(
            f"Failed to parse token response for {cloud_type}"
        ) from e
