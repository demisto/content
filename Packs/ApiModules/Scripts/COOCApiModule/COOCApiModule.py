import json
from enum import Enum

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


# Cloud provider types
class CloudTypes(Enum):
    AWS = "AWS"
    AZURE = "AZURE"
    GCP = "GCP"
    OCI = "OCI"


# Platform API paths
GET_CTS_ACCOUNTS_TOKEN = "/cts/accounts/token"
GET_ONBOARDING_ACCOUNTS = "/onboarding/accounts"
GET_ONBOARDING_CONNECTORS = "/onboarding/connectors"


def get_access_token(cloud_type: str, scopes: list = None) -> str:
    """
    Retrieves a valid access token for the specified cloud provider from CTS.

    Args:
        cloud_type (str): Cloud provider type ("GCP", "AWS", "AZURE", "OCI").
        scopes (list, optional): Authorization scopes. Defaults to an empty list.

    Returns:
        str: Access token for the specified cloud provider.

    Raises:
        DemistoException: If token retrieval fails or response parsing fails.
    """
    context = demisto.callingContext.get("context", {})
    cloud_info = context.get("CloudIntegrationProviderInfo", {})

    demisto.info(f"Access token request context: {context}")

    request_data = {
        "connector_id": cloud_info.get("connectorID"),
        "account_id": cloud_info.get("accountID"),
        "outpost_id": cloud_info.get("outpostID"),
        "cloud_type": cloud_type,
    }

    if scopes:
        request_data["scopes"] = scopes

    if cloud_type == CloudTypes.AWS.value and context.get("region_name"):
        request_data["region_name"] = context["region_name"]

    demisto.info(f"Request data for token retrieval: {request_data}")

    response = demisto._platformAPICall(path=GET_CTS_ACCOUNTS_TOKEN, method="POST", data={"request_data": request_data})

    status_code = response.get("status")
    if status_code != 200:
        error_detail = response.get("data", "No error message provided")
        raise DemistoException(
            f"Failed to get token from CTS for {cloud_type}. " f"Status code: {status_code}. Error: {error_detail}"
        )

    try:
        res_json = json.loads(response["data"])
        token_data = res_json.get("data", {})
        access_token = token_data["access_token"]
        expiration_time = token_data.get("expiration_time")
        demisto.info(f"Received access token. Expiration time: {expiration_time}")
        return access_token
    except (json.JSONDecodeError, KeyError, TypeError) as e:
        raise DemistoException(f"Failed to parse access token from CTS response for {cloud_type}.") from e


def get_cloud_entities(connector_id: str = None, account_id: str = None) -> dict:
    """
    Retrieves cloud entities based on the provided ID.
    If connector_id is provided, returns accounts associated with that connector.
    If account_id is provided, returns connectors associated with that account.

    Args:
        connector_id (str, optional): The ID of the connector to fetch accounts for.
        account_id (str, optional): The ID of the account to fetch connectors for.

    Returns:
        dict: Response containing the requested entities.

    Raises:
        DemistoException: If the API call fails.
        ValueError: If neither connector_id nor account_id is provided, or if both are provided.
    """
    if bool(connector_id) == bool(account_id):  # ensures one and only one is provided
        raise ValueError("Exactly one of connector_id or account_id must be provided.")

    entity_type, entity_id, path = (
        ("account", connector_id, GET_ONBOARDING_ACCOUNTS)
        if connector_id
        else ("connector", account_id, GET_ONBOARDING_CONNECTORS)
    )

    response = demisto._platformAPICall(path=path, method="GET", params={"entity_type": entity_type, "entity_id": entity_id})

    status_code = response.get("status_code")
    if status_code != 200:
        error_detail = response.get("data") or "No error message provided"
        raise DemistoException(
            f"Failed to get {entity_type}s for ID '{entity_id}'. " f"Status code: {status_code}. Detail: {error_detail}"
        )

    return response
