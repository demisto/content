import json
from enum import Enum
import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections.abc import Callable
from typing import Any, Optional


class CloudTypes(Enum):
    AWS = "AWS"
    AZURE = "AZURE"
    GCP = "GCP"
    OCI = "OCI"


# Provider-specific account identifier names
PROVIDER_ACCOUNT_NAMES = {
    CloudTypes.GCP.value: "Project ID",
    CloudTypes.AWS.value: "AWS Account ID",
    CloudTypes.AZURE.value: "Subscription ID",
    CloudTypes.OCI.value: "Oracle Cloud Account ID",
}

# Platform API paths
GET_CTS_ACCOUNTS_TOKEN = "/cts/accounts/token"
GET_ONBOARDING_ACCOUNTS = "/onboarding/accounts"
GET_ONBOARDING_CONNECTORS = "/onboarding/connectors"


class HealthStatus(str, Enum):
    ERROR = "ERROR"
    WARNING = "WARNING"
    OK = "ok"


class ErrorType(str, Enum):
    CONNECTIVITY_ERROR = "ConnectivityError"
    PERMISSION_ERROR = "PermissionError"
    INTERNAL_ERROR = "InternalError"


class HealthCheckError:
    def __init__(self, account_id: str, connector_id: str, message: str, error_type: ErrorType):
        self.account_id = account_id
        self.connector_id = connector_id
        self.message = message
        self.error_type = error_type
        self.classification = HealthStatus.WARNING if self.error_type == ErrorType.PERMISSION_ERROR else HealthStatus.ERROR

    def to_dict(self) -> dict:
        # Determine classification based on error type

        return {
            "account_id": self.account_id,
            "connector_id": self.connector_id,
            "message": self.message,
            "error": self.error_type,
            "classification": self.classification,
        }


class HealthCheckResult:
    """Health check results container for cloud connector."""

    def __init__(self, connector_id: str):
        self.errors: list[HealthCheckError] = []
        self.connector_id = connector_id

    def error(self, error: HealthCheckError) -> None:
        """
        Adds a health check error to the results.

        Args:
            error (HealthCheckError): The error to add to the results.
        """
        self.errors.append(error)

    def summarize(self) -> CommandResults | str:
        """Summarizes the health check results by calculating severity based on error classifications.

        Returns:
            CommandResults | str:
                - If errors exist: CommandResults object with severity level and error details, otherwise "ok".
        """

        def _calculate_severity() -> int:
            """
            Calculates the severity level based on error classifications.
            """
            return EntryType.ERROR if HealthStatus.ERROR in [error.classification for error in self.errors] else EntryType.WARNING

        def _aggregate_error_messages(errors: list[HealthCheckError]) -> str:
            """
            Combines multiple error messages into a single string with line breaks.
            """
            return "\n".join([error.message for error in errors])

        def _aggregate_errors() -> list[dict]:
            """
            Aggregates errors by account and error type.
            """
            # Structure: {account_id: {error_type: [errors]}}
            aggregated_by_account_and_type = {}

            for error in self.errors:
                account_id = error.account_id
                error_type = error.error_type

                # Initialize nested dictionaries if they don't exist
                if account_id not in aggregated_by_account_and_type:
                    aggregated_by_account_and_type[account_id] = {}

                if error_type not in aggregated_by_account_and_type[account_id]:
                    aggregated_by_account_and_type[account_id][error_type] = []

                aggregated_by_account_and_type[account_id][error_type].append(error)

            aggregated_errors = []
            for account_id, error_types in aggregated_by_account_and_type.items():
                for error_type, errors in error_types.items():
                    combined_error = HealthCheckError(
                        account_id=account_id,
                        connector_id=self.connector_id,
                        message=_aggregate_error_messages(errors),
                        error_type=error_type,
                    )
                    aggregated_errors.append(combined_error.to_dict())

            return aggregated_errors

        return (
            CommandResults(entry_type=_calculate_severity(), content_format=EntryFormat.JSON, raw_response=_aggregate_errors())
            if self.errors
            else HealthStatus.OK
        )


def get_cloud_credentials(cloud_type: str, account_id: str, scopes: list = None) -> dict:
    """
    Retrieves valid credentials for the specified cloud provider from CTS.
    Args:
        cloud_type (str): Cloud provider type ("GCP", "AWS", "AZURE", "OCI").
        account_id (str): Cloud account identifier - GCP: Project ID, AWS: Account ID,
                          AZURE: Subscription ID
        scopes (list, optional): Authorization scopes. Defaults to None.
    Returns:
        dict: Credentials dictionary for the specified cloud provider. The structure varies by cloud type:
            - For all providers:
                - 'expiration_time' (int): Expiration time in epoch time (milliseconds)
            - For GCP:
                - 'access_token' (str): Bearer token
            - For AWS:
                - 'access_token' (str): SecretAccessKey
                - 'session_token' (str): SessionToken
                - 'key' (str): AccessKeyId
            - For AZURE:
                - 'access_token' (str): JWT
    Raises:
        DemistoException: If token retrieval fails or response parsing fails.
        ValueError: If account_id is not provided.
    """
    if not account_id:
        name = PROVIDER_ACCOUNT_NAMES.get(cloud_type, "account identifier")
        raise ValueError(f"Missing {name} for {cloud_type}")

    context = demisto.callingContext.get("context", {})
    cloud_info = context.get("CloudIntegrationInfo", {})

    demisto.info(f"Cloud credentials request context: {context}")

    request_data = {
        "connector_id": cloud_info.get("connectorID"),
        "account_id": account_id,
        "outpost_id": cloud_info.get("outpostID"),
        "cloud_type": cloud_type,
    }

    if scopes:
        request_data["scopes"] = scopes

    if cloud_type == CloudTypes.AWS.value and context.get("region_name"):
        request_data["region_name"] = context["region_name"]

    demisto.info(f"Request data for credentials retrieval: {request_data}")

    response = demisto._platformAPICall(path=GET_CTS_ACCOUNTS_TOKEN, method="POST", data={"request_data": request_data})

    status_code = response.get("status")
    if status_code != 200:
        error_detail = response.get("data", "No error message provided")
        raise DemistoException(
            f"Failed to get credentials from CTS for {cloud_type}. Status code: {status_code}. Error: {error_detail}"
        )

    try:
        res_json = json.loads(response["data"])
        credentials = res_json.get("data")
        if not credentials:
            raise KeyError("Did not receive any credentials from CTS.")
        expiration_time = credentials.get("expiration_time")
        demisto.info(f"Received credentials. Expiration time: {expiration_time}")
        return credentials
    except (
        json.JSONDecodeError,
        KeyError,
        TypeError,
    ) as e:
        raise DemistoException(f"Failed to parse credentials from CTS response for {cloud_type}.") from e


def get_accounts_by_connector_id(connector_id: str, max_results: int = None) -> list:
    """
    Retrieves the accounts associated with a specific connector with pagination support.
    Args:
        connector_id (str): The ID of the connector to fetch accounts for.
        max_results (int, optional): Maximum number of results to return. Defaults to None (all results).
    Returns:
        list: List of accounts associated with the specified connector.
    """
    all_accounts = []
    next_token = ""
    while True:
        params = {"entity_type": "connector", "entity_id": connector_id}
        if next_token:
            params["next_token"] = next_token

        result = demisto._platformAPICall(GET_ONBOARDING_ACCOUNTS, "GET", params)
        res_json = json.loads(result["data"])

        accounts = res_json.get("values", [])
        all_accounts.extend(accounts)

        next_token = res_json.get("next_token", "")
        if not next_token or (max_results and len(all_accounts) >= max_results):
            break

    if max_results:
        return all_accounts[:max_results]
    return all_accounts


def _check_account_permissions(
    account: dict, connector_id: str, permission_check_func: Callable[[str, str], HealthCheckError]
) -> HealthCheckError | None:
    """
    Helper function to check permissions for a single account.
    Args:
        account (dict): Account information.
        connector_id (str): The connector ID.
        permission_check_func (callable): Function that implements the permission check.
    Returns:
        Any: Result of the permission check.
    """
    account_id = account.get("account_id")
    if not account_id:
        demisto.debug(f"Account without ID found for connector {connector_id}: {account}")
        return None

    try:
        return permission_check_func(account_id, connector_id)
    except Exception as e:
        demisto.error(f"Error checking permissions for account {account_id}: {str(e)}")
        return HealthCheckError(
            account_id=account_id,
            connector_id=connector_id,
            message=f"Failed to check permissions: {str(e)}",
            error_type=ErrorType.INTERNAL_ERROR,
        )


def run_permissions_check_for_accounts(
    connector_id: str, permission_check_func: Callable[[str, str], Any], max_workers: Optional[int] = 10
) -> str | CommandResults:
    """
    Runs a permission check function for each account associated with a connector concurrently.
    Args:
        connector_id (str): The ID of the connector to fetch accounts for.
        permission_check_func (callable): Function that implements the permission check.
                                         Should accept account_id and connector_id parameters
                                         and return a HealthCheckResult.
        max_workers (int, optional): Maximum number of worker threads. Defaults to 10.
    Returns:
        Either "ok" string or CommandResults with appropriate EntryType
    Raises:
        DemistoException: If the account retrieval fails.
    """
    accounts = get_accounts_by_connector_id(connector_id)

    if not accounts:
        demisto.debug(f"No accounts found for connector ID: {connector_id}")
        return HealthStatus.OK

    health_check_result = HealthCheckResult(connector_id)
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_account = {
            executor.submit(_check_account_permissions, account, connector_id, permission_check_func): account
            for account in accounts
        }

        for future in as_completed(future_to_account):
            result = future.result()
            if result is not None:
                health_check_result.error(result)

    # Process the results to get one entry per account with the most severe error
    return health_check_result.summarize()
