from enum import Enum
import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from collections.abc import Callable
from typing import Any
import requests


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


class HealthStatus(str):
    ERROR = "ERROR"
    WARNING = "WARNING"
    OK = "ok"


class ErrorType(str):
    CONNECTIVITY_ERROR = "Connectivity Error"
    PERMISSION_ERROR = "Permission Error"
    INTERNAL_ERROR = "Internal Error"


class HealthCheckError:
    def __init__(self, account_id: str, connector_id: str, message: str, error_type: str):
        self.account_id = account_id
        self.connector_id = connector_id
        self.message = message
        self.error_type = error_type
        # Determine classification based on error type
        self.classification = HealthStatus.WARNING if self.error_type == ErrorType.PERMISSION_ERROR else HealthStatus.ERROR

    def to_dict(self) -> dict:
        return {
            "account_id": self.account_id,
            "connector_id": self.connector_id,
            "message": self.message,
            "error": self.error_type,
            "classification": self.classification,
        }


class HealthCheck:
    """Health check results container for cloud connector."""

    def __init__(self, connector_id: str):
        self.errors: list[HealthCheckError] = []
        self.connector_id = connector_id

    def error(self, error: HealthCheckError | list[HealthCheckError]) -> None:
        """Adds a health check error or list of errors to the results.

        Args:
            error (HealthCheckError | list[HealthCheckError]): The error(s) to add to the results.
        """
        if isinstance(error, list):
            self.errors.extend(error)
        else:
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

        if not self.errors:
            return HealthStatus.OK

        error_list = [error.to_dict() for error in self.errors]
        return CommandResults(entry_type=_calculate_severity(), content_format=EntryFormat.JSON, raw_response=error_list)


def get_connector_id() -> str | None:
    """
    Retrieves the connector ID from the calling context.

    This function extracts the connector ID from the CloudIntegrationInfo in the calling context.

    Returns:
        str | None: The connector ID if available in the context, otherwise None.
    """
    cloud_info_context = demisto.callingContext.get("context", {}).get("CloudIntegrationInfo", {})
    demisto.debug(f"[COOC API] Cloud credentials request context: {cloud_info_context}")

    if connector_id := cloud_info_context.get("connectorID"):
        demisto.debug(f"[COOC API] Retrieved connector ID from context: {connector_id}")
    else:
        demisto.debug("[COOC API] No connector ID found in context")

    return connector_id


def get_cloud_credentials(cloud_type: str, account_id: str, scopes: list = None) -> dict:
    """Retrieves valid credentials for the specified cloud provider from CTS.

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

    cloud_info_context = demisto.callingContext.get("context", {}).get("CloudIntegrationInfo", {})

    request_data = {
        "connector_id": cloud_info_context.get("connectorID"),
        "account_id": account_id,
        "outpost_id": cloud_info_context.get("outpostID"),
        "cloud_type": cloud_type,
    }

    if scopes:
        request_data["scopes"] = scopes

    demisto.debug(f"[COOC API] Request data for credentials retrieval: {request_data}")
    response = None

    try:
        response = demisto._platformAPICall(path=GET_CTS_ACCOUNTS_TOKEN, method="POST", data={"request_data": request_data})
        raw_data = response.get("data")

        if not raw_data:
            raise ValueError(f"No 'data' field in CTS response: {response}")

        if isinstance(raw_data, str):
            res_json = json.loads(raw_data)
        elif isinstance(raw_data, dict):
            res_json = raw_data
        else:
            raise ValueError(f"Unexpected type for response['data']: {type(raw_data)}")

        credentials = res_json.get("data")
        if not credentials:
            raise KeyError("Did not receive any credentials from CTS.")

        expiration_time = credentials.get("expiration_time")
        demisto.debug(f"[COOC API] {account_id}: Received credentials. Expiration time: {expiration_time}")
        return credentials

    except Exception as e:
        demisto.debug(f"[COOC API] {account_id}: Error while retrieving credentials: {str(e)}. Response: {response}")
        raise DemistoException(f"Failed to get credentials from CTS: {str(e)}. Response: {response}")


def get_accounts_by_connector_id(connector_id: str, max_results: int | None = 1) -> list:
    """
    Retrieves the accounts associated with a specific connector with pagination support.
    Args:
        connector_id (str): The ID of the connector to fetch accounts for.
        max_results (int, optional): Maximum number of results to return. Defaults to None (all results).
    Returns:
        list: List of accounts (only of type ACCOUNT) associated with the specified connector.
    """
    all_accounts = []
    next_token = ""
    try:
        while True:
            params = {"entity_type": "connector", "entity_id": connector_id}
            if next_token:
                params["next_token"] = next_token

            result = demisto._platformAPICall(GET_ONBOARDING_ACCOUNTS, "GET", params)
            res_json = json.loads(result["data"])
            accounts = res_json.get("values", [])
            all_accounts.extend([a for a in accounts if a.get("account_type") == "ACCOUNT" and a.get("account_id")])
            next_token = res_json.get("next_token", "")
            if not next_token or (max_results and len(all_accounts) >= max_results):
                break
    except Exception as e:
        raise DemistoException(f"Failed to fetch accounts for connector: {str(e)}")

    if max_results:
        return all_accounts[:max_results]
    return all_accounts


def _check_account(
    account_id: str, connector_id: str, shared_creds: dict, health_check_func: Callable[[dict, str, str], HealthCheckError]
) -> HealthCheckError | None:
    """Helper function to check a single account.

    Args:
        account_id (str): The Account ID.
        connector_id (str): The connector ID.
        shared_creds (dict): Pre-fetched credentials to reuse across all accounts.
        health_check_func (callable): Function that implements the health check.

    Returns:
        HealthCheckError | None: Result of the health check, or None if account has no ID.
    """

    try:
        return health_check_func(shared_creds, account_id, connector_id)
    except Exception as e:
        demisto.error(f"[COOC API] Error checking account {account_id}: {str(e)}")
        return HealthCheckError(
            account_id=account_id,
            connector_id=connector_id,
            message=f"Failed to check account: {str(e)}",
            error_type=ErrorType.INTERNAL_ERROR,
        )


def run_health_check_for_accounts(
    connector_id: str, cloud_type: str, health_check_func: Callable[[dict, str, str], Any]
) -> str | CommandResults:
    """Runs a health check function for each account associated with a connector sequentially.

    Args:
        connector_id (str): The ID of the connector to fetch accounts for.
        cloud_type (str): The cloud provider type (AWS, GCP, AZURE, OCI).
        health_check_func (callable): Function that implements the health check.
                                        Should accept shared_creds, account_id and connector_id parameters
                                        and return a HealthCheckError or None.

    Returns:
        str | CommandResults: Either "ok" string or CommandResults with appropriate EntryType

    Raises:
        DemistoException: If the account retrieval fails.
    """
    health_check_result = HealthCheck(connector_id)
    try:
        accounts = get_accounts_by_connector_id(connector_id)
        if not accounts:
            demisto.debug(f"[COOC API] No accounts found for connector ID: {connector_id}")
            return HealthStatus.OK

        account_id = accounts[0]["account_id"]
        shared_creds = get_cloud_credentials(cloud_type, account_id)
        demisto.debug(f"[COOC API] Retrieved shared {cloud_type} credentials for all accounts")

    except Exception as e:
        error_msg = f"Failed to retrieve {cloud_type} credentials for connector {connector_id}: {str(e)}"
        demisto.error(error_msg)
        health_check_result.error(
            HealthCheckError(
                account_id="",  # No specific account since this is a connector-level error
                connector_id=connector_id,
                message=error_msg,
                error_type=ErrorType.CONNECTIVITY_ERROR,
            )
        )
        return health_check_result.summarize()

    result = _check_account(account_id, connector_id, shared_creds, health_check_func)
    if result is not None:
        health_check_result.error(result)

    demisto.debug(f"[COOC API] Completed processing {account_id}")
    return health_check_result.summarize()


def get_proxydome_token() -> str:
    """
    Retrieves a Proxydome identity token from the GCP metadata server.

    This function makes a request to the GCP metadata server to obtain an identity token
    that can be used for authentication with Proxydome services. It bypasses any configured
    proxies for this request.

    Returns:
        str: The identity token as a string.

    Raises:
        requests.RequestException: If the request to the metadata server fails.
    """
    url = "http://metadata/computeMetadata/v1/instance/service-accounts/default/identity"
    params = {"audience": os.getenv("CORTEX_AUDIENCE")}
    headers = {"Metadata-Flavor": "Google"}
    proxies = {"http": "", "https": ""}

    response = requests.get(url, headers=headers, params=params, proxies=proxies)
    return response.text


def return_multiple_permissions_error(error_entries: list[Dict]) -> None:
    """
    Handles permission errors responses and exits the script execution.

    This function logs permission errors, formats them as Demisto error entries,
    and terminates script execution. It's used when cloud operations fail due to
    insufficient permissions or authentication issues.

    Args:
        error_entries (list): List of dictionaries containing error details with the following structure:
            - account_id (str): The cloud account identifier where the error occurred
            - message (str): The permission error message (including the name of the permission)
            - name (str): The RAW name of the permission itself that is missing, for example containers.list"

    Returns:
        None: This function does not return as it calls sys.exit(0)
    """
    # Input validation
    entries = []
    for entry in error_entries:
        error_entry = create_permissions_error_entry(entry.get("account_id"), entry.get("message"), entry.get("name"))
        entries.append(error_entry)
        # Log the permission error for security audit purposes
        demisto.debug(f"[COOC API] Permission error detected for account {error_entry.get('account_id')}: {error_entry}")

    # Return formatted error response
    demisto.results(
        {
            "Type": entryTypes["error"],
            "ContentsFormat": formats["json"],
            "Contents": entries,
            "EntryContext": None,
        }
    )
    # Exit the script execution
    sys.exit(0)


def create_permissions_error_entry(account_id: Optional[str], message: Optional[str], name: Optional[str]) -> dict:
    """
    Creates a standardized error entry dictionary for permission-related errors.

    This function constructs a formatted error entry containing permission error details
    that can be used for logging and error handling in cloud operations. It validates
    input parameters and creates a consistent error structure.

    Args:
        account_id (Optional[str]): The cloud account identifier where the error occurred
        message (Optional[str]): The permission error message (including the name of the permission)
        name (Optional[str]): The RAW name of the permission itself that is missing, for example containers.list

    Returns:
        dict: A dictionary containing structured error information with keys:
            - account_id: The provided account identifier
            - message: The error message
            - name: The permission name
            - classification: Set to "WARNING"
            - error: Set to "Permission Error"
    """
    # Input validation
    error_entry = {"account_id": account_id, "message": message, "name": name}
    for var_name, var_value in error_entry.items():
        if not var_value or (isinstance(var_value, str) and not var_value.strip()):
            error_entry.update({var_name: "N/A"})
            demisto.info(f"[COOC API] Invalid entry was given to the permissions entry {var_name=}:{var_value=}.")

    error_entry.update({"classification": "WARNING", "error": "Permission Error"})
    # Log the permission error for security audit purposes
    demisto.debug(f"[COOC API] Permission error detected for account {error_entry.get('account_id')}: {error_entry}")

    # Return formatted error response
    return error_entry


def is_gov_account(connector_id: str, account_id: str) -> bool:
    """
    Return whether the account connected to the connector_id is a gov account or not.

    Args:
        connector_id (str): The connector id of the cloud provider.
        account_id (str): The relevant account id

    Returns:
        A boolean representing whether the account is a gov account or not.
    """
    accounts_info = get_accounts_by_connector_id(connector_id, None)  # return all accounts with max_results = None

    relevant_account = {}
    for account in accounts_info:
        if account.get("account_id") == account_id:
            relevant_account = account
            demisto.debug("found the account")
            break

    demisto.debug(f"{relevant_account.get('cloud_partition')=}")
    if account_cloud_partition := relevant_account.get("cloud_partition", ""):
        return account_cloud_partition.upper() == "GOV"
    else:
        demisto.debug(f"No account found with account_id: {account_id}, or no cloud_partition.")
        return False
