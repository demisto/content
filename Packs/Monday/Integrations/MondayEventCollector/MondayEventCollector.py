import hashlib
import json
import demistomock as demisto  # noqa: F401
from CommonServerPython import *
import urllib3
from dateutil import parser


# Disable insecure warnings
urllib3.disable_warnings()

""" CONSTANTS """

VENDOR = "Monday"
PRODUCT = "Monday"

# Event type string as appears in the yml file
AUDIT_LOGS_TYPE = "Audit Logs"
ACTIVITY_LOGS_TYPE = "Activity Logs"

REDIRECT_URI = "https://localhost"
AUTH_URL = "https://auth.monday.com/oauth2/token"

# API limitations
MAX_AUDIT_LOGS_PER_PAGE = 1000
MAX_ACTIVITY_LOGS_PER_PAGE = 10000

# Integration limitations as appears in yml file
MAX_AUDIT_LOGS_PER_FETCH = 5000
MAX_ACTIVITY_LOGS_PER_FETCH = 10000

DATE_FORMAT = "%Y-%m-%dT%H:%M:%SZ"

START_FETCH_TIME = 60 * 1000

# Debug prefixes - used for logger messages
AUDIT_LOG_DEBUG_PREFIX = "Audit Logs- MondayEventCollector Debug Message:\n"
ACTIVITY_LOG_DEBUG_PREFIX = "Activity Logs- MondayEventCollector Debug Message:\n"
DEBUG_PREFIX = "MondayEventCollector Debug Message:\n"


""" CLIENT CLASS """


class ActivityLogsClient(BaseClient):
    """
    Client for Monday.com Activity Logs API using OAuth 2.0 authentication.
    Extends BaseClient to support proxy configuration and proper HTTP request handling.
    """

    def __init__(
        self, client_id: str, client_secret: str, auth_code: str, activity_logs_url: str, proxy: bool = False, verify: bool = True
    ):
        """
        Initialize ActivityLogsClient with OAuth 2.0 credentials and configuration.

        Args:
            client_id (str): Monday.com OAuth 2.0 client ID
            client_secret (str): Monday.com OAuth 2.0 client secret
            auth_code (str): Authorization code from OAuth 2.0 flow
            activity_logs_url (str): Base URL for Monday.com activity logs API
            proxy (bool): Whether to use proxy for requests
            verify (bool): Whether to verify SSL certificates
        """
        # Use the activity logs URL as base URL, we'll construct full URLs in methods
        super().__init__(base_url=activity_logs_url, verify=verify, proxy=proxy)
        self.client_id = client_id
        self.client_secret = client_secret
        self.auth_code = auth_code
        self.activity_logs_url = activity_logs_url

    def get_access_token_request(self) -> str:
        """
        Exchange authorization code for access token using Monday.com OAuth 2.0 flow.

        Returns:
            str: Access token for Monday.com API authentication
        """
        payload = {
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "code": self.auth_code,
            "redirect_uri": REDIRECT_URI,
        }
        headers = {"Content-Type": "application/x-www-form-urlencoded"}

        response = self._http_request(method="POST", full_url=AUTH_URL, headers=headers, data=payload, resp_type="json")

        access_token = response.get("access_token")
        if not access_token:
            demisto.debug(f"{DEBUG_PREFIX}Response missing access_token")
            raise DemistoException("Response missing access_token")

        return access_token

    def get_activity_logs_request(self, query: str, access_token: str) -> dict:
        """
        Send GraphQL request to fetch activity logs from Monday.com API.

        Args:
            query (str): GraphQL query string
            access_token (str): OAuth 2.0 access token

        Returns:
            dict: Response from Monday.com API containing activity logs
        """
        demisto.debug(f"{ACTIVITY_LOG_DEBUG_PREFIX}Requesting activity logs\nQuery: {query}")

        headers = {"Authorization": f"Bearer {access_token}", "Content-Type": "application/json"}

        response = self._http_request(
            method="POST",
            url_suffix="v2",
            headers=headers,
            json_data={"query": query},
            resp_type="json",
        )

        return response

    def check_empty_page(self, query: str, access_token: str) -> bool:
        """
        Check if a GraphQL query returns an empty page of results.

        Args:
            query (str): GraphQL query string
            access_token (str): OAuth 2.0 access token

        Returns:
            bool: True if the page is empty, False otherwise
        """
        try:
            response = self.get_activity_logs_request(query, access_token)
            logs = response["data"]["boards"][0].get("activity_logs", [])
            return not logs
        except Exception as e:
            demisto.debug(f"{ACTIVITY_LOG_DEBUG_PREFIX}Error checking empty page: {str(e)}")
            return True


class AuditLogsClient(BaseClient):
    """
    Client for Monday.com Audit Logs API using API token authentication.
    Extends BaseClient to support proxy configuration and proper HTTP request handling.
    """

    def __init__(self, audit_token: str, audit_logs_url: str, proxy: bool = False, verify: bool = True):
        """
        Initialize AuditLogsClient with API token and configuration.

        Args:
            audit_token (str): Monday.com API token for audit logs
            audit_logs_url (str): Base URL for Monday.com audit logs API
            proxy (bool): Whether to use proxy for requests
            verify (bool): Whether to verify SSL certificates
        """
        super().__init__(base_url=audit_logs_url, verify=verify, proxy=proxy)
        self.audit_token = audit_token
        self.audit_logs_url = audit_logs_url

    def get_audit_logs_request(self, time_filter: str, page: int, per_page: int) -> dict:
        """
        Send GET request to fetch audit logs from Monday.com API.

        Args:
            time_filter (str): JSON string with start_time and end_time filters
            page (int): Page number for pagination
            per_page (int): Number of logs per page

        Returns:
            dict: Response from Monday.com API containing audit logs
        """
        headers = {"Authorization": f"Bearer {self.audit_token}", "Content-Type": "application/json"}

        params = {"filters": time_filter, "page": page, "per_page": per_page}

        demisto.debug(f"{AUDIT_LOG_DEBUG_PREFIX}Requesting audit logs\nParams: {params}")

        response = self._http_request(
            method="GET", url_suffix="audit-api/get-logs", headers=headers, params=params, resp_type="json"
        )

        return response


def generate_login_url() -> CommandResults:
    """
    Generate OAuth 2.0 authorization URL for Monday.com authentication to grant permissions to the Cortex XSOAR integration.

    Returns:
        CommandResults: Command result containing the authorization URL and instructions
    """
    params = demisto.params()
    client_id = params.get("credentials", {}).get("identifier", "")
    if not client_id:
        demisto.debug(f"{AUDIT_LOG_DEBUG_PREFIX}Client ID parameter is missing.")
        raise DemistoException("Please provide Client ID in the integration parameters before running monday-generate-login-url.")

    login_url = f"https://auth.monday.com/oauth2/authorize?client_id={client_id}"

    result_msg = f"""Click on the [login URL]({login_url}) to sign in and grant Cortex XSOAR the permissions.
    You will be automatically redirected to a link with the following structure:
    ```REDIRECT_URI?code=AUTH_CODE&region=REGION&scope=boards%3Aread&state=```
    Copy the `AUTH_CODE` (without the `code=` prefix)
    and paste it in your instance configuration under the **Authorization code** parameter.
    """
    return CommandResults(readable_output=result_msg)


def get_access_token(client: ActivityLogsClient) -> str:
    """
    Exchange authorization code for access token from Monday.com OAuth 2.0 flow.

    This function first checks if an access token already exists in the integration context.
    If not found, it exchanges the authorization code for an access token using Monday.com's
    OAuth 2.0 token endpoint.

    Args:
        client (ActivityLogsClient, optional): ActivityLogsClient instance for making requests

    Returns:
        str: Access token for Monday.com API authentication
    Note:
        The access token is stored in the integration context for reuse in subsequent calls.
    """
    integration_context = get_integration_context()
    access_token = integration_context.get("access_token", "")
    if access_token:
        demisto.debug(f"{DEBUG_PREFIX}Access token already exists in integration context")
        return access_token

    params = demisto.params()
    client_id = params.get("credentials", {}).get("identifier", "")
    secret = params.get("credentials", {}).get("password", "")
    auth_code = params.get("auth_code", {}).get("password", "")

    if not client_id or not secret or not auth_code:
        demisto.debug(f"{DEBUG_PREFIX}. get_access_token function: Client ID, Client secret or Authorization code is missing.")
        raise DemistoException(
            f"{DEBUG_PREFIX}. get_access_token function: Client ID, Client secret or Authorization code is missing."
        )

    try:
        access_token = client.get_access_token_request()

        integration_context.update({"access_token": access_token})
        set_integration_context(integration_context)
        demisto.debug(f"{DEBUG_PREFIX}Access token received successfully and set to integration context")

        return access_token

    except Exception as e:
        demisto.debug(f"{DEBUG_PREFIX}Error retrieving access token: {str(e)}")
        raise DemistoException(f"Error retrieving access token: {str(e)}")


def test_module() -> str:
    """
    Test connectivity for audit logs endpoint only.
    There is no way to test activity logs connectivity be test module button because it requires OAuth 2.0 flow.

    Returns:
        str: Success message if connection test passes or error message if connection test fails

    """
    audit_client = initiate_audit_client()
    now_ms = int(time.time() * 1000)
    try:
        if audit_client.audit_token and audit_client.audit_logs_url:
            get_audit_logs(last_run={}, now_ms=now_ms, limit=1, logs_per_page=1, client=audit_client)
            return "ok"
        else:
            return "Please provide Audit API token and Audit Server URL to test connection for audit logs."

    except Exception as e:
        demisto.debug(f"{DEBUG_PREFIX}Error testing connection: {str(e)}")
        return "Failed to test connection for audit logs."


def test_connection() -> CommandResults:
    """
    Test connectivity for both activity logs and audit logs endpoints.
    First, try to test activity logs connectivity using OAuth 2.0 flow.
    If it fails, try to test audit logs connectivity using API token.
    It attempts to fetch a single log from each configured endpoint to verify connectivity.

    Returns:
        CommandResults: Success message if connection test passes for either endpoint

    Note:
        - For activity logs: Requires client_id, client_secret, auth_code, and board_ids
        - For audit logs: Requires audit_token and audit_logs_url
        - At least one log type must be properly configured for the test to pass
    """
    params = demisto.params()
    activity_client = initiate_activity_client()
    audit_client = initiate_audit_client()

    now_ms = int(time.time() * 1000)

    activity_logs_success = False

    try:
        # Try to test connection for activity logs using OAuth 2.0 flow.
        integration_context = get_integration_context()
        access_token = integration_context.get("access_token", "")

        if access_token or (activity_client.auth_code and activity_client.client_id and activity_client.client_secret):
            board_ids = params.get("board_ids", "")
            board_ids_list = [board_id.strip() for board_id in board_ids.split(",") if board_id.strip()] if board_ids else []
            if board_ids_list:
                # All parameters are provided for activity logs, test fetch single activity log.
                get_activity_logs(last_run={}, now_ms=now_ms, limit=1, board_id=board_ids_list[0], client=activity_client)
                result = "✅ Test connection success for activity logs.\n"
                activity_logs_success = True
            else:
                result = (
                    "❌ Test connection failed for activity logs.\n"
                    "Please provide Board IDs to test connection for activity logs.\n"
                )
        else:
            result = (
                "❌ Test connection failed for activity logs.\n"
                "Please provide Client ID, Client secret and Authorization code with "
                "monday-generate-login-url command before testing connection for activity logs.\n"
            )

        # Activity logs test failed, try audit logs.
        if audit_client.audit_token and audit_client.audit_logs_url:
            # All parameters are provided for audit logs, test fetch single audit log.
            get_audit_logs(last_run={}, now_ms=now_ms, limit=1, logs_per_page=1, client=audit_client)
            if activity_logs_success:
                return CommandResults(readable_output="✅ Test connection success for both activity logs and audit logs.")
            result += "✅ Test connection success for audit logs."
        else:
            result += (
                "❌ Test connection failed for audit logs.\n"
                "Please provide Audit API token and Audit Server URL to test connection for audit logs.\n"
            )

        return CommandResults(readable_output=result)

    except Exception as e:
        demisto.debug(f"{DEBUG_PREFIX}Error testing connection: {str(e)}")
        raise DemistoException(f"Error testing connection: {str(e)}")


def get_remaining_audit_logs(last_run: dict, logs_per_page: int, client: AuditLogsClient) -> tuple[list, dict]:
    """
    Fetch remaining audit logs from Monday based on configuration.
    Called only if the user set the audit logs limit to be bigger than 1,000,
    and there are remaining logs to fetch from the last fetch run.

    Args:
        last_run (dict): The last run of the fetch.
        logs_per_page (int): Number of logs per page
        client (AuditLogsClient): AuditLogsClient instance for making requests

    Returns:
        tuple[list, dict]: The remaining audit logs and the updated last run.
    """
    excess_logs_info = last_run.get("excess_logs_info", {})
    if not excess_logs_info:
        demisto.debug(f"{AUDIT_LOG_DEBUG_PREFIX}No excess logs info found in last run.")
        return [], last_run

    offset = excess_logs_info.get("offset")
    page = excess_logs_info.get("page")
    start_time = excess_logs_info.get("start_time")
    end_time = excess_logs_info.get("end_time")

    time_filter = f'{{"start_time":"{start_time}","end_time":"{end_time}"}}'

    try:
        response = client.get_audit_logs_request(time_filter, page, logs_per_page)

        fetched_logs = response.get("data", [])
        fetched_logs = fetched_logs[offset:]

        # All excess logs fetched from the last fetch time range, no longer logs fetched from the last fetch time range.
        # Remove duplicate logs based on the lower bound logs set on the previous fetch.
        if not last_run.get("continuing_fetch_info"):
            fetched_logs = remove_duplicate_logs(
                fetched_logs,
                last_run.get("lower_bound_log_id", []),
                is_id_field_exists=False,
                debug_prefix=AUDIT_LOG_DEBUG_PREFIX,
            )

        last_run["excess_logs_info"] = None
        return fetched_logs, last_run

    except Exception as e:
        demisto.debug(f"{AUDIT_LOG_DEBUG_PREFIX}Exception during get remaining audit logs. Exception is {e!s}")
        raise DemistoException(f"Exception during get remaining audit logs. Exception is {e!s}")


def generate_log_hash(log: dict) -> str:
    """
    Generate a unique hash for a log entry based on the entire log object.

    Args:
        log: Log dictionary containing event data

    Returns:
        str: SHA-256 hash of the entire log object
    """
    # Create a consistent string formatting representation of the entire log for hashing. (sorted and without spaces)
    hash_string = json.dumps(log, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(hash_string.encode("utf-8")).hexdigest()


def get_newest_log_id_with_same_timestamp(logs: list, time_key: str, is_id_field_exists: bool):
    """
    Get the IDs of logs with the newest timestamp, support when logs are sorted by timestamp in descending order.

    Args:
        logs: List of fetched logs
        time_key: Key to extract timestamp from log
        is_id_field_exists: Whether the id field exists in the logs

    Returns:
        List of log IDs with the newest timestamp
    """
    if not logs:
        return []

    newest_log_timestamp = logs[0].get(time_key)
    same_timestamp_ids = []

    for log in logs:
        if log.get(time_key) == newest_log_timestamp:
            log_id = log.get("id") if is_id_field_exists else generate_log_hash(log)
            same_timestamp_ids.append(log_id)
        else:
            return same_timestamp_ids
    return same_timestamp_ids


def extract_activity_log_data(logs: list) -> list:
    """
    Extract and process the 'data' field from Monday activity logs.

    Monday activity logs contain a 'data' field with JSON string that needs to be parsed.
    This function processes each log entry and converts the JSON string to a dictionary.

    Args:
        logs (list): List of activity log dictionaries from Monday API

    Returns:
        list: List of logs with processed 'data' field (JSON string converted to dict)
    """
    for log in logs:
        log["data"] = process_activity_log_data(log)
    return logs


def process_activity_log_data(log: dict) -> dict:
    """
    Process the "data" field from a Monday activity log entry.

    Args:
        log: Activity log dictionary containing a "data" field with JSON string

    Returns:
        dict: Parsed data dictionary, or empty dict if parsing fails
    """
    try:
        data_str = log.get("data", "")
        if not data_str:
            return {}

        # Parse the JSON string from the data field
        parsed_data = json.loads(data_str)
        return parsed_data

    except (json.JSONDecodeError, TypeError, AttributeError) as e:
        demisto.debug(f"Failed to parse activity log data field: {e}")
        return {}


def convert_timestamp(ts, data_format: str = "%Y-%m-%dT%H:%M:%S.%fZ"):
    """
    Convert Monday's 17-digit Unix timestamp to ISO8601 format.

    Monday activity logs use a special 17-digit Unix timestamp format that represents
    time with microsecond precision. This function converts it to standard ISO8601 format.

    Args:
        ts: 17-digit Unix timestamp from Monday API (e.g., "17545145534156780")
        data_format (str): Output datetime format string. Defaults to ISO8601 with microseconds.

    Returns:
        str: Formatted datetime string in ISO8601 format

    Example:
        Input: "17545145534156780"
        Output: "2024-06-03T14:25:47.415678Z"

    Note:
        The 17-digit timestamp is divided by 10,000,000 to get standard Unix seconds.
    """
    ts_int = int(ts)
    seconds = ts_int / 10_000_000
    dt = datetime.fromtimestamp(seconds, tz=timezone.utc)
    dt = dt.strftime(data_format)
    return dt


def remove_duplicate_logs(logs: list, ids_to_remove: list, is_id_field_exists: bool, debug_prefix: str = DEBUG_PREFIX) -> list:
    """
    Remove duplicate logs based on previous fetch.

    Args:
        logs: List of fetched logs
        ids_to_remove: IDs to remove from logs
        is_id_field_exists: Whether the id field exists in the logs

    Returns:
        List of logs without duplicates
    """
    if not logs:
        demisto.debug(f"{DEBUG_PREFIX}No logs to remove duplicates from.")
        return logs
    if not ids_to_remove:
        demisto.debug(f"{DEBUG_PREFIX}No lower bound log id to remove duplicates from.")
        return logs

    ids_to_remove = set(ids_to_remove)
    if is_id_field_exists:
        filtered_logs = [log for log in logs if log.get("id") not in ids_to_remove]
    else:
        filtered_logs = [log for log in logs if generate_log_hash(log) not in ids_to_remove]

    if not filtered_logs:
        demisto.debug(f"{debug_prefix}No logs available for this request after removing duplicates.")
    else:
        demisto.debug(f"{debug_prefix}Removed {len(logs) - len(filtered_logs)} duplicate logs removed.")

    return filtered_logs


def is_activity_log_last_page(query: str, page: int, client: ActivityLogsClient, access_token: str) -> bool:
    """
    Check if the current page is the last page for activity logs pagination.

    Monday's GraphQL API doesn't provide a 'next_page' field.
    Instead, we determine if we've reached the last page by checking if the next page (page+1)
    contains any logs. If the next page is empty, then the current page is the last page.

    Args:
        query (str): GraphQL query string for fetching activity logs
        page (int): Current page number being processed
        client (ActivityLogsClient): Client instance for making requests
        access_token (str): OAuth 2.0 access token

    Returns:
        bool: True if current page is the last page (next page is empty), False otherwise
    """
    next_page = page + 1
    next_page_query = query.replace(f"page: {page}", f"page: {next_page}")
    return client.check_empty_page(next_page_query, access_token)


def get_activity_logs(last_run: dict, now_ms: int, limit: int, board_id: str, client: ActivityLogsClient) -> tuple[list, dict]:
    """
    Fetch activity logs from Monday based on configuration.

    Args:
        last_run: Previous fetch state containing last_timestamp and fetched_ids
        now_ms: Current time in milliseconds
        limit: Maximum number of logs to fetch per board
        board_id: Monday.com board ID to fetch logs from
        client: ActivityLogsClient instance for making requests

    Returns:
        tuple: (logs, last_run) where logs are the fetched logs and last_run is the updated state.
    """

    # Not all logs were fetched in the previous fetch between from and to times.
    if last_run.get("continuing_fetch_info"):
        is_continuing_fetch = True
        continuing_fetch_info = last_run.get("continuing_fetch_info", {})
        page = continuing_fetch_info.get("page")
        start_time = continuing_fetch_info.get("start_time")
        end_time = continuing_fetch_info.get("end_time")
        demisto.debug(
            f"{ACTIVITY_LOG_DEBUG_PREFIX}Continuing fetch for Activity Logs from: {start_time} to {end_time}\nPage: {page}"
        )

    # First fetch in the current time range.
    else:
        is_continuing_fetch = False
        end_time = timestamp_to_datestring(now_ms, date_format="%Y-%m-%dT%H:%M:%S.%fZ")

        if last_run.get("last_timestamp"):
            start_time = subtract_epsilon_from_timestamp(last_run.get("last_timestamp"))
            demisto.debug(
                f"{ACTIVITY_LOG_DEBUG_PREFIX}decrease epsilon from start_time to include logs with the exact same timestamp.\n"
                f"original last_timestamp: {last_run.get('last_timestamp')}, after subtract epsilon: {start_time}"
            )
        else:
            start_time = timestamp_to_datestring(now_ms - START_FETCH_TIME, date_format="%Y-%m-%dT%H:%M:%S.%fZ")

        page = 1
        demisto.debug(
            f"{ACTIVITY_LOG_DEBUG_PREFIX}Starting new fetch range for Activity Logs "
            f"from: {start_time} to {end_time}\nPage: {page}"
        )

    access_token = get_access_token(client)
    query = f"""
    query {{
        boards (ids: [{board_id}]) {{
            activity_logs (
                from: "{start_time}",
                to: "{end_time}",
                limit: {limit},
                page: {page}
            ) {{
                created_at
                data
                id
                event
            }}
        }}
    }}
    """

    try:
        response = client.get_activity_logs_request(query, access_token)
    except Exception as e:
        demisto.debug(f"{ACTIVITY_LOG_DEBUG_PREFIX}Exception during get activity logs. Exception is {e!s}")
        raise DemistoException(f"Exception during get activity logs. Exception is {e!s}")

    # Extract board logs from response
    board_logs = response.get("data", {}).get("boards", [{}])[0].get("activity_logs", [])
    fetched_logs = extract_activity_log_data(board_logs)
    demisto.debug(f"{ACTIVITY_LOG_DEBUG_PREFIX}Successfully fetched {len(fetched_logs)} activity logs from board: {board_id}")

    if page == 1:
        if fetched_logs:
            last_run["upper_bound_log_id"] = get_newest_log_id_with_same_timestamp(
                fetched_logs, "created_at", is_id_field_exists=True
            )

            newest_log_timestamp = fetched_logs[0].get("created_at")
            newest_log_timestamp = convert_timestamp(newest_log_timestamp)

            demisto.debug(
                f"{ACTIVITY_LOG_DEBUG_PREFIX}page=1, newest log timestamp: {newest_log_timestamp}, "
                f"set upper_bound_log_id: {last_run['upper_bound_log_id']}"
            )

        else:
            demisto.debug(f"{ACTIVITY_LOG_DEBUG_PREFIX}page=1, no logs available for this time range.")
            return [], last_run
    # last page reached when the response contains no activity logs.
    if is_activity_log_last_page(query, page, client, access_token):
        demisto.debug(f"{ACTIVITY_LOG_DEBUG_PREFIX}page={page} is the last page.")

        lower_bound_log_id = last_run.get("lower_bound_log_id", [])
        fetched_logs = remove_duplicate_logs(
            fetched_logs, ids_to_remove=lower_bound_log_id, is_id_field_exists=True, debug_prefix=ACTIVITY_LOG_DEBUG_PREFIX
        )

        last_run["lower_bound_log_id"] = last_run.get(
            "upper_bound_log_id", []
        ).copy()  # The upper bound log id is the lower bound in the next fetch
        demisto.debug(
            f"{ACTIVITY_LOG_DEBUG_PREFIX}set lower_bound_log_id to be upper_bound_log_id: {last_run['lower_bound_log_id']}"
        )

        # If it's a continuing fetch, the last_timestamp is already saved from the first fetch run.
        if not is_continuing_fetch:
            last_run["last_timestamp"] = newest_log_timestamp
            demisto.debug(
                f"{ACTIVITY_LOG_DEBUG_PREFIX}This is the first fetch in the current time range.\n"
                f"set last_timestamp to be newest_log_timestamp: {last_run['last_timestamp']}"
            )

        last_run["continuing_fetch_info"] = None
        demisto.debug(f"{ACTIVITY_LOG_DEBUG_PREFIX} Setting continuing_fetch_info to None")

        return fetched_logs, last_run

    # At this point we need to continue fetching because there are more pages to fetch
    page += 1
    last_run["continuing_fetch_info"] = {"page": page, "start_time": start_time, "end_time": end_time}
    demisto.debug(
        f"{ACTIVITY_LOG_DEBUG_PREFIX}Limit is reached and there are more pages to fetch.\n"
        f"Setting continuing_fetch_info: {last_run['continuing_fetch_info']}"
    )

    # The first fetch in the current run, set the last_timestamp to the time of the newest log.
    # If it's a continuing fetch, the last_timestamp is already saved from the first fetch run.
    if not is_continuing_fetch:
        last_run["last_timestamp"] = newest_log_timestamp
        demisto.debug(
            f"{ACTIVITY_LOG_DEBUG_PREFIX}This is the first fetch in the current time range, "
            f"setting last_timestamp: {last_run['last_timestamp']}"
        )

    return fetched_logs, last_run


def subtract_epsilon_from_timestamp(timestamp_str, epsilon_ms=1):
    """
    Generic function to subtract epsilon from any ISO timestamp format
    """
    try:
        # Parse any ISO format automatically
        dt = parser.isoparse(timestamp_str)
        # Subtract epsilon
        dt_with_epsilon = dt - timedelta(milliseconds=epsilon_ms)
        # Format back to original format (preserve precision)
        return dt_with_epsilon.isoformat().replace("+00:00", "Z")
    except Exception:
        # Fallback to original timestamp if parsing fails
        return timestamp_str


def get_audit_logs(last_run: dict, now_ms: int, limit: int, logs_per_page: int, client: AuditLogsClient) -> tuple[list, dict]:
    """
    Fetch audit logs from Monday based on configuration.

    Remaining logs fetched before calling this function, this function starts to fetch always from new page.
    (last_run does not contain the "excess_logs_info" key)
    Args:
        last_run: Previous fetch state containing last_timestamp and fetched_ids
        now_ms: Current time in milliseconds
        limit: Maximum number of logs to fetch
        logs_per_page: Number of logs per page
        client: AuditLogsClient instance for making requests

    Returns:
        tuple: (logs, last_run) where last_run is the updated state and logs are the fetched logs.
    """

    remaining_logs = 0
    fetched_logs = []

    newest_log_timestamp = ""
    total_logs: list = []

    # Not all logs were fetched in the previous fetch between start_time and end_time.
    if last_run.get("continuing_fetch_info"):
        is_continuing_fetch = True
        continuing_fetch_info = last_run.get("continuing_fetch_info", {})
        page = continuing_fetch_info.get("page")
        start_time = continuing_fetch_info.get("start_time")
        end_time = continuing_fetch_info.get("end_time")
        demisto.debug(f"{AUDIT_LOG_DEBUG_PREFIX}Continuing fetch for Audit Logs from: {start_time} to {end_time}\nPage: {page}")

    # First fetch in the current time range.
    else:
        is_continuing_fetch = False
        end_time = timestamp_to_datestring(now_ms, date_format="%Y-%m-%dT%H:%M:%S.%fZ")

        if last_run.get("last_timestamp"):
            start_time = subtract_epsilon_from_timestamp(last_run.get("last_timestamp"))
            demisto.debug(
                f"{AUDIT_LOG_DEBUG_PREFIX}decrease epsilon from start_time to include logs with the exact same timestamp.\n"
                f"original last_timestamp: {last_run.get('last_timestamp')}, after subtract epsilon: {start_time}"
            )
        else:
            start_time = timestamp_to_datestring(now_ms - START_FETCH_TIME, date_format="%Y-%m-%dT%H:%M:%S.%fZ")

        page = 1
        demisto.debug(
            f"{AUDIT_LOG_DEBUG_PREFIX}Starting new fetch range for Audit Logs from: {start_time} to {end_time}\nPage: {page}"
        )

    time_filter = f'{{"start_time":"{start_time}","end_time":"{end_time}"}}'

    """
        The first condition that reached will exit the loop:
        1. len(total_logs) >= limit
        2. next_page = None
    """
    while len(total_logs) < limit:
        remaining_logs = limit - len(total_logs)

        demisto.debug(
            f"{AUDIT_LOG_DEBUG_PREFIX}Starting to fetch new page of audit logs.\nRemaining logs to fetch: {remaining_logs}"
        )

        try:
            response = client.get_audit_logs_request(time_filter, page, logs_per_page)
        except Exception as e:
            demisto.debug(f"{AUDIT_LOG_DEBUG_PREFIX}Exception during get audit logs. Exception is {e!s}")
            raise DemistoException(f"Exception during get audit logs. Exception is {e!s}")

        fetched_logs = response.get("data", [])
        demisto.debug(f"{AUDIT_LOG_DEBUG_PREFIX}Successfully fetched {len(fetched_logs)} audit logs.")

        if page == 1:
            if fetched_logs:
                last_run["upper_bound_log_id"] = get_newest_log_id_with_same_timestamp(
                    fetched_logs, "timestamp", is_id_field_exists=False
                )
                newest_log_timestamp = fetched_logs[0].get("timestamp")

                demisto.debug(
                    f"{AUDIT_LOG_DEBUG_PREFIX}page=1, newest log timestamp: {newest_log_timestamp}.\n"
                    f"set upper_bound_log_id: {last_run['upper_bound_log_id']}"
                )

            else:
                demisto.debug(f"{AUDIT_LOG_DEBUG_PREFIX}page=1, no logs available for this time range.")
                return [], last_run

        # last page reached, next_page = None, meaning there are no more logs to fetch.
        # We can remove duplicate logs based on the lower bound logs set on the previous fetch.
        if not response.get("next_page"):
            demisto.debug(f"{AUDIT_LOG_DEBUG_PREFIX}page={page} is the last page.")

            lower_bound_log_id = last_run.get("lower_bound_log_id", [])
            fetched_logs = remove_duplicate_logs(
                fetched_logs, lower_bound_log_id, is_id_field_exists=False, debug_prefix=AUDIT_LOG_DEBUG_PREFIX
            )
            total_logs.extend(fetched_logs)

            last_run["lower_bound_log_id"] = last_run.get(
                "upper_bound_log_id", []
            ).copy()  # The upper bound log id is the lower bound in the next fetch
            demisto.debug(
                f"{AUDIT_LOG_DEBUG_PREFIX}set lower_bound_log_id to be upper_bound_log_id: {last_run['lower_bound_log_id']}"
            )

            # If it's a continuing fetch, the last_timestamp is already saved from the first fetch run.
            if not is_continuing_fetch:
                last_run["last_timestamp"] = newest_log_timestamp
                demisto.debug(
                    f"{AUDIT_LOG_DEBUG_PREFIX}This is the first fetch in the current time range.\n"
                    f"set last_timestamp to be newest_log_timestamp: {last_run['last_timestamp']}"
                )

            if len(fetched_logs) > remaining_logs:
                demisto.debug(
                    f"{AUDIT_LOG_DEBUG_PREFIX} page={page} has more logs than remaining logs to fetch.\n"
                    f"remaining_logs: {remaining_logs}, Fetched logs from page {page}: {len(fetched_logs)}"
                )
                last_run["excess_logs_info"] = {
                    "page": page,
                    "start_time": start_time,
                    "end_time": end_time,
                    "offset": remaining_logs,
                }
                demisto.debug(f"{AUDIT_LOG_DEBUG_PREFIX} Setting excess_logs_info for next fetch: {last_run['excess_logs_info']}")
                total_logs = total_logs[:limit]
                demisto.debug(f"{AUDIT_LOG_DEBUG_PREFIX} Truncated total_logs from {len(total_logs)} to limit: {limit}")

            last_run["continuing_fetch_info"] = None
            demisto.debug(f"{AUDIT_LOG_DEBUG_PREFIX} Setting continuing_fetch_info to None")

            return total_logs, last_run

        total_logs.extend(fetched_logs)
        page += 1

    # At this point, limit is reached so we need to continue fetching (next_page = None is not reached)
    last_run["continuing_fetch_info"] = {"page": page, "start_time": start_time, "end_time": end_time}
    demisto.debug(
        f"{AUDIT_LOG_DEBUG_PREFIX}Limit is reached and there are more pages to fetch.\n"
        f"Setting continuing_fetch_info: {last_run['continuing_fetch_info']}"
    )

    # Only partial logs were fetched from the last page when limit is reached.
    if len(fetched_logs) > remaining_logs:
        last_run["excess_logs_info"] = {
            "page": page - 1,
            "start_time": start_time,
            "end_time": end_time,
            "offset": remaining_logs,
        }
        demisto.debug(
            f"{AUDIT_LOG_DEBUG_PREFIX}Limit is reached and Only partial logs were fetched from the last page.\n"
            f"Setting excess_logs_info: {last_run['excess_logs_info']}"
        )

        total_logs = total_logs[:limit]

    # The first fetch in the current run, set the last_timestamp to the time of the newest log.
    # If it's a continuing fetch, the last_timestamp is already saved from the first fetch run.
    if not is_continuing_fetch:
        last_run["last_timestamp"] = newest_log_timestamp
        demisto.debug(
            f"{AUDIT_LOG_DEBUG_PREFIX}This is the first fetch in the current time range.\n"
            f"setting last_timestamp: {last_run['last_timestamp']}"
        )

    return total_logs[:limit], last_run


def fetch_audit_logs(last_run: dict) -> tuple[dict, list]:
    """
    Fetch audit logs from Monday.com API.

    Args:
        last_run (dict): Previous fetch state containing timestamps, pagination info,
                        and any continuing/excess fetch information

    Returns:
        tuple[dict, list]: Updated last_run state and list of fetched audit logs
    """
    now_ms = int(time.time() * 1000)
    audit_logs = []
    params = demisto.params()

    limit = min(MAX_AUDIT_LOGS_PER_FETCH, int(params.get("max_audit_logs_per_fetch", 5000)))
    logs_per_page = min(MAX_AUDIT_LOGS_PER_PAGE, limit)

    try:
        demisto.debug(f"{AUDIT_LOG_DEBUG_PREFIX}last_run before fetching audit logs: {last_run}")
        client = initiate_audit_client()

        if not client.audit_token or not client.audit_logs_url:
            demisto.debug(f"{AUDIT_LOG_DEBUG_PREFIX}Audit API token or Audit Server URL parameters are missing.")
            raise DemistoException(
                "Please provide Audit API token and Audit Server URL in the integration parameters for fetch audit logs."
            )

        # Handle fetching remaining logs from previous fetch
        if last_run.get("excess_logs_info"):
            excess_logs, last_run = get_remaining_audit_logs(last_run, logs_per_page, client)
            limit_before_fetch = limit
            audit_logs.extend(excess_logs)
            limit -= len(excess_logs)
            demisto.debug(
                f"{AUDIT_LOG_DEBUG_PREFIX}Fetched {len(excess_logs)} excess audit logs, "
                f"limit changes from {limit_before_fetch} to {limit}"
            )
            demisto.debug(f"{AUDIT_LOG_DEBUG_PREFIX}last_run after fetching remaining audit logs: {last_run}")

        fetched_logs, last_run = get_audit_logs(
            last_run=last_run, now_ms=now_ms, limit=limit, logs_per_page=logs_per_page, client=client
        )
        audit_logs.extend(fetched_logs)

    except Exception as e:
        demisto.debug(f"{AUDIT_LOG_DEBUG_PREFIX}Exception during fetch audit logs. Exception is {e!s}")
        raise DemistoException(f"{AUDIT_LOG_DEBUG_PREFIX}Exception during fetch audit logs. Exception is {e!s}")

    add_fields_to_events(audit_logs, event_type="Audit Log")

    return last_run, audit_logs


def initiate_activity_log_last_run(last_run: dict, board_ids_list: list[str]) -> dict:
    """
    Initialize last_run structure for multi-board activity logs fetching.

    Activity logs are fetched per board, and each board maintains its own separate state.

    Args:
        last_run (dict): Current last_run state from previous fetch execution
        board_ids_list (list[str]): List of board IDs configured for activity logs fetching

    Returns:
        dict: Updated last_run with entries for each board

    Example:
        Input: last_run={}, board_ids_list=["123", "456"]
        Output: {"123": {}, "456": {}}

    """
    if not last_run:
        for board_id in board_ids_list:
            last_run[board_id] = {}
    return last_run


def initiate_activity_client() -> ActivityLogsClient:
    """
    Initialize ActivityLogsClient for making requests.

    Returns:
        ActivityLogsClient: ActivityLogsClient instance for making requests.
    """
    demisto_params = demisto.params()
    client_id = demisto_params.get("credentials", {}).get("identifier", "")
    client_secret = demisto_params.get("credentials", {}).get("password", "")
    auth_code = demisto_params.get("auth_code", {}).get("password", "")
    proxy = demisto_params.get("proxy", False)
    verify = not demisto_params.get("insecure", False)
    activity_logs_url = demisto_params.get("activity_logs_url", "https://api.monday.com")

    return ActivityLogsClient(
        client_id=client_id,
        client_secret=client_secret,
        auth_code=auth_code,
        activity_logs_url=activity_logs_url,
        proxy=proxy,
        verify=verify,
    )


def initiate_audit_client() -> AuditLogsClient:
    """
    Create AuditLogsClient for making requests.

    Returns:
        AuditLogsClient: AuditLogsClient instance for making requests
    """
    params = demisto.params()
    audit_token = params.get("audit_token", {}).get("password")
    audit_logs_url = params.get("audit_logs_url", "")
    proxy = params.get("proxy", False)
    verify = not params.get("insecure", False)

    return AuditLogsClient(audit_token=audit_token, audit_logs_url=audit_logs_url, proxy=proxy, verify=verify)


def fetch_activity_logs(last_run: dict) -> tuple[dict, list]:
    """
    Fetch activity logs from Monday.com API for multiple boards.

    Args:
        last_run (dict): Previous fetch state containing per-board timestamps and fetched IDs
                        Structure: {"board_id":
                                        {"last_timestamp": "...",
                                        "lower_bound_log_id": [...],
                                        "upper_bound_log_id": [...],
                                        "continuing_fetch_info": {...}
                                        },
                                    "board_id2":
                                        {...}
                                    }

    Returns:
        tuple[dict, list]: Updated last_run state and list of fetched activity logs from all boards
    """
    demisto_params = demisto.params()

    board_ids = demisto_params.get("board_ids", "")
    if not board_ids:
        demisto.debug(f"{ACTIVITY_LOG_DEBUG_PREFIX}board ID is missing.")
        raise DemistoException("Please provide board IDs in the integration parameters before starting to fetch activity logs.")
    board_ids_list = [board_id.strip() for board_id in board_ids.split(",") if board_id.strip()]

    last_run = initiate_activity_log_last_run(last_run, board_ids_list)

    limit = min(MAX_ACTIVITY_LOGS_PER_FETCH, int(demisto_params.get("max_activity_logs_per_fetch", 10000)))
    now_ms = int(time.time() * 1000)
    activity_logs: list = []

    try:
        client = initiate_activity_client()

        for board_id in board_ids_list:
            current_board_last_run = last_run[board_id]
            demisto.debug(
                f"{ACTIVITY_LOG_DEBUG_PREFIX}board_id: {board_id}, last_run before fetching activity logs:\n"
                f"{current_board_last_run}"
            )

            fetched_logs, updated_last_run = get_activity_logs(
                last_run=current_board_last_run,
                now_ms=now_ms,
                limit=limit,
                board_id=board_id,
                client=client,
            )
            last_run[board_id] = updated_last_run
            activity_logs.extend(fetched_logs)
            demisto.debug(
                f"{ACTIVITY_LOG_DEBUG_PREFIX}board_id: {board_id}, last_run after fetching activity logs:\n{last_run[board_id]}"
            )

    except Exception as e:
        demisto.debug(f"{ACTIVITY_LOG_DEBUG_PREFIX}Exception during fetch activity logs. Exception is {e!s}")
        raise DemistoException(f"{ACTIVITY_LOG_DEBUG_PREFIX}Exception during fetch activity logs. Exception is {e!s}")

    add_fields_to_events(activity_logs, event_type="Activity Log")

    return last_run, activity_logs


def add_fields_to_events(events: List[Dict], event_type: str):
    """
    Adds the _time key to the events.
    Args:
        events: List[Dict] - list of events to add the _time key to.
    Returns:
        list: The events with the _time key.
    """
    for event in events:
        if event_type == "Audit Log":
            create_time = arg_to_datetime(arg=event.get("timestamp"))
            time_value = create_time.strftime(DATE_FORMAT) if create_time else None
        else:  # Activity Log
            create_time = event.get("created_at")
            time_value = convert_timestamp(create_time, DATE_FORMAT) if create_time else None

        event["_time"] = time_value
        event["event_type"] = event_type


def fetch_events() -> tuple[dict, list]:
    """
    Fetch events from Monday based on configuration. (Activity Logs and Audit Logs)

    Returns:
        tuple: (last_run, events) where last_run is the updated state and events are the fetched logs.
    """
    events = []
    params = demisto.params()

    last_run = demisto.getLastRun()
    if not last_run:
        last_run = {AUDIT_LOGS_TYPE: {}, ACTIVITY_LOGS_TYPE: {}}
        demisto.debug(f"Empty last run object, initializing new last run object: {last_run}")

    last_run_audit_logs = last_run.get(AUDIT_LOGS_TYPE, {})
    last_run_activity_logs = last_run.get(ACTIVITY_LOGS_TYPE, {})

    selected_event_types = params.get("selected_event_types", "") or "Audit Logs,Activity Logs"
    demisto.debug(f"{DEBUG_PREFIX}Selected event types: {selected_event_types} "
                 f"({'configured' if params.get('selected_event_types') else 'default'})")

    if AUDIT_LOGS_TYPE in selected_event_types:
        demisto.debug(f"{DEBUG_PREFIX}Start fetch Audit Logs, Current Audit Logs last_run object:\n{last_run_audit_logs}")
        last_run_audit_logs, fetched_audit_logs = fetch_audit_logs(last_run_audit_logs)
        events.extend(fetched_audit_logs)
        demisto.debug(f"{DEBUG_PREFIX}Total fetched audit logs: {len(fetched_audit_logs)}")

    if ACTIVITY_LOGS_TYPE in selected_event_types:
        demisto.debug(
            f"{DEBUG_PREFIX}Start fetch Activity Logs, Current Activity Logs last_run object:\n{last_run_activity_logs}"
        )
        last_run_activity_logs, fetched_activity_logs = fetch_activity_logs(last_run_activity_logs)
        events.extend(fetched_activity_logs)
        demisto.debug(f"{DEBUG_PREFIX}Total fetched activity logs: {len(fetched_activity_logs)}")

    last_run = {AUDIT_LOGS_TYPE: last_run_audit_logs, ACTIVITY_LOGS_TYPE: last_run_activity_logs}

    return last_run, events


""" MAIN FUNCTION """


def main() -> None:  # pragma: no cover
    """
    main function, parses params and runs command functions
    """

    command = demisto.command()
    demisto.debug(f"{DEBUG_PREFIX}Command being called is {command}")
    try:
        if command == "test-module":
            return_results(test_module())
        elif command == "monday-generate-login-url":
            return_results(generate_login_url())
        elif command == "monday-auth-test":
            return_results(test_connection())
        elif command == "fetch-events":
            last_run, events = fetch_events()
            demisto.debug(f"{DEBUG_PREFIX}Monday Integration Sending {len(events)} events to XSIAM.\n{events}")
            send_events_to_xsiam(events, vendor=VENDOR, product=PRODUCT)
            demisto.debug(f"{DEBUG_PREFIX}Sent events to XSIAM successfully")

            demisto.setLastRun(last_run)
            demisto.debug(f"{DEBUG_PREFIX}Updated last_run object after fetch: {last_run}")

    except Exception as e:
        return_error(f"{DEBUG_PREFIX}Failed to execute {command} command.\nError:\n{str(e)}")


""" ENTRY POINT """

if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
