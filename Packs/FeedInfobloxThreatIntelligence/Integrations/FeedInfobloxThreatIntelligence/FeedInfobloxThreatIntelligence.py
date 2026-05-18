"""Infoblox Threat Intelligence Feed Integration for Cortex XSOAR

This integration fetches threat intelligence indicators from the Infoblox TIDE API
and imports them as indicators in XSOAR.

Developer Documentation: https://xsoar.pan.dev/docs/welcome
Code Conventions: https://xsoar.pan.dev/docs/integrations/code-conventions
Linting: https://xsoar.pan.dev/docs/integrations/linting
"""

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from CommonServerUserPython import *


import json
import urllib3
import dateparser
import requests
from datetime import datetime, timedelta
from typing import Any


# Disable insecure warnings
urllib3.disable_warnings()

""" CONSTANTS """

BASE_URL = "https://csp.infoblox.com"
DATE_FORMAT = "%Y-%m-%dT%H:%M:%SZ"  # ISO8601 format with UTC, default in XSOAR

# Retry mechanism constants
TOTAL_RETRIES = 3
BACKOFF_FACTOR = 7.5  # Sleep for [0s, 15s, 30s] between retries
STATUS_CODE_TO_RETRY = (429, *(status_code for status_code in requests.status_codes._codes if status_code >= 500))  # type: ignore
VALID_CODES = [
    status_code
    for status_code in requests.status_codes._codes  # type: ignore
    if status_code  # type: ignore[attr-defined]
    >= 200
    and status_code < 300
]
# HTTP error responses
HTTP_ERRORS = {
    400: "Bad request: An error occurred while fetching the data.",
    401: "Authentication error: Please provide valid API Key.",
    403: "Forbidden: Please provide valid API Key.",
    404: "Resource not found: Invalid endpoint was called.",
    429: "Rate limit exceeded: Try again later.",
    500: "Internal server error: Please try again after some time.",
}

# Field mapping for Infoblox indicators to XSOAR fields
INFOBLOX_FIELD_MAPPING = {
    "firstseenbysource": {"path": "detected", "type": "date"},
    "lastseenbysource": {"path": "received", "type": "date"},
    "expirationdate": {"path": "expiration", "type": "date"},
    "published": {"path": "imported", "type": "date"},
    "description": {"path": "extended.notes", "type": "str"},
    "definition": {"path": "type", "type": "str"},
    "trafficlightprotocol": {"path": "", "type": "str", "default": "AMBER"},
    "confidence": {"path": "confidence", "type": "str"},
    "category": {"path": "class", "type": "str"},
    "malwarefamily": {"path": "property", "type": "str"},
    "service": {"path": "profile", "type": "str"},
    "domainidnname": {"path": "tld", "type": "str"},
    "sourcepriority": {"path": "threat_level", "type": "int"},
    "signaturealgorithm": {"path": "dga", "type": "str"},
    "state": {"path": "up", "type": "str"},
    "hostname": {"path": "host", "type": "str"},
    "domainname": {"path": "domain", "type": "str"},
    "ipaddress": {"path": "ip", "type": "str"},
    "email": {"path": "email", "type": "str"},
}

# Key mapping for Infoblox response
RESPONSE_KEY_MAPPING = {
    "class": "threat_class",
}

# Default number of indicators to fetch in a single API call
DEFAULT_LIMIT = 1000
# Daily limit of indicators allowed by the API
DAILY_LIMIT = 10000
# Maximum number of indicators allowed by the API
MAX_INDICATORS_LIMIT = 50000
# Number of days to fetch at a time in incremental mode
FETCH_WINDOW_DAYS = 1
# Maximum number of indicators to process in a batch for XSOAR
BATCH_SIZE = 2000
# Default first fetch value
DEFAULT_FIRST_FETCH = "1 hour"
# Default indicator types
DEFAULT_INDICATOR_TYPES = ["ip", "host", "email", "url", "hash"]
# Total number of indicator types
TOTAL_INDICATOR_TYPES = len(DEFAULT_INDICATOR_TYPES)

""" CLIENT CLASS """


class Client(BaseClient):
    """Client class to interact with the Infoblox TIDE API.

    This Client implements API calls to fetch threat intelligence indicators
    from the Infoblox TIDE API. It inherits from BaseClient defined in
    CommonServerPython.
    """

    def __init__(self, api_key: str, verify: bool = True, proxy: bool = False, read_timeout: int = 180) -> None:
        """Initialize the Client.

        Args:
            api_key (str): API key for authentication.
            verify (bool, optional): Whether to verify SSL. Defaults to True.
            proxy (bool, optional): Whether to use system proxy. Defaults to False.
            read_timeout (int, optional): Timeout for HTTP requests in seconds. Defaults to 180.
        """
        headers = {"Authorization": f"Token {api_key}"} if api_key else {}
        super().__init__(base_url=BASE_URL, verify=verify, proxy=proxy, headers=headers)
        self._read_timeout = read_timeout

    def _handle_error_response(self, res: requests.Response) -> None:
        """
        Handle error responses from the API.

        Args:
            res (requests.Response): Response to process.

        Raises:
            DemistoException: With appropriate error message based on status code.
        """
        status_code = res.status_code
        if status_code == 400:
            raise DemistoException("Bad Request (400): Invalid parameters or request body.")
        elif status_code == 401:
            raise DemistoException("Authentication Error (401): API key is invalid or expired.")
        elif status_code == 403:
            raise DemistoException("Forbidden (403): Insufficient permissions to access this resource.")
        elif status_code == 404:
            raise DemistoException("Not Found (404): The requested resource was not found.")
        elif status_code == 429:
            raise DemistoException("Rate Limit Exceeded (429): Too many requests. Please try again later.")
        elif 500 <= status_code < 600:
            raise DemistoException(f"Server Error ({status_code}): Internal server error occurred. Please try again later.")
        else:
            err_msg = HTTP_ERRORS.get(status_code, f"Error in API call with status code {status_code}.")
            raise DemistoException(err_msg)

    def http_request(
        self,
        method: str,
        url_suffix: str = "",
        full_url: str = None,
        params: dict = None,
        data: dict = None,
        json_data: dict = None,  # noqa: ARG002
        headers: dict = None,
        timeout: int = None,
    ) -> Any:
        """Send an HTTP request with enhanced error handling and retry mechanism.

        Args:
            method (str): HTTP method (GET, POST, etc.).
            url_suffix (str, optional): Suffix to append to the base URL. Defaults to ''.
            full_url (str, optional): Full URL to use instead of base URL + suffix. Defaults to None.
            params (dict, optional): URL parameters. Defaults to None.
            data (dict, optional): Form data. Defaults to None.
            json_data (dict, optional): JSON data body. Defaults to None.
            headers (dict, optional): Additional headers. Defaults to None.
            timeout (int, optional): Request timeout. Defaults to None.

        Returns:
            Any: Response from the API.

        Raises:
            DemistoException: If the request fails.
        """
        # Log the request details for debugging
        demisto.debug(f"Requesting Infoblox TIDE API with method: {method}, url_suffix: {url_suffix} and params: {params}")

        try:
            res = self._http_request(
                method=method,
                url_suffix=url_suffix,
                full_url=full_url,
                params=params,
                data=json.dumps(data) if data else None,
                headers=headers,
                timeout=timeout or self._read_timeout,
                resp_type="response",
                ok_codes=(200, 201, 204),
                error_handler=self._handle_error_response,
                retries=TOTAL_RETRIES,
                status_list_to_retry=STATUS_CODE_TO_RETRY,
                backoff_factor=BACKOFF_FACTOR,
            )

            try:
                return res.json()
            except ValueError:
                return res.content

        except requests.ConnectionError as e:
            err_msg = "Connection error in the API call to Infoblox.\n"
            try:
                err_msg += e.args[0].reason.args[0]
            except Exception:
                err_msg += str(e)
            raise DemistoException(err_msg) from e

        except DemistoException as e:
            if "Read timed out" in str(e) or "Connection aborted" in str(e):
                err_msg = "Connection timed out. Check your internet connection or the service may be temporarily unavailable."
                raise DemistoException(err_msg) from e
            raise

    def get_indicators_by_type(self, indicator_type: str, params: dict[str, Any] = None) -> dict[str, Any]:
        """Retrieves indicators from the Infoblox Threat Intelligence Feed by type.
        Args:
            indicator_type (str): Type of indicators to retrieve (HOST, IP, etc.).
            params (dict[str, Any], optional): Additional parameters for the API request. Defaults to None.
        Returns:
            dict[str, Any]: Response containing threat indicators.
        """
        demisto.debug(f"Fetching indicators with parameters: {params}")
        return self.http_request(method="GET", url_suffix=f"/tide/api/data/threats/{indicator_type}/hourly", params=params)

    def get_indicators(
        self,
        limit: int = None,
        indicator_types: list[str] | None = None,
        from_date: str | None = None,
        to_date: str | None = None,
        dga_flag: str = None,
        threat_class: list[str] = None,
        profile: list[str] = None,
    ) -> list[dict[str, Any]]:
        """Retrieves indicators from the Infoblox Threat Intelligence Feed.

        Args:
            limit (int, optional): Maximum number of indicators to return. Defaults to None.
            indicator_types (List[str], optional): Type of indicators to retrieve (HOST, IP, etc.). Defaults to None.
            from_date (str, optional): Only retrieve indicators updated since this time (ISO format). Defaults to None.
            to_date (str, optional): Only retrieve indicators updated until this time (ISO format). Defaults to None.
            dga_flag (str, optional): Filter by DGA (Domain Generation Algorithm) flag. Defaults to None.
            threat_class (List[str], optional): Filter by threat classes. Defaults to None.
            profile (List[str], optional): Filter by profiles. Defaults to None.

        Returns:
            List[Dict[str, Any]]: Response containing threat indicators.
        """
        params: dict[str, Any] = {}

        if not limit:
            limit = 1

        if from_date:
            params["from_date"] = from_date

        if to_date:
            params["to_date"] = to_date

        if dga_flag:
            params["dga"] = dga_flag

        if threat_class:
            params["class"] = ",".join(threat_class)

        if profile:
            params["profile"] = ",".join(profile)

        if indicator_types:
            indicator_types = [indicator_type.lower() for indicator_type in indicator_types]
        else:
            indicator_types = DEFAULT_INDICATOR_TYPES

        demisto.debug(f"Fetching indicators with parameters: {params}")

        indicator_limit = limit // len(indicator_types)  # type: ignore
        indicator_limit_addup = limit % len(indicator_types)  # type: ignore
        indicator_list = []
        for indicator_type in indicator_types:
            params["rlimit"] = (
                indicator_limit + indicator_limit_addup if indicator_type == indicator_types[-1] else indicator_limit
            )
            if indicator_type == "ip":
                params["include_ipv6"] = True
            elif indicator_type != "ip" and "include_ipv6" in params:
                del params["include_ipv6"]
            response = self.get_indicators_by_type(indicator_type, params)

            # Extract indicators from response with proper type checking
            indicators_data = []
            if isinstance(response, dict):
                indicators_data = response.get("threat", [])
                if not isinstance(indicators_data, list):
                    demisto.debug(f"Expected list of indicators, got {type(indicators_data)}")
                    continue
            indicator_list.extend(indicators_data)
        return indicator_list  # type: ignore


""" HELPER FUNCTIONS """


def transform_keys(
    data: dict[str, Any] | list[dict[str, Any]], key_mapping: dict[str, str]
) -> dict[str, Any] | list[dict[str, Any]]:
    """
    Transform keys in a dictionary or list of dictionaries based on a key mapping.

    Args:
        data (dict[str, Any] | list[dict[str, Any]]): Dictionary, list of dictionaries, or any nested structure.
        key_mapping (dict[str, str]): Dictionary mapping old keys to new keys.

    Returns:
        dict[str, Any] | list[dict[str, Any]]: Transformed data with keys renamed according to the mapping.
    """
    if isinstance(data, dict):
        # Transform dictionary keys
        transformed = {}
        for key, value in data.items():
            # Use mapped key if available, otherwise use original key
            new_key = key_mapping.get(key, key)
            # Recursively transform nested structures
            transformed[new_key] = transform_keys(value, key_mapping)
        return transformed

    elif isinstance(data, list):
        # Transform each item in the list
        return [transform_keys(item, key_mapping) for item in data]  # type: ignore

    else:
        # Return primitive values as-is
        return data


def map_indicator_type(indicator_data: dict[str, Any]) -> tuple[str, str | None]:
    """Maps Infoblox indicator types to XSOAR types.

    Args:
        indicator_data (Dict[str, Any]): Indicator data from Infoblox.

    Returns:
        Tuple[str, Optional[str]]: XSOAR indicator type and value (value may be None if not found).
    """
    # Ensure indicator_data is a dict to satisfy type checker
    if not isinstance(indicator_data, dict):
        demisto.debug(f"Unexpected indicator data type: {type(indicator_data)}")
        return FeedIndicatorType.Domain, None

    # Type checker assistance - we've verified it's a dict
    indicator_data_dict: dict[str, Any] = indicator_data

    indicator_type = indicator_data_dict.get("type")
    value = None

    if indicator_type == "HOST" or indicator_type == "DOMAIN":
        xsoar_type = FeedIndicatorType.Domain
        value = indicator_data_dict.get("domain") or indicator_data_dict.get("host")
    elif indicator_type == "IP":
        xsoar_type = FeedIndicatorType.IP
        value = indicator_data_dict.get("ip")
    elif indicator_type == "URL":
        xsoar_type = FeedIndicatorType.URL
        value = indicator_data_dict.get("url")
    elif indicator_type == "EMAIL":
        xsoar_type = FeedIndicatorType.Email
        value = indicator_data_dict.get("email")
    elif indicator_type == "HASH":
        xsoar_type = FeedIndicatorType.File
        value = indicator_data_dict.get("hash")
    else:
        xsoar_type = FeedIndicatorType.Domain  # Default to domain
        value = indicator_data_dict.get("host") or indicator_data_dict.get("domain")

    return xsoar_type, value


def extract_indicator_fields(
    indicator_data: dict[str, Any], feed_tags: list[str] = None, tlp_color: str = None
) -> dict[str, Any]:
    """Extract fields from Infoblox indicator data based on mapping.

    Args:
        indicator_data (Dict[str, Any]): Indicator data from Infoblox.
        feed_tags (List[str], optional): Tags to add to the indicator. Defaults to None.
        tlp_color (str, optional): TLP color to set. Defaults to None.

    Returns:
        Dict[str, Any]: Mapped fields for the XSOAR indicator.
    """
    fields = {}

    for xsoar_field, mapping in INFOBLOX_FIELD_MAPPING.items():
        if mapping.get("path"):
            # Navigate nested fields using dot notation
            field_value: Any = indicator_data
            for path_part in mapping["path"].split("."):
                if field_value and isinstance(field_value, dict) and path_part in field_value:
                    field_value = field_value.get(path_part)
                else:
                    field_value = None
                    break

            if field_value is not None:
                # Convert field types
                if mapping.get("type") == "date" and field_value:
                    fields[xsoar_field] = field_value
                elif mapping.get("type") == "int":
                    try:
                        fields[xsoar_field] = int(field_value)
                    except (ValueError, TypeError):
                        pass
                elif mapping.get("type") == "bool":
                    fields[xsoar_field] = field_value.lower() == "true"
                else:
                    fields[xsoar_field] = field_value
        elif mapping.get("default") is not None:
            fields[xsoar_field] = mapping.get("default")

    # Add feed tags
    if feed_tags:
        fields["tags"] = feed_tags

    # Set TLP color if provided
    if tlp_color:
        fields["trafficlightprotocol"] = tlp_color

    return fields


def calculate_dbot_score(indicator_data: dict[str, Any]) -> int:
    """Calculate DBot score based on threat_level and confidence.

    Args:
        indicator_data (Dict[str, Any]): Indicator data from Infoblox.

    Returns:
        int: DBot score (1=Unknown, 2=Suspicious, 3=Malicious).
    """
    threat_level = indicator_data.get("threat_level", 0)

    if threat_level >= 80:
        return Common.DBotScore.BAD
    if threat_level >= 30:
        return Common.DBotScore.SUSPICIOUS
    if threat_level > 0:
        return Common.DBotScore.GOOD
    return Common.DBotScore.NONE


def validate_str_param(param: Any, param_name: str, required: bool = False) -> str:
    """Validate string parameter.

    Args:
        param: Parameter to validate.
        param_name: Parameter name for error message.
        required: Whether the parameter is required.

    Returns:
        Validated parameter or None if not required and empty.

    Raises:
        DemistoException: If parameter is required but empty or not a string.
    """
    if param is None:
        if required:
            raise DemistoException(f"Missing required parameter '{param_name}'")
        return None  # type: ignore

    if not isinstance(param, str):
        try:
            param = str(param)
        except (ValueError, TypeError):
            raise DemistoException(f"Parameter '{param_name}' must be a string or convertible to string")

    if not param.strip():
        if required:
            raise DemistoException(f"Parameter '{param_name}' cannot be empty")
        return None  # type: ignore

    return param.strip()


def validate_int_param(
    param: Any,
    param_name: str,
    required: bool = False,
    default: int | None = None,
    min_val: int | None = None,
    max_val: int | None = None,
) -> int | None:
    """Validate integer parameter.

    Args:
        param: Parameter to validate.
        param_name: Parameter name for error message.
        min_val: Minimum allowed value.
        max_val: Maximum allowed value.
        required: Whether the parameter is required.
        default: Default value if param is None.

    Returns:
        Validated parameter or default if not required and empty.

    Raises:
        DemistoException: If parameter is invalid.
    """
    if param is None:
        if required:
            raise DemistoException(f"Missing required parameter '{param_name}'")
        return default

    try:
        if isinstance(param, str):
            param = param.strip()
            if not param:
                if required:
                    raise DemistoException(f"Parameter '{param_name}' cannot be empty")
                return default
            val = int(param)
        elif isinstance(param, (int | float)):
            val = int(param)
        else:
            raise ValueError(f"Cannot convert {type(param).__name__} to int")

        # Special case for limit parameter to enforce MAX_INDICATORS_LIMIT
        if (param_name == "limit" or param_name == "max_fetch") and val > MAX_INDICATORS_LIMIT:
            demisto.debug(f"Requested {param_name} {val} exceeds maximum allowed {MAX_INDICATORS_LIMIT}, using maximum allowed")
            val = MAX_INDICATORS_LIMIT

        if min_val is not None and val < min_val:
            raise DemistoException(f"Parameter '{param_name}' must be at least {min_val}")

        if max_val is not None and val > max_val:
            raise DemistoException(f"Parameter '{param_name}' must be at most {max_val}")

        return val
    except ValueError as e:
        raise DemistoException(f"Parameter '{param_name}' must be a valid integer: {str(e)}") from e


def validate_datetime_param(time_string: str, param_name: str) -> str | None:
    """
    Validate a datetime.
    :param time_string: Time string.
    :param param_name: Name of the time string.
    :return: Validated datetime.
    """
    time_string = validate_str_param(time_string, param_name)
    time_obj = arg_to_datetime(time_string, param_name)
    if time_obj:
        return time_obj.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3]  # type: ignore
    return None


def get_first_fetch_time(first_fetch: str, default_hours: int = 1) -> str:
    """Parse first fetch time and return ISO format.

    Args:
        first_fetch (str): First fetch time string.
        default_hours (int, optional): Default hours to fetch if not provided. Defaults to 1 hour.

    Returns:
        str: ISO formatted datetime string.
    """
    if not first_fetch:
        first_fetch = f"{default_hours} hours"

    dt = dateparser.parse(first_fetch)
    if dt:
        return dt.strftime("%Y-%m-%dT%H:%M:%S.000Z")

    # If parsing failed, use default
    dt = dateparser.parse(f"{default_hours} hours")
    return dt.strftime("%Y-%m-%dT%H:%M:%S.000Z")  # type: ignore


""" COMMAND FUNCTIONS """


def command_test_module(client: Client):
    """Tests API connectivity and authentication.

    Returning 'ok' indicates that the integration works like it is supposed to.
    Connection to the service is successful.
    Raises exceptions if something goes wrong.

    :param client: Infoblox Threat Intelligence Feed client.
    :return: 'ok' if test passed.
    :rtype: ``str``
    """

    try:
        demisto.debug("Testing connectivity to Infoblox Threat Intelligence Feed")
        params = demisto.params()
        feed = params.get("feed", False)
        if feed:
            threshold = datetime.now() - timedelta(hours=4)
            threshold = threshold.strftime("%Y-%m-%dT%H:%M:%S.000Z")  # type: ignore
            first_fetch = params.get("first_fetch", DEFAULT_FIRST_FETCH)
            feed_fetch_interval = int(params.get("feedFetchInterval", 60))
            if feed_fetch_interval > 240:
                raise DemistoException("Feed fetch interval cannot be greater than 4 hours.")
            if get_first_fetch_time(first_fetch) < threshold:  # type: ignore
                raise DemistoException("First fetch time cannot be older than 4 hours.")
            fetch_indicators_command(client, params, {}, is_test=True)
        else:
            response = client.get_indicators(limit=1)
            if not response:
                raise DemistoException("Failed to retrieve data from Infoblox API. Empty response received.")

        demisto.debug("Successfully connected to Infoblox Threat Intelligence Feed.")
        return "ok"
    except DemistoException as e:
        if "401" in str(e):
            raise DemistoException("Authentication failed. Please verify your API key.") from e
        elif "404" in str(e):
            raise DemistoException("API endpoint not found. Please verify the URL.") from e
        elif "Connection error" in str(e) or "Read timed out" in str(e):
            raise DemistoException(f"Connection error: {str(e)}. Please check your network connectivity and server URL.") from e
        else:
            raise DemistoException(f"Failed to execute test-module. Error: {str(e)}") from e


def fetch_indicators_command(
    client: Client, params: dict[str, Any], last_run: dict[str, Any], is_test: bool = False
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Fetch indicators from Infoblox TIDE API.

    This function will fetch indicators from the Infoblox TIDE API based on the integration parameters
    and the last fetch time. It will update the last run information for incremental fetching.

    Args:
        client (Client): The client instance for API communication.
        params (Dict[str, Any]): The integration parameters.
        last_run (Dict[str, Any]): The last run information for incremental fetching.
        is_test (bool, optional): Whether this is a test run. Defaults to False.

    Returns:
        Tuple[List[Dict[str, Any]], Dict[str, Any]]: Indicators and next run information.
    """
    # Get parameters with validation
    feed_tags = argToList(params.get("feedTags", ""))
    tlp_color = validate_str_param(params.get("tlp_color"), "tlp_color") or "AMBER"

    # Get current time
    now_time = datetime.now()

    # Validate and parse integer parameters
    max_fetch = validate_int_param(
        params.get("max_fetch"), "max_fetch", min_val=1, max_val=MAX_INDICATORS_LIMIT, default=DEFAULT_LIMIT
    )

    # Get indicator types with validation
    indicator_types = argToList(params.get("indicator_types", []))

    dga_threat = params.get("dga_threat")
    dga_threat = arg_to_bool_or_none(dga_threat)
    threat_classes = argToList(params.get("threat_classes", []))
    profiles = argToList(params.get("data_provider_profiles", []))

    # Get last run information for incremental fetching or set to 1 hour ago if not available
    last_fetch_time = last_run.get("last_fetch_time")

    if not last_fetch_time:
        first_fetch = params.get("first_fetch", DEFAULT_FIRST_FETCH)
        last_fetch_time = get_first_fetch_time(first_fetch)

    max_fetch_time = now_time - timedelta(hours=4)
    max_fetch_time = max_fetch_time.strftime("%Y-%m-%dT%H:%M:%S.000Z")
    last_fetch_time = max(last_fetch_time, max_fetch_time)
    demisto.debug(f"Coercing last fetch time to: {last_fetch_time}")
    # Parse last_fetch_time to datetime object
    try:
        last_fetch_dt = datetime.strptime(last_fetch_time, "%Y-%m-%dT%H:%M:%S.000Z")
    except ValueError as e:
        demisto.debug(f"Error parsing last_fetch_time '{last_fetch_time}': {str(e)}\nUsing default date 1 hour ago.")
        last_fetch_dt = now_time - timedelta(hours=1)
        last_fetch_time = last_fetch_dt.strftime("%Y-%m-%dT%H:%M:%S.000Z")

    # Calculate to_fetch_dt as one day after from_fetch_dt, but not exceeding current time
    current_dt = now_time
    to_fetch_dt = current_dt

    # Format dates as strings for API call
    from_date = last_fetch_time
    to_date = to_fetch_dt.strftime("%Y-%m-%dT%H:%M:%S.000Z")

    if is_test:
        max_fetch = 1

    # Fetch indicators with detailed logging
    demisto.debug(
        "Fetching indicators with parameters:\n"
        + "  from_date: "
        + from_date
        + "\n"
        + "  to_date: "
        + to_date
        + "\n"
        + "  limit: "
        + str(max_fetch)
        + "\n"
        + "  indicator_types: "
        + str(indicator_types)
        + "\n"
        + "  dga_threat: "
        + str(dga_threat)
        + "\n"
        + "  threat_classes: "
        + str(threat_classes if threat_classes else "None")
        + "\n"
        + "  profiles: "
        + str(profiles if profiles else "None")
    )

    # Call API with validated parameters
    indicators_data = client.get_indicators(
        limit=max_fetch,
        indicator_types=indicator_types,
        from_date=from_date,
        to_date=to_date,
        dga_flag=dga_threat,
        threat_class=threat_classes if threat_classes else None,
        profile=profiles if profiles else None,
    )

    if is_test:
        return [], {}

    indicators = []

    # Process indicators with detailed logging
    demisto.debug(f"Processing {len(indicators_data)} indicators")
    for indicator_data in indicators_data:
        # Get indicator type and value
        xsoar_type, value = map_indicator_type(indicator_data)  # type: ignore

        if not value:
            demisto.debug(f"Skipping indicator with no value: {indicator_data.get('id', 'unknown ID')}")  # type: ignore
            continue

        # Extract fields
        fields = extract_indicator_fields(indicator_data, feed_tags, tlp_color)  # type: ignore

        # Calculate DBot score
        dbot_score = calculate_dbot_score(indicator_data)  # type: ignore

        # Create indicator object
        indicator_obj = {"value": value, "type": xsoar_type, "fields": fields, "rawJSON": indicator_data, "score": dbot_score}
        indicators.append(indicator_obj)

    # Update last run information for incremental fetching with improved logic
    # Always advance the fetch window to the to_date we used for this fetch
    # This ensures we pick up where we left off on the next execution
    next_run = {"last_fetch_time": to_date}
    demisto.debug(f"Advancing fetch time window to {to_date} for next execution")

    # Log summary of indicators fetched
    demisto.debug(
        f"Fetch summary: Retrieved {len(indicators)} indicators from {from_date} to {to_date}. "
        + f"Next fetch will start from {to_date}."
    )

    demisto.debug(f"Fetched {len(indicators)} indicators, next_run: {json.dumps(next_run)}")
    return indicators, next_run


def infoblox_get_indicators_command(client: Client, args: dict[str, Any], params: dict[str, Any]) -> CommandResults:
    """Get indicators manually from Infoblox TIDE API.

    Args:
        client (Client): Infoblox client.
        args (Dict[str, Any]): Command arguments.
        params (Dict[str, Any]): Integration parameters.

    Returns:
        CommandResults: Command results with indicators data.
    """
    # Get parameters with validation
    feed_tags = argToList(params.get("feedTags", ""))
    tlp_color = validate_str_param(params.get("tlp_color"), "tlp_color") or "AMBER"

    # Validate and parse integer parameters
    limit = validate_int_param(args.get("limit"), "limit", min_val=1, max_val=MAX_INDICATORS_LIMIT, default=DEFAULT_LIMIT)

    # Get other parameters with validation
    indicator_types = argToList(args.get("indicator_types", []))
    from_date = validate_datetime_param(args.get("from_date"), "from_date")  # type: ignore
    to_date = validate_datetime_param(args.get("to_date"), "to_date")  # type: ignore
    dga_flag = args.get("dga_threat")
    dga_flag = arg_to_bool_or_none(dga_flag)  # type: ignore
    threat_classes = argToList(args.get("threat_classes", []))
    data_provider_profiles = argToList(args.get("data_provider_profiles", []))

    # Log the query parameters
    demisto.debug(
        "Querying indicators with parameters:\n"
        + "  from_date: "
        + str(from_date)
        + "\n"
        + "  to_date: "
        + str(to_date)
        + "\n"
        + "  limit: "
        + str(limit)
        + "\n"
        + "  indicator_types: "
        + str(indicator_types)
        + "\n"
        + "  dga_flag: "
        + str(dga_flag)
        + "\n"
        + "  threat_classes: "
        + str(threat_classes if threat_classes else "None")
        + "\n"
        + "  data_provider_profiles: "
        + str(data_provider_profiles if data_provider_profiles else "None")
    )

    if indicator_types and limit < len(indicator_types):  # type: ignore
        raise ValueError("Limit must be greater than or equal to the number of indicator types.")
    elif not indicator_types and limit < TOTAL_INDICATOR_TYPES:  # type: ignore
        raise ValueError(f"Please provide indicator types when limit is less than {TOTAL_INDICATOR_TYPES}.")

    # Call API with validated parameters
    indicators_data = client.get_indicators(
        limit=limit,
        indicator_types=indicator_types,
        from_date=from_date,
        to_date=to_date,
        dga_flag=dga_flag,
        threat_class=threat_classes if threat_classes else None,
        profile=data_provider_profiles if data_provider_profiles else None,
    )

    # Extract indicators from response with proper type checking
    if not indicators_data:
        return CommandResults(
            readable_output="No indicators found.",
            raw_response=indicators_data,
        )

    indicators = []

    # Process indicators with detailed logging
    demisto.debug(f"Processing {len(indicators_data)} indicators for display")
    for indicator_data in indicators_data:
        xsoar_type, value = map_indicator_type(indicator_data)  # type: ignore

        if not value:
            demisto.debug(f"Skipping indicator with no value: {indicator_data.get('id', 'unknown ID')}")  # type: ignore
            continue

        fields = extract_indicator_fields(indicator_data, feed_tags, tlp_color)  # type: ignore
        indicators.append({"type": xsoar_type, "value": value, "fields": fields})

    # Create human-readable output
    headers = ["Type", "Value", "Threat Class", "Confidence", "Threat Level", "Expiration", "Property", "Profile"]

    readable_output = []
    for indicator in indicators:
        indicator_fields = indicator["fields"]
        readable_output.append(
            {
                "Type": indicator["type"],
                "Value": indicator["value"],
                "Threat Class": indicator_fields.get("category"),  # type: ignore
                "Confidence": indicator_fields.get("confidence"),  # type: ignore
                "Threat Level": indicator_fields.get("sourcepriority"),  # type: ignore
                "Expiration": indicator_fields.get("expirationdate"),  # type: ignore
                "Property": indicator_fields.get("malwarefamily"),  # type: ignore
                "Profile": indicator_fields.get("service"),  # type: ignore
            }
        )

    # Add summary information to the output
    summary = f"Found {len(indicators)} indicators"
    if from_date and to_date:
        summary += f" between {from_date} and {to_date}"

    readable_output_md = tableToMarkdown(
        f"Infoblox TIDE Indicators: {summary}", readable_output, headers=headers, removeNull=True
    )

    return CommandResults(
        readable_output=readable_output_md,
        outputs_prefix="Infoblox.FeedIndicator",
        outputs_key_field="id",
        outputs=transform_keys(indicators_data, RESPONSE_KEY_MAPPING),
        raw_response=indicators_data,
    )


def main():
    """Main function, parses params and runs command functions"""

    params = demisto.params()

    # Get API key for authentication
    api_key = params.get("api_key", {}).get("password")
    if not api_key:
        raise DemistoException("API Key must be provided.")

    # SSL verification and proxy settings
    verify_certificate = not params.get("insecure", False)
    proxy = params.get("proxy", False)

    # Get command and debug
    command = demisto.command()
    demisto.debug(f"Command being called is {command}")

    try:
        # Initialize client
        client = Client(api_key=api_key, verify=verify_certificate, proxy=proxy)
        # Parse command arguments
        args = demisto.args()

        # Execute command
        if command == "test-module":
            # This is the call made when pressing the integration Test button
            result = command_test_module(client)
            return_results(result)

        elif command == "fetch-indicators":
            # Command for scheduled fetch
            last_run = demisto.getLastRun()
            indicators, next_run = fetch_indicators_command(client, params, last_run)
            demisto.setLastRun(next_run)

            # Process indicators in batches to avoid memory issues
            for b in batch(indicators, batch_size=BATCH_SIZE):
                demisto.createIndicators(b)

        elif command == "infoblox-cloud-get-indicators":
            # Manual command to get indicators
            result = infoblox_get_indicators_command(client, args, params)
            return_results(result)

        else:
            raise NotImplementedError(f"Command {command} is not implemented")

    # Log exceptions and return errors
    except Exception as e:
        demisto.error(f"Error in {command} command: {str(e)}")
        return_error(f"Failed to execute {command} command.\nError:\n{str(e)}")


if __name__ in ("__main__", "__builtin__", "builtins"):  # pragma: no cover
    main()
