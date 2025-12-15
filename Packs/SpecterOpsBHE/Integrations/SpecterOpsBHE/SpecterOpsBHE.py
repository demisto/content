import demistomock as demisto  # noqa
from CommonServerPython import *  # noqa
from CommonServerUserPython import *  # noqa
import requests
import hmac
import hashlib
import base64
from datetime import datetime
from urllib.parse import (  # type: ignore[assignment]
    urljoin,  # type: ignore[assignment]
    quote_plus,  # type: ignore[assignment]
    urlparse,  # type: ignore[assignment]
    urlunparse,  # type: ignore[assignment]
)
import re
import time


# BHE Endpoints
ENDPOINTS = {
    "available_domain": "/api/v2/available-domains",
    "search": "/api/v2/search?q={query}",
    "dictionary_types": "/api/v2/{obj_type}s/{object_id}",
    "azure_types": ("/api/v2/azure/{obj_type}?object_id={object_id}&counts=false"),
    "shortest_path": ("/api/v2/graphs/shortest-path?" "start_node={start_node}&end_node={end_node}"),
    "domain_available_types": "/api/v2/domains/{domain}/available-types",
    "path_title": "/api/v2/assets/findings/{finding_type}/title.md",
    "attack_path_details": (
        "/api/v2/domains/{domain_id}/details?" "finding={finding_type}&skip={skip}&limit=1000&" "asset_group_tag_id=1"
    ),
    "base": "/api/v2/base/{object_id}",
    "azure_related_types": (
        "/api/v2/azure/tenants?" "object_id={object_id}&related_entity_type={rel_type}&" "skip=0&limit=100&counts=true"
    ),
    "update_primary_response": (
        "/api/v2/azure/{obj_type}?" "object_id={object_id}&related_entity_type={related_type}&" "skip=0&limit=100&counts=true"
    ),
    "short_description": ("/api/v2/assets/findings/{finding_type}/short_description.md"),
    "short_remediation": ("/api/v2/assets/findings/{finding_type}/short_remediation.md"),
    "long_remediation": ("/api/v2/assets/findings/{finding_type}/long_remediation.md"),
}

# Errors code:
BAD_REQUEST = 400
UNAUTHORIZED_REQUEST = 401
FORBIDDEN_REQUEST = 403
NOT_FOUND = 404
TOO_MANY_REQUEST = 429
SERVER_ERROR = 500

# Retry configuration
MAX_RETRIES = 3
RETRY_STATUS_CODES = [429, 500, 502, 503, 504]

# LOCK_TIMEOUT will be set in main() function
LOCK_TIMEOUT = 600  # Default value, will be updated in main()

SEVERITY_MAP = {"low": 1, "medium": 2, "moderate": 2, "high": 3, "critical": 4}

DIRECTORY_TYPES = [
    "User",
    "Computer",
    "Group",
    "Container",
    "Domain",
    "GPO",
    "Aiaca",
    "Rootca",
    "Enterpriseca",
    "Ntauthstore",
    "Certtemplate",
    "OU",
]

AZURE_TYPES = [
    "AZApp",
    "AZGroup",
    "AZUser",
    "AZRole",
    "AZTenant",
    "AZServicePrincipal",
    "AZAutomationAccount",
]

AZURE_RELATED_TYPES = {
    "AZApp": {"inbound-control": "inbound_object_control"},
    "AZGroup": {
        "group-membership": "group_membership",
        "group-members": "group_members",
        "roles": "roles",
        "inbound-control": "inbound_object_control",
        "outbound-control": "outbound_object_control",
    },
    "AZRole": {"active-assignments": "active_assignments"},
    "AZServicePrincipal": {
        "roles": "roles",
        "inbound-control": "inbound_object_control",
        "outbound-control": "outbound_object_control",
        "inbound-abusable-app-role-assignments": ("inbound_abusable_app_role_assignments"),
        "outbound-abusable-app-role-assignments": ("outbound_abusable_app_role_assignments"),
    },
    "AZUser": {
        "group-membership": "group_membership",
        "roles": "roles",
        "outbound-execution-privileges": "execution_privileges",
        "outbound-control": "outbound_object_control",
        "inbound-control": "inbound_object_control",
    },
}

AZ_TENANT_RELATED_TYPES = [
    "descendent-users",
    "descendent-groups",
    "descendent-management-groups",
    "descendent-subscriptions",
    "descendent-resource-groups",
    "descendent-virtual-machines",
    "descendent-managed-clusters",
    "descendent-vm-scale-sets",
    "descendent-container-registries",
    "descendent-web-apps",
    "descendent-automation-accounts",
    "descendent-key-vaults",
    "descendent-function-apps",
    "descendent-logic-apps",
    "descendent-applications",
    "descendent-service-principals",
    "descendent-devices",
    "inbound-control",
]


""" Exception Classes """


class BloodHoundException(Exception):
    """
    General Exception for BloodHound
    """


class BloodHoundValidationException(Exception):
    """
    Validation Exception for BloodHound
    """


class BloodHoundBadRequestException(Exception):
    """
    Bad Request Exception for BloodHound
    """


class BloodHoundNotFoundException(Exception):
    """
    Not Found Exception for BloodHound
    """


class BloodHoundUnauthorizedException(Exception):
    """
    Unauthorized Exception for BloodHound
    """


class BloodHoundForbiddenException(Exception):
    """
    Forbidden Exception for BloodHound
    """


class BloodHoundRateLimitException(Exception):
    """
    Rate Limit Exception for BloodHound
    """


class BloodHoundServerErrorException(Exception):
    """
    Server Error Exception for BloodHound
    """


"""
Lock Mechanism
"""


def acquire_lock():
    ctx = demisto.getIntegrationContext() or {}
    now = time.time()
    lock_time = float(ctx.get("lock_time", "0"))
    last_fetch = float(ctx.get("last_fetch_time", 0))

    if lock_time and now - lock_time < (LOCK_TIMEOUT):
        demisto.info("[FETCH-LOCK] Another fetch still running. " "Skipping this round.")
        return False

    if last_fetch and now - last_fetch < (LOCK_TIMEOUT):
        demisto.info(f"[FETCH-INTERVAL] Fetch already executed this interval " f"{last_fetch}. Skipping.")
        return False

    ctx["lock_time"] = str(now)
    demisto.setIntegrationContext(ctx)
    demisto.info(f"[FETCH-LOCK] Lock acquired at " f"{datetime.utcnow().isoformat()}")
    return True


def release_lock():
    ctx = demisto.getIntegrationContext() or {}
    now = time.time()
    ctx.pop("lock_time", None)
    ctx["last_fetch_time"] = str(now)
    demisto.setIntegrationContext(ctx)
    demisto.info(f"[FETCH-LOCK] Lock released at " f"{datetime.utcnow().isoformat()}")


""" CLIENT CLASS """


class Client(BaseClient):
    def __init__(
        self,
        bhe_domain,
        bhe_token_id,
        bhe_token_key,
        bhe_finding_domain,
        bhe_finding_category,
        custom_proxy_url=None,
        custom_proxy_username=None,
        custom_proxy_password=None,
    ):
        self.bhe_domain = bhe_domain
        self.__token_id = bhe_token_id
        self.__token_key = bhe_token_key
        self.bhe_finding_domain = bhe_finding_domain
        self.bhe_finding_category = bhe_finding_category
        self.custom_proxy_url = custom_proxy_url
        self.custom_proxy_username = custom_proxy_username
        self.custom_proxy_password = custom_proxy_password

    def _get_full_url(self, url_key: str, **kwargs: Any) -> str:
        """Construct full URL from endpoint key and parameters"""
        return urljoin(self.bhe_domain, ENDPOINTS[url_key].format(**kwargs))

    def _get_headers(self, method: str, uri: str) -> dict:
        """Generate authentication headers for API requests"""
        try:
            digester = hmac.new(self.__token_key.encode(), None, hashlib.sha256)
            digester.update(f"{method}{uri}".encode())
            digester = hmac.new(digester.digest(), None, hashlib.sha256)
            datetime_formatted = datetime.now().astimezone().isoformat("T")
            digester.update(datetime_formatted[:13].encode())
            digester = hmac.new(digester.digest(), None, hashlib.sha256)

            headers = {
                "User-Agent": "BloodHound Enterprise - XSOAR Integration",
                "Authorization": f"bhesignature {self.__token_id}",
                "RequestDate": datetime_formatted,
                "Signature": base64.b64encode(digester.digest()).decode(),
                "Content-Type": "application/json",
            }

            return headers
        except Exception as e:
            error_msg: str = f"Error generating headers: {e}"
            demisto.debug(error_msg)
            raise BloodHoundException(error_msg)

    @staticmethod
    def _validate_response(response: requests.Response, error_msg: str = "An error occurred"):
        """
        Validates the HTTP response and raises relevant exceptions
        """
        try:
            response.raise_for_status()
        except requests.HTTPError as error:
            try:
                json_resp = response.json()
            except Exception:
                error_content = response.content.decode("utf-8", errors="ignore") if response.content else "No response content"
                raise BloodHoundException(f"{error_msg}: {error} - {error_content}")

            if response.status_code == BAD_REQUEST:
                raise BloodHoundBadRequestException(f"{error_msg}: {error} - " f"{json_resp.get('message', 'Bad Request')}")
            elif response.status_code == NOT_FOUND:
                raise BloodHoundNotFoundException(f"{error_msg}: {error} - " f"{json_resp.get('message', 'Not Found')}")
            elif response.status_code == UNAUTHORIZED_REQUEST:
                raise BloodHoundUnauthorizedException(
                    f"{error_msg}: Unauthorized - " f"{json_resp.get('message', 'Unauthorized')}"
                )
            elif response.status_code == FORBIDDEN_REQUEST:
                raise BloodHoundForbiddenException(f"{error_msg}: Forbidden Error - " f"{json_resp.get('message', 'Forbidden')}")
            elif response.status_code == TOO_MANY_REQUEST:
                raise BloodHoundRateLimitException(f"{error_msg}: Rate Limit - " f"{json_resp.get('message', 'Rate Limit')}")
            elif response.status_code >= SERVER_ERROR:
                raise BloodHoundServerErrorException(
                    f"{error_msg}: Server Error ({response.status_code}) - "
                    f"{json_resp.get('message', 'Internal Server Error')}"
                )

            raise BloodHoundException(f"{error_msg}: {error} - {json_resp.get('message')}")

    def _build_proxy_dict(self):
        """Build proxy dictionary for requests if custom proxy is enabled"""
        if not self.custom_proxy_url:
            return None
        try:
            proxy_url = self.custom_proxy_url.strip()

            if not proxy_url:
                demisto.debug("Custom proxy URL is empty, " "skipping proxy configuration")
                return None

            if not proxy_url.startswith(("http://", "https://")):
                proxy_url = f"http://{proxy_url}"

            if self.custom_proxy_username and self.custom_proxy_password:
                username = quote_plus(self.custom_proxy_username)
                password = quote_plus(self.custom_proxy_password)
                parsed = urlparse(proxy_url)

                if parsed.netloc:
                    netloc = f"{username}:{password}@{parsed.netloc}"
                elif parsed.path:
                    netloc = f"{username}:{password}@{parsed.path}"
                else:
                    raise BloodHoundValidationException("Invalid proxy URL format: missing host")

                proxy_url = urlunparse((parsed.scheme, netloc, "", "", "", ""))
            masked_url = proxy_url.replace(self.custom_proxy_password, "***") if self.custom_proxy_password else proxy_url
            demisto.debug(f"Using custom proxy: {masked_url}")

            return {"http": proxy_url, "https": proxy_url}
        except Exception as e:
            demisto.error(f"Error building proxy configuration: {e}")
            raise BloodHoundException(f"Failed to configure proxy: {e}")

    def _execute_single_request(self, method: str, url: str, uri_path: str, params: Any, data: Any, proxies: Any):
        """
        Execute a single HTTP request attempt.

        Args:
            method: HTTP method (GET, POST, etc.)
            url: Full URL for the request
            uri_path: URI path for header generation
            params: Query parameters
            data: Request body data
            proxies: Proxy configuration

        Returns:
            JSON response or raw response object
        """
        headers = self._get_headers(method, uri_path)
        response = requests.request(
            method,
            url,
            headers=headers,
            params=params,
            data=data,
            proxies=proxies,
            verify=True,
            timeout=30,
        )
        return response

    def _handle_retryable_error(self, e: Exception, attempt: int, endpoint_key: str):
        """
        Handle retryable errors with direct retry.

        Args:
            e: The exception that occurred
            attempt: Current attempt number
            endpoint_key: Endpoint key for logging

        Raises:
            BloodHoundException: If max retries exceeded
        """
        if attempt < MAX_RETRIES:
            demisto.debug(
                f"Encountered retryable error: {str(e)}. " f"Retrying immediately " f"(attempt {attempt + 1}/{MAX_RETRIES + 1})"
            )
        else:
            demisto.error(f"Max retries ({MAX_RETRIES + 1}) exceeded " f"for {endpoint_key}: {str(e)}")
            raise

    def _handle_connection_error(self, e: Exception, error_type: str = "Connection"):
        """
        Handle proxy and connection errors.

        Args:
            e: The exception that occurred
            error_type: Type of error (Connection or Proxy)

        Raises:
            BloodHoundException: With detailed error message
        """
        error_msg = f"{error_type} error: {e}"
        if self.custom_proxy_url:
            if error_type == "Proxy":
                error_msg += f" Please verify that the proxy server at " f"{self.custom_proxy_url} is accessible and running."
            else:
                error_msg += f" Failed to connect to proxy at " f"{self.custom_proxy_url}."
        demisto.error(error_msg)
        raise BloodHoundException(error_msg)

    def _api_request(self, endpoint_key: str, return_json: bool = True, method: str = "GET", **kwargs: Any):
        """
        Makes an API request with retry logic for rate limiting and server errors.

        Args:
            endpoint_key: The endpoint key from ENDPOINTS dictionary
            return_json: Whether to return JSON response or raw response
            method: HTTP method (GET, POST, etc.)
            **kwargs: Additional parameters for URL formatting and request

        Returns:
            JSON response or raw response object

        Raises:
            BloodHoundException: For non-retryable errors or after max retries
        """
        # Prepare request parameters
        url = self._get_full_url(endpoint_key, **kwargs)
        uri_path = ENDPOINTS[endpoint_key].format(**kwargs)
        params = kwargs.get("params", None)
        data = kwargs.get("data", None)

        # Build proxy configuration if custom proxy is enabled
        proxies = self._build_proxy_dict()
        if proxies:
            demisto.debug(f"Proxy Configuration - {proxies}")
        # Retry loop for rate limiting and server errors
        for attempt in range(MAX_RETRIES + 1):
            try:
                # Execute the request
                response = self._execute_single_request(method, url, uri_path, params, data, proxies)

                # Validate response and return
                self._validate_response(response, f"API request to {endpoint_key} failed")
                return response.json() if return_json else response
            except (
                BloodHoundRateLimitException,
                BloodHoundServerErrorException,
            ) as e:
                # Handle retryable errors
                self._handle_retryable_error(e, attempt, endpoint_key)
                continue
            except (
                BloodHoundBadRequestException,
                BloodHoundUnauthorizedException,
                BloodHoundForbiddenException,
                BloodHoundNotFoundException,
            ):
                # Non-retryable errors - re-raise immediately
                raise
            except requests.exceptions.ProxyError as e:
                # Handle proxy errors
                self._handle_connection_error(e, "Proxy")
            except requests.exceptions.ConnectionError as e:
                # Handle connection errors
                self._handle_connection_error(e, "Connection")
            except Exception as e:
                # Handle unexpected errors
                demisto.error(f"Unexpected error in API request to {endpoint_key}: " f"{str(e)}")
                raise
        raise BloodHoundException(
            f"API request to {endpoint_key} failed: All retry attempts exhausted without returning a valid response"
        )

    def test_connection(self):
        """
        Tests the connection to the BloodHound Enterprise API.

        Returns:
            Response object: Raw HTTP response from the test connection endpoint.
        """
        return self._api_request("available_domain", return_json=False)


""" Fetch Attack Path  """


def get_available_domains(client: Client) -> tuple[bool, Any]:
    """
    Fetches the list of available domains from the BloodHound Enterprise API.
    Returns:
        Tuple (bool, response):
            - True and response object if successful
            - False and error/None if failed
    """
    try:
        response = client._api_request("available_domain")
        if response:
            return True, response
        else:
            demisto.debug("No response received while fetching available domains.")
            return False, None

    except Exception as e:
        demisto.debug(f"Exception occurred while fetching available domains: {e}")
        return False, e


def filter_domains(domains: dict[str, Any], selected_domains: str) -> dict[str, Any]:
    """
    Filter domains based on user selection

    Args:
        domains (dict): Dictionary of available domains
        selected_domains (str): Comma-separated string of domain names to include

    Returns:
        dict: Filtered domains dictionary

    Raises:
        Exception: If no domains match the selected domain names
    """
    demisto.info("Filtering domains")

    if not selected_domains or selected_domains.strip().lower() == "all":
        return domains

    domain_names_to_include = [name.strip() for name in selected_domains.split(",")]
    filtered_domains = {}
    for domain_id, domain_info in domains.items():
        if domain_info.get("name").strip() in domain_names_to_include:
            filtered_domains[domain_id] = domain_info

    if not filtered_domains:
        error_msg = "No domains matched the selected domain names. " "Please check your 'Selected Environments' configuration."
        demisto.debug(error_msg)
        raise Exception(error_msg)

    return filtered_domains


def get_path_title(client: Client, finding_type: str) -> str:
    """
    Fetches the path title markdown for a single finding type.
    Returns the markdown text or empty string if not found.
    """
    try:
        response = client._api_request(
            endpoint_key="path_title",
            return_json=False,
            finding_type=finding_type,
        )

        if response:
            return response.text
        else:
            demisto.debug("Received non-200 response or empty body.")
            return ""

    except Exception as e:
        demisto.debug(f"Failed to fetch title for finding type {finding_type}: {e}")
        return ""


def get_finding_type_short_description(client: Client, finding_type: str) -> str:
    """
    Fetches the short description markdown for a given finding type.

    Args:
        finding_type (str): Type of the finding to retrieve short description for.

    Returns:
        str: The markdown text if available, otherwise an empty string.
    """
    try:
        response = client._api_request(
            endpoint_key="short_description",
            return_json=False,
            finding_type=finding_type,
        )

        if response:
            return response.text
        else:
            demisto.debug("Received non-200 response or empty body.")
            return ""
    except Exception as e:
        demisto.debug(f"Failed to fetch short_description for finding type " f"{finding_type}: {e}")
        return ""


def get_finding_type_short_remediation(client: Client, finding_type: str) -> str:
    """
    Fetches the short remediation markdown for a given finding type.

    Args:
        finding_type (str): Type of the finding to retrieve short remediation for.

    Returns:
        str: The markdown text if available, otherwise an empty string.
    """
    try:
        response = client._api_request(
            endpoint_key="short_remediation",
            return_json=False,
            finding_type=finding_type,
        )

        if response:
            return response.text
        else:
            demisto.debug("Received non-200 response or empty body.")
            return ""

    except Exception as e:
        demisto.debug(f"Failed to fetch short_remediation for finding type " f"{finding_type}: {e}")
        return ""


def get_finding_type_long_remediation(client: Client, finding_type: str) -> str:
    """
    Fetches the long remediation markdown for a given finding type.

    Args:
        finding_type (str): Type of the finding to retrieve long remediation for.

    Returns:
        str: The markdown text if available, otherwise an empty string.
    """
    try:
        response = client._api_request(
            endpoint_key="long_remediation",
            return_json=False,
            finding_type=finding_type,
        )

        if response:
            return response.text
        else:
            demisto.debug("Received non-200 response or empty body.")
            return ""

    except Exception as e:
        demisto.debug(f"Failed to fetch long_remediation for finding type " f"{finding_type}: {e}")
        return ""


def fetch_path_info(client: Client, domains: dict[str, Any]) -> dict[str, Any]:
    """
    Fetch path metadata for each unique finding type, including:
    - Title
    - Short Remediation
    - Long Remediation


    Returns:
        dict: Dictionary mapping finding types to their path metadata
    """
    demisto.info("Fetching path details for each unique finding type...")

    unique_finding_types = set()
    for domain_info in domains.values():
        unique_finding_types.update(domain_info.get("available_types", []))

    demisto.info(f"Found {len(unique_finding_types)} unique finding types " f"to fetch details for.")

    path_details = {}
    for finding_type in unique_finding_types:
        try:
            title = get_path_title(client, finding_type)
            short_description = get_finding_type_short_description(client, finding_type)
            short_remediation = get_finding_type_short_remediation(client, finding_type)
            long_remediation = get_finding_type_long_remediation(client, finding_type)

            if not title:
                demisto.debug(f"Failed to fetch title for {finding_type}, " f"using finding_type as fallback.")
                title = finding_type

            path_details[finding_type] = {
                "title": title,
                "short_remediation": short_remediation,
                "long_remediation": long_remediation,
                "short_description": short_description,
            }
        except Exception as e:
            demisto.debug(f"Failed to fetch path details for {finding_type}: {e}")
            path_details[finding_type] = {
                "title": finding_type,
                "short_remediation": "",
                "long_remediation": "",
                "short_description": "",
            }

    return path_details


def get_attack_path_details_page(
    client: Client,
    domain_id: str,
    finding_type: str,
    skip: int = 0,
    created_at: str = None,
) -> list:
    """
    Fetches a single page of attack path details for the given domain and finding type.
    Pagination is handled outside this method using the `skip` parameter.
    Optionally filters results to only those created after a specified date.

    Args:
        domain_id: The domain ID to fetch attack paths for
        finding_type: The type of finding to fetch
        skip: Number of results to skip (for pagination)
        created_at: Optional date string in YYYY-MM-DD format to filter results by created date

    Returns:
        list: Attack path details data
    """
    try:
        params: dict[str, Any] = {}

        if created_at:
            params["created_at"] = created_at

        params["sort_by"] = "created_at"

        response = client._api_request(
            "attack_path_details",
            domain_id=domain_id,
            finding_type=finding_type,
            skip=skip,
            **params,
        )
        return response.get("data", []) if response else []
    except Exception as e:
        demisto.debug(f"Failed to fetch attack path details for domain {domain_id}, " f"finding type {finding_type}: {e}")
        return []


def _paginate_and_filter_attack_paths(
    client: Client,
    domain_id: str,
    finding_type: str,
    finding_type_key: str,
    last_created_at_timestamp: str | None,
    finding_type_latest_dates: dict[str, str],
):
    """
    Paginate through attack path details and filter for newer paths.

    Args:
        client: BHE client instance
        domain_id: Domain ID to fetch paths for
        finding_type: Type of finding to fetch
        finding_type_key: Composite key for timestamp tracking
        last_created_at_timestamp: Timestamp to filter by
        finding_type_latest_dates: Dictionary to update with latest timestamps

    Returns:
        list: Filtered attack paths that are newer than the timestamp
    """
    filtered_attack_paths = []
    skip = 0
    max_pages = 1000  # Safety limit to prevent infinite loops

    # Paginate through all attack paths
    for _page_num in range(max_pages):
        page = get_attack_path_details_page(
            client,
            domain_id,
            finding_type,
            skip=skip,
            created_at=last_created_at_timestamp,
        )

        # Break if no more pages
        if not page:
            break

        # Filter for newer paths
        newer_paths = []
        for attack_path in page:
            created_at = attack_path.get("created_at")
            is_newer = created_at and (not last_created_at_timestamp or created_at > last_created_at_timestamp)
            if is_newer:
                newer_paths.append(attack_path)
                # Update latest timestamp for this specific finding type
                if finding_type_key not in finding_type_latest_dates or created_at > finding_type_latest_dates[finding_type_key]:
                    finding_type_latest_dates[finding_type_key] = created_at

        filtered_attack_paths.extend(newer_paths)
        skip += len(page)

    return filtered_attack_paths


def _get_last_timestamp_for_finding_type(last_run: dict, finding_type_key: str, domain_name: str) -> Any | None:
    """
    Get the last timestamp for a finding type, with backward compatibility.

    Args:
        last_run: Dictionary containing last run timestamps
        finding_type_key: Composite key for finding type
        domain_name: Domain name for legacy timestamp lookup

    Returns:
        str: Last created_at timestamp or None
    """
    last_created_at_timestamp = last_run.get(finding_type_key)

    # Backward compatibility: check for old domain-level timestamp
    # if finding-type-specific not found
    if not last_created_at_timestamp:
        last_created_at_timestamp = last_run.get(domain_name)
        if last_created_at_timestamp:
            demisto.debug(
                f"Using legacy domain-level timestamp for "
                f"{finding_type_key}. "
                f"Will migrate to finding-type-specific tracking "
                f"after this fetch."
            )

    return last_created_at_timestamp


def fetch_attack_path_details(client: Client, last_run: dict[str, Any], domains: dict[str, Any]) -> tuple[dict, dict]:
    """
    Fetch attack path details for each domain and finding type,
    using the last update date as a filter when available.
    Only returns attack paths that are newer than the stored last created_at date.
    Tracks timestamps per (domain, finding_type) combination for granular control.

    Returns:
        tuple: (attack path details dict, finding_type_latest_dates dict)
    """
    demisto.info("Starting attack path fetch process across all domains and types...")

    attack_path_details = {}
    domain_attack_path_counts = {}
    finding_type_latest_dates: dict[str, str] = {}

    # Process each domain
    for domain_id, domain_info in domains.items():
        domain_name = domain_info.get("name", "unknown")
        types = domain_info.get("available_types", [])
        domain_attack_path_counts[domain_name] = 0

        demisto.info(f"Processing domain: {domain_name} with {len(types)} " f"finding types.")

        # Process each finding type for the domain
        for finding_type in types:
            # Create composite key for finding-type-specific timestamp tracking
            finding_type_key = f"{domain_name}:{finding_type}"
            last_created_at_timestamp = _get_last_timestamp_for_finding_type(last_run, finding_type_key, domain_name)

            # Log timestamp usage
            if last_created_at_timestamp:
                demisto.info(f"Using last created_at timestamp for " f"{finding_type_key}: {last_created_at_timestamp}.")
            else:
                demisto.info(f"No last created_at timestamp found for " f"{finding_type_key}, will fetch all attack paths.")

            # Paginate and filter attack paths
            filtered_attack_paths = _paginate_and_filter_attack_paths(
                client,
                domain_id,
                finding_type,
                finding_type_key,
                last_created_at_timestamp,
                finding_type_latest_dates,
            )

            # Store results if any paths found
            if filtered_attack_paths:
                attack_path_details[(domain_id, finding_type)] = filtered_attack_paths
                domain_attack_path_counts[domain_name] += len(filtered_attack_paths)
                demisto.info(
                    f"{finding_type_key}: Found {len(filtered_attack_paths)} "
                    f"new attack paths. "
                    f"Latest created_at: "
                    f"{finding_type_latest_dates.get(finding_type_key, 'N/A')}"
                )
            else:
                # Preserve existing timestamp even if no new paths found
                if finding_type_key not in finding_type_latest_dates and last_created_at_timestamp:
                    finding_type_latest_dates[finding_type_key] = last_created_at_timestamp

        demisto.info(
            f"Domain {domain_name}: " f"{domain_attack_path_counts.get(domain_name, 0)} " f"total new attack paths found"
        )

    return attack_path_details, finding_type_latest_dates


def get_available_types_for_domain(client: Client, domain: str) -> list:
    """Fetch available types for a single domain."""
    try:
        response = client._api_request("domain_available_types", domain=domain)
        if response:
            return response.get("data", [])
        else:
            demisto.debug("Received non-200 response or empty body.")
            return []
    except Exception as e:
        demisto.debug(f"Exception occurred while fetching attack path types " f"for domain {domain}: {e}")
        return []


def collect_available_types(client: Client, domains: dict[str, Any]) -> dict[str, Any]:
    """
    Collect available types for each domain and add them to domain info

    Args:
        bhe_manager: BloodHound Enterprise manager instance
        domains: Dictionary mapping domain IDs to domain information

    Returns:
        dict: Updated domains dictionary with available types
    """
    demisto.info("Collecting available finding types for each domain...")
    for domain_id in domains:
        demisto.info(f"Fetching finding types for domain: " f"{domains[domain_id].get('name', domain_id)}")
        types = get_available_types_for_domain(client, domain_id)
        domains[domain_id]["available_types"] = types
    return domains


def filter_finding_types(domains: dict[str, Any], selected_finding_types: str) -> dict[str, Any]:
    """
    Filter finding types for each domain based on user selection

    Args:
        domains (dict): Dictionary of domains with their available types
        selected_finding_types (str): Comma-separated string of finding types to include

    Returns:
        dict: Domains dictionary with filtered available_types

    Raises:
        Exception: If no domain has any matching finding types
    """
    demisto.info(f"Filtering finding types using user input: " f"{selected_finding_types}")
    if not selected_finding_types or selected_finding_types.strip().lower() == "all":
        return domains

    finding_types_to_include = [ftype.strip() for ftype in selected_finding_types.split(",")]

    any_domain_has_findings = False

    for domain_id in domains:
        if "available_types" in domains[domain_id]:
            # Filter finding types to only include selected types
            domains[domain_id]["available_types"] = [
                ftype for ftype in domains[domain_id]["available_types"] if ftype in finding_types_to_include
            ]

            if domains[domain_id]["available_types"]:
                any_domain_has_findings = True
    if not any_domain_has_findings:
        error_msg = (
            "No finding types matched the selected finding types. " "Please check your 'Selected Finding Types' configuration."
        )
        demisto.error(error_msg)
    return domains


def _extract_bhe_instance(bhe_domain: str) -> str:
    """
    Extract BHE instance name from domain URL.

    Args:
        bhe_domain: BHE domain URL

    Returns:
        str: Uppercase instance name
    """
    pattern = r"(?:https?:\/\/)?([a-zA-Z0-9-]+)(?:\.[a-zA-Z0-9.-]+)+"
    match_pattern = re.search(pattern, bhe_domain)
    if match_pattern:
        return match_pattern.group(1).upper()
    return bhe_domain.upper()


def _group_attack_paths_by_domain(
    attack_path_details: dict,
    domains: dict,
    attack_paths_info: dict,
) -> dict:
    """
    Group attack paths by domain name and path title.

    Args:
        attack_path_details: Dictionary of attack path details
        domains: Dictionary of domain information
        attack_paths_info: Dictionary of path information by finding type

    Returns:
        dict: Grouped attack paths by domain and path title
    """
    domain_path_groups: dict[str, dict[str, list[tuple[str, dict[str, Any]]]]] = {}

    # Group by domain and path title
    for (domain_id, finding_type), attack_paths in attack_path_details.items():
        domain_name = domains.get(domain_id, {}).get("name", "unknown")
        path_info = attack_paths_info.get(finding_type, {})
        path_title = path_info.get("title", finding_type)

        if domain_name not in domain_path_groups:
            domain_path_groups[domain_name] = {}

        if path_title not in domain_path_groups[domain_name]:
            domain_path_groups[domain_name][path_title] = []

        for path in attack_paths:
            domain_path_groups[domain_name][path_title].append((finding_type, path))

    return domain_path_groups


def _extract_object_ids(item: dict) -> list:
    """
    Extract object IDs from attack path item.

    Args:
        item: Attack path item dictionary

    Returns:
        list: List of object IDs
    """
    if "FromPrincipalProps" in item:
        return list(
            filter(
                None,
                [
                    item.get("FromPrincipalProps", {}).get("objectid"),
                    item.get("ToPrincipalProps", {}).get("objectid"),
                ],
            )
        )
    elif item.get("Props", {}).get("objectid"):
        return [item.get("Props", {}).get("objectid")]
    return []


def _extract_object_names(item: dict) -> list:
    """
    Extract object names from attack path item.

    Args:
        item: Attack path item dictionary

    Returns:
        list: List of object names
    """
    if "FromPrincipalProps" in item:
        return list(
            filter(
                None,
                [
                    item.get("FromPrincipalProps", {}).get("name"),
                    item.get("ToPrincipalProps", {}).get("name"),
                ],
            )
        )
    elif item.get("Props", {}).get("name"):
        return [item.get("Props", {}).get("name")]
    return []


def _create_event_dict(
    item: dict,
    domain_name: str,
    path_title: str,
    finding_type: str,
    current_time: str,
    short_remediation: str,
    long_remediation: str,
    short_description: str,
) -> dict:
    """
    Create event dictionary from attack path item.

    Args:
        item: Attack path item dictionary
        domain_name: Domain name
        path_title: Path title
        finding_type: Finding type
        current_time: Current timestamp
        short_remediation: Short remediation text
        long_remediation: Long remediation text
        short_description: Short description text

    Returns:
        dict: Event dictionary
    """
    attack_id = item.get("id", "unknown")
    severity = str(item.get("Severity", "low")).lower()
    object_ids = _extract_object_ids(item)
    object_names = _extract_object_names(item)

    event = {
        "StartTime": current_time,
        "EndTime": current_time,
        "Name": f"Attack Path {attack_id}",
        "ObjectIds": ", ".join(object_ids),
        "ObjectNames": ", ".join(object_names),
        "AttackId": attack_id,
        "Domain": domain_name,
        "Severity": severity,
        "PathTitle": path_title.strip(),
        "FindingType": finding_type,
        "DomainSID": item.get("DomainSID"),
        # Convert impact percentage from decimal to percentage
        "ImpactPercentage": round(float(item.get("ImpactPercentage", 0)) * 100, 2),
        "ImpactCount": item.get("ImpactCount"),
        # Convert exposure percentage from decimal to percentage
        "ExposurePercentage": round(float(item.get("ExposurePercentage", 0)) * 100, 2),
        "ExposureCount": item.get("ExposureCount"),
        "AcceptedUntil": item.get("AcceptedUntil"),
        "Accepted": item.get("Accepted"),
        "CreatedAt": item.get("created_at"),
        "UpdatedAt": item.get("updated_at"),
        "ShortRemediation": short_remediation.strip(),
        "LongRemediation": long_remediation.strip(),
        "ShortDescription": short_description.strip(),
    }

    # Set impacted principal information with fallback values
    event["ImpactedPrincipal"] = item.get("Principal", item.get("ToPrincipal"))
    event["ImpactedPrincipalKind"] = item.get("PrincipalKind", item.get("ToPrincipalKind"))
    event["ImpactedPrincipalName"] = item.get("PrincipalName", item.get("ToPrincipalName"))
    event["ImpactedPrincipalEnvironment"] = item.get("Environment", item.get("ToEnvironment"))

    # Extract object ID for impacted principal
    to_principal_obj_id = item.get("ToPrincipalProps", {}).get("objectid")
    props_obj_id = item.get("Props", {}).get("objectid")
    event["ImpactedPrincipalObjectId"] = to_principal_obj_id or props_obj_id

    # Add non-tier-zero principal information if available
    if "FromPrincipal" in item:
        event["NonTierZeroPrincipal"] = item.get("FromPrincipal")
        event["NonTierZeroPrincipalName"] = item.get("FromPrincipalName")
        event["NonTierZeroPrincipalKind"] = item.get("FromPrincipalKind")
        event["NonTierZeroPrincipalEnvironment"] = item.get("FromEnvironment")
        from_principal_obj_id = item.get("FromPrincipalProps", {}).get("objectid")
        props_obj_id = item.get("Props", {}).get("objectid")
        event["NonTierZeroPrincipalObjectId"] = from_principal_obj_id or props_obj_id

    return event


def _create_incident_dict(
    bhe_instance: str,
    domain_name: str,
    path_title: str,
    event: dict,
    severity: str,
    current_time: str,
    short_description: str,
    short_remediation: str,
) -> dict:
    """
    Create incident dictionary from event data.

    Args:
        bhe_instance: BHE instance name
        domain_name: Domain name
        path_title: Path title
        event: Event dictionary
        severity: Severity level
        current_time: Current timestamp
        short_description: Short description text
        short_remediation: Short remediation text

    Returns:
        dict: Incident dictionary
    """
    return {
        "name": f"{bhe_instance} - {domain_name} - {path_title}",
        "type": "SpecterOpsBHE Attack Path",
        "severity": SEVERITY_MAP.get(severity, 1),
        "occurred": current_time,
        "rawJSON": json.dumps(event),
        "details": (
            f"New attack paths detected in domain {domain_name}. "
            f"Short Description: {short_description}, "
            f"Short Remediation: {short_remediation}"
        ),
    }


def create_incidents(
    client: Client, attack_path_details: dict[str, Any], domains: dict[str, Any], attack_paths_info: dict[str, Any]
) -> list[dict[str, Any]]:
    """
    Create a list of incidents based on attack path details.
    Each incident will contain information about all the attack paths
    found for a specific domain and path title.
    """
    try:
        incidents: list[dict[str, Any]] = []
        current_time = datetime.utcnow().isoformat() + "Z"

        # Extract BHE instance name from domain
        bhe_instance = _extract_bhe_instance(client.bhe_domain)

        # Group attack paths by domain and path title
        domain_path_groups = _group_attack_paths_by_domain(attack_path_details, domains, attack_paths_info)

        if not domain_path_groups:
            # Return empty list if no attack paths are found
            return incidents

        # Create incidents for each grouped path
        for domain_name, attack_paths_info_dict in domain_path_groups.items():
            for path_title, attack_paths_with_type in attack_paths_info_dict.items():
                if not attack_paths_with_type:
                    continue

                # Get path information for the finding type
                finding_type = attack_paths_with_type[0][0]
                path_info = attack_paths_info.get(finding_type, {})
                short_remediation = path_info.get("short_remediation", "")
                long_remediation = path_info.get("long_remediation", "")
                short_description = path_info.get("short_description", "")

                # Create incident for each attack path
                for finding_type, item in attack_paths_with_type:
                    # Create event dictionary
                    event = _create_event_dict(
                        item,
                        domain_name,
                        path_title,
                        finding_type,
                        current_time,
                        short_remediation,
                        long_remediation,
                        short_description,
                    )

                    # Create incident dictionary
                    severity = str(item.get("Severity", "low")).lower()
                    incident = _create_incident_dict(
                        bhe_instance,
                        domain_name,
                        path_title,
                        event,
                        severity,
                        current_time,
                        short_description,
                        short_remediation,
                    )

                    incidents.append(incident)

        return incidents
    except Exception as e:
        demisto.error(f"Error in create_incidents: {str(e)}")
        return []


def fetch_incidents(bhe_client: Client):
    if not acquire_lock():
        demisto.info("[FETCH] Lock not acquired, sending empty incident list.")
        demisto.incidents([])
        return None
    try:
        demisto.info("Executing fetch_incidents function")
        last_run = demisto.getLastRun()

        status, domains_response = get_available_domains(bhe_client)
        if not status:
            return []

        domains_data = domains_response.get("data", [])
        demisto.info(f"Found {len(domains_data)} domains from API")
        domains = {domain["id"]: domain for domain in domains_data if domain["collected"]}
        demisto.info(f"Found {len(domains)} collected domains")
        domains = filter_domains(domains, bhe_client.bhe_finding_domain)
        demisto.info(f"After domain filtering: {len(domains)} domains remain")
        domains = collect_available_types(bhe_client, domains)
        demisto.info("Completed collecting available types for all domains")
        domains = filter_finding_types(domains, bhe_client.bhe_finding_category)
        demisto.info("Completed filtering finding types")
        attack_paths_info = fetch_path_info(bhe_client, domains)
        demisto.info(f"Fetched path info for {len(attack_paths_info)} finding types")
        # Fetch attack path details and track latest timestamps
        attack_path_details, finding_type_latest_dates = fetch_attack_path_details(bhe_client, last_run, domains)

        # Create Incident
        incidents = create_incidents(bhe_client, attack_path_details, domains, attack_paths_info)

        if last_run is None:
            last_run = {}
        last_run.update(finding_type_latest_dates)
        demisto.setLastRun(last_run)
        demisto.incidents(incidents)

    except Exception as e:
        demisto.error(f"Error in fetch_incidents: {str(e)}")
    finally:
        release_lock()


""" Commands  """


def get_object_id_by_name(client: Client, name: str) -> dict:
    """
    Fetches the object_id of a node based on its name.
    Returns a dictionary with status, message, and object_id (if found).
    """
    try:
        response = client._api_request("search", query=name)
        if response.get("data"):
            return {
                "status": "success",
                "message": "Object ID found.",
                "data": response.get("data"),
            }
        else:
            return {"status": "success", "message": "Object ID Not found."}
    except Exception as e:
        return {"status": "error", "message": str(e), "data": None}


def get_object_id(bhe_client: Client, names: list[str]) -> dict:
    try:
        response_payload: dict[str, dict] = {}
        for name in names:
            encoded_name = name.strip().replace(" ", "%20").replace("@", "%40")
            response = get_object_id_by_name(bhe_client, encoded_name)
            response_payload[name] = response
        return response_payload
    except Exception as e:
        demisto.error(f"Error - {str(e)}")
        return {"status": "error", "message": str(e)}


def _handle_fetch_asset_information(client: Client, object_id: str) -> dict:
    """
    Retrieves asset information based on the given object ID.

    Steps:
    - Searches for the object using its ID.
    - Determines the type of the object and fetches its primary details.
    - If the object is of Azure type, also fetches and appends related data.

    Args:
        object_id (str): The unique object ID to search.

    Returns:
        dict: Dictionary containing status, message, and asset data.
    """
    try:
        response = client._api_request("search", query=object_id)

        if not response.get("data"):
            return {"status": "error", "message": "Object Id not available"}

        if response.get("data") == []:
            return {"status": "success", "message": "Received empty response from server."}

        obj_type = response["data"][0]["type"]

        primary_response = _fetch_primary_response(client, object_id, obj_type)

        if not primary_response:
            return {"status": "error", "message": "Failed to fetch primary response"}

        if obj_type.startswith("AZ"):
            try:
                _handle_azure_types(client, object_id, obj_type, primary_response)
            except Exception as e:
                demisto.debug(f"Error fetching Azure related data for {object_id}: {e}")

        return {
            "status": "success",
            "message": "Asset fetched",
            "data": primary_response.get("data", {}),
        }
    except BloodHoundException as e:
        error_msg = str(e).lower()
        if "memory" in error_msg or "volume" in error_msg or "limitation" in error_msg:
            return {
                "status": "error",
                "message": (f"Memory limitation encountered for object " f"{object_id}: {e}"),
            }
        else:
            return {"status": "error", "message": f"API error for object {object_id}: {e}"}
    except Exception as e:
        return {"status": "error", "message": f"Unexpected error for object {object_id}: {e}"}


def _fetch_primary_response(client: Client, object_id: str, obj_type: str) -> dict:
    """
    Fetches the primary asset data based on object type and ID.

    Args:
        object_id (str): The unique identifier for the asset.
        obj_type (str): The type of the object (e.g., AZApp, AZUser, etc.).

    Returns:
        dict: API response containing primary asset data.
    """
    endpoint_type: str
    params: dict[str, Any]

    if obj_type in DIRECTORY_TYPES:
        endpoint_type = "dictionary_types"
        params = {"obj_type": obj_type.lower(), "object_id": object_id}
    elif obj_type in AZURE_TYPES:
        endpoint_type = "azure_types"
        params = {"obj_type": _get_azure_type_path(obj_type), "object_id": object_id}
    else:
        endpoint_type = "base"
        params = {"object_id": object_id}

    return client._api_request(endpoint_type, **params)


def _get_azure_type_path(obj_type: str) -> str:
    """
    Converts Azure object type to appropriate API path component.

    Args:
        obj_type (str): Azure object type (e.g., AZServicePrincipal).

    Returns:
        str: Corresponding path segment for the API.
    """
    if obj_type == "AZServicePrincipal":
        return "service-principals"
    elif obj_type == "AZApp":
        return "applications"
    return (obj_type[2:] + "s").lower()


def _handle_azure_types(client: Client, object_id: str, obj_type: str, primary_response: dict) -> None:
    """
    Enhances the primary response with Azure-specific related entity counts.

    Args:
        object_id (str): The object ID to enrich.
        obj_type (str): The Azure object type.
        primary_response (dict): The response dictionary to update.
    """
    if obj_type == "AZTenant":
        result_msg = _process_az_tenant(client, object_id, primary_response)
        if result_msg and "Skipped" in result_msg:
            demisto.debug(f"AZTenant processing result: {result_msg}")
    else:
        related_types = AZURE_RELATED_TYPES.get(obj_type, {})

        for related_type, mapping_key in related_types.items():
            _update_primary_response(
                client,
                primary_response,
                object_id,
                obj_type,
                related_type,
                mapping_key,
            )


def _process_az_tenant(client: Client, object_id: str, primary_response: dict) -> str:
    """
    Processes AZTenant-specific related entity counts and enriches primary response.

    Args:
        object_id (str): Object ID of the AZTenant.
        primary_response (dict): Dictionary to be enriched with counts.

    Returns:
        str: Success message if processing completes, error message if an exception occurs.
    """
    descendent_count = 0
    inbound_control_count = 0

    for rel_type in AZ_TENANT_RELATED_TYPES:
        try:
            # Fetch related types for Azure tenant
            secondary_response = client._api_request(
                "azure_related_types",
                rel_type=rel_type,
                object_id=object_id,
            )

            if secondary_response and "count" in secondary_response:
                if rel_type == "inbound-control":
                    inbound_control_count = secondary_response["count"]
                else:
                    descendent_count += secondary_response["count"]
            else:
                demisto.debug(f"Failed to fetch data for related type: {rel_type}")
        except (
            BloodHoundException,
            requests.exceptions.Timeout,
            requests.exceptions.RequestException,
        ) as e:
            error_msg = str(e).lower()
            if "timeout" in error_msg or "waiting for engine" in error_msg:
                error_msg = f"Skipped AZTenant {object_id} due to timeout/request error: {str(e)}"
                demisto.debug(error_msg)
                return error_msg
            elif "memory" in error_msg or "volume" in error_msg or "limitation" in error_msg:
                demisto.debug(f"Memory limitation encountered for AZTenant " f"{rel_type}, skipping: {e}")
            else:
                demisto.debug(f"Error fetching data for related type {rel_type}: {e}")
        except Exception as e:
            error_msg = f"Skipped AZTenant {object_id} due to unexpected error: {str(e)}"
            demisto.debug(error_msg)
            return error_msg

    if "data" in primary_response:
        primary_response["data"]["inbound_object_control"] = inbound_control_count
        primary_response["data"]["descendents"] = {"descendent_counts": descendent_count}

    return f"Successfully processed AZTenant {object_id}"


def _update_primary_response(
    client: Client,
    primary_response: dict,
    object_id: str,
    obj_type: str,
    related_type: str,
    mapping_key: str,
) -> None:
    """
    Fetches count of related entities and updates the primary response accordingly.

    Args:
        primary_response (dict): The original asset data to be enriched.
        object_id (str): Object identifier.
        obj_type (str): Object type.
        related_type (str): Type of related entity to query.
        mapping_key (str): Key under which to store the count in the response.
    """
    try:
        # Fetch related entity count for the primary response
        secondary_response = client._api_request(
            "update_primary_response",
            obj_type=obj_type,
            object_id=object_id,
            related_type=related_type,
        )

        if not secondary_response or "count" not in secondary_response:
            demisto.debug(f"Failed to fetch data for related type: {related_type}")
            primary_response["data"][mapping_key] = 0
            return

        primary_response["data"][mapping_key] = secondary_response["count"]
    except BloodHoundException as e:
        error_msg = str(e).lower()
        if "memory" in error_msg or "volume" in error_msg or "limitation" in error_msg:
            demisto.debug(f"Memory limitation encountered for {obj_type} " f"{related_type}, setting count to 0: {e}")
            primary_response["data"][mapping_key] = 0
        else:
            demisto.debug(f"Error fetching data for related type {related_type}: {e}")
            primary_response["data"][mapping_key] = 0
    except Exception as e:
        demisto.debug(f"Unexpected error fetching data for related type {related_type}: {e}")
        primary_response["data"][mapping_key] = 0


def fetch_asset_info(bhe_client: Client, object_ids: list[str]) -> dict:
    try:
        response_payload_asset: dict[str, dict] = {}
        for object_id in object_ids:
            clean_object_id = object_id.strip()
            asset_info = _handle_fetch_asset_information(bhe_client, clean_object_id)
            response_payload_asset[object_id] = asset_info
        return response_payload_asset
    except Exception as e:
        return {"status": "error", "message": f"Error: {str(e)}"}


def does_path_exists_between_nodes(client: Client, start_node: str, end_node: str) -> dict:
    """
    Checks if a shortest path exists between two nodes in BloodHound Enterprise.
    Returns a dictionary with status, message, and data (True/False).
    """
    try:
        # Check if path exists between nodes
        client._api_request(
            "shortest_path",
            return_json=False,
            start_node=start_node,
            end_node=end_node,
        )
        return {"status": "success", "message": "Path exists between nodes.", "data": True}
    except BloodHoundServerErrorException:
        return {
            "status": "error",
            "message": ("Internal server error or path does not exist"),
            "data": False,
        }
    except Exception as e:
        return {"status": "error", "message": str(e), "data": False}


def test_module(bhe_client: Client) -> str:
    try:
        bhe_client.test_connection()
        return "ok"
    except BloodHoundUnauthorizedException:
        return "Test failed: Unauthorized - Please verify that your " "Token ID and Token Key are correct."
    except BloodHoundBadRequestException:
        return "Test failed: Bad Request - Invalid request parameters. " "Please verify your configuration."
    except BloodHoundForbiddenException:
        return (
            "Test failed: Forbidden request. Please check your access "
            "permissions and ensure you are using the correct credentials"
        )
    except BloodHoundServerErrorException as e:
        return (
            f"Server error - BloodHound Enterprise server encountered "
            f"an error. Please try again later or contact support: "
            f"{str(e)}"
        )
    except Exception as e:
        if "Name does not resolve" in str(e):
            return "Test failed: Invalid domain provided. Please verify your configuration."
        else:
            return f"Oops! The URL seems incorrect or unreachable. " f"Please check and try again. {str(e)}"


def main():
    """main function, parses params and runs command functions"""
    global LOCK_TIMEOUT

    params = demisto.params()
    interval_minutes = params.get("incidentFetchInterval", 0)
    LOCK_TIMEOUT = int(interval_minutes) * 60 if int(interval_minutes) else 600
    domain = params.get("url").rstrip("/")
    bhe_token_id = params.get("token_id")
    bhe_token_key = params.get("token_key")
    bhe_finding_domain = params.get("finding_domain")
    bhe_finding_category = params.get("finding_category")
    custom_proxy_url = params.get("proxy_url")
    custom_proxy_username = params.get("proxy_username")
    custom_proxy_password = params.get("proxy_password")

    bhe_domain = f"https://{domain}" if not domain.startswith(("http://", "https://")) else domain

    bhe_client = Client(
        bhe_domain=bhe_domain,
        bhe_token_id=bhe_token_id,
        bhe_token_key=bhe_token_key,
        bhe_finding_domain=bhe_finding_domain,
        bhe_finding_category=bhe_finding_category,
        custom_proxy_url=custom_proxy_url,
        custom_proxy_username=custom_proxy_username,
        custom_proxy_password=custom_proxy_password,
    )

    command = demisto.command()
    args = demisto.args()
    demisto.debug(f"Command being called is {command}")
    try:
        if command == "test-module":
            result = test_module(bhe_client)
            return_results(result)

        elif command == "bhe-get-object-id":
            object_result = get_object_id(bhe_client, args.get("object_names").split(","))
            return_results(object_result)

        elif command == "bhe-fetch-asset-info":
            object_ids = [obj_id.strip() for obj_id in args.get("object_ids").split(",")]
            fetch_result = fetch_asset_info(bhe_client, object_ids)
            return_results(fetch_result)

        elif command == "bhe-does-path-exist":
            start_node = args.get("FromPrincipal")
            end_node = args.get("ToPrincipal")
            if not start_node and not end_node:
                return_results("Error: Both 'FromPrincipal' and 'ToPrincipal' " "arguments are missing.")
            elif not start_node:
                return_results("Error: Missing required argument 'FromPrincipal'.")
            elif not end_node:
                return_results("Error: Missing required argument 'ToPrincipal'.")
            else:
                raw_result = does_path_exists_between_nodes(bhe_client, start_node, end_node)
                if isinstance(raw_result, dict) and raw_result.get("status") == "error":
                    return_results(f"Error: {raw_result.get('message', 'Unknown error')}")
                else:
                    return_results(raw_result)

        elif command == "fetch-incidents":
            result = fetch_incidents(bhe_client)

        else:
            raise NotImplementedError(f'Command "{command}" is not implemented.')

    except Exception as e:
        return_error(f"Failed to execute {command} command.\nError:\n{str(e)}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
