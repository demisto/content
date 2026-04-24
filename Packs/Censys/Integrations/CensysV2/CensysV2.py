from collections.abc import Callable
from typing import Any

import demistomock as demisto
import urllib3
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa

# Disable insecure warnings
urllib3.disable_warnings()  # pylint: disable=no-member

TOTAL_RETRIES = 4
STATUS_CODE_TO_RETRY = (429, *(status_code for status_code in requests.status_codes._codes if status_code >= 500))  # type: ignore
OK_CODES = (200, 201)
BACKOFF_FACTOR = 7.5  # Sleep for [0s, 15s, 30s, 60s] between retries.
DATE_FORMAT: str = "%Y-%m-%dT%H:%M:%S.000Z"
PACK_VERSION = get_pack_version() or "3.1.0"
DEMISTO_XSOAR_VERSION = get_demisto_version_as_str().split("-")[0]
CONNECTOR_NAME_VERSION = f"CensysXSOAR/{PACK_VERSION} (XSOAR/{DEMISTO_XSOAR_VERSION}; ts={int(time.time())})"

ENDPOINTS = {
    "HOST_EVENT_HISTORY": "v3/global/asset/host/{}/timeline",
    "INITIATE_RESCAN": "v3/global/scans/rescan",
    "RESCAN_STATUS": "v3/global/scans/{}",
    "INITIATE_JOB": "v3/threat-hunting/censeye/jobs",
    "JOB_STATUS": "v3/threat-hunting/censeye/jobs/{}",
    "JOB_RESULTS": "v3/threat-hunting/censeye/jobs/{}/results",
}

ERRORS = {
    "INVALID_OBJECT": "Failed to parse {} object from response: {}",
    "REQUIRED_ARGUMENT": "Please provide a valid value for the '{}'. It is required field.",
    "INVALID_TIME_RANGE": "Invalid time range: '{}' ({}) must be earlier than '{}' ({}).",
    "INVALID_IP": "Invalid IP address: {}",
    "INVALID_SELECT": "'{}' is an invalid value for '{}'. Value must be in {}.",
    "INVALID_PORT": "{} is an invalid value for the port. The port must be between {} to {}.",
}

HR_SUFFIX = {
    "HOST_EVENT_HISTORY": "/hosts/{}?at_time={}",
    "HOST_ALL_EVENTS": "/hosts/{}/events",
}

OUTPUT_PREFIX = {
    "HOST_EVENT_HISTORY": "Censys.HostEventHistory",
    "INITIATE_RESCAN": "Censys.Rescan",
    "RELATED_INFRASTRUCTURE": "Censys.RelatedInfrastructure",
}

DEFAULT_PAGE_SIZE = 100
MAX_NUMBER_OF_RECORDS = 1000
MAX_NUMBER_OF_PAGES = 10
CENSYS_API_URL = "https://api.platform.censys.io"
CENSYS_PLATFORM_URL = "https://platform.censys.io"
DEFAULT_TIMEOUT_THRESHOLD_SECONDS = 240  # 4 minutes in seconds
DEFAULT_VALUE_NA = "N/A"
INTEGRATION_NAME = "Censys"
DEFAULT_POLLING_INTERVAL = 10  # 10 seconds
DEFAULT_POLLING_TIMEOUT = 630  # 10 minutes 30 seconds
DEFAULT_PORTS = [80, 443]
DEFAULT_TRANSPORT_PROTOCOL = "Unknown"
MIN_PORT = 1
MAX_PORT = 65535

VALID_IOC_TYPE = {"service": "Service", "web property": "Web Property"}
VALID_TRANSPORT_PROTOCOL = {"unknown": "Unknown", "tcp": "TCP", "udp": "UDP", "icmp": "ICMP", "quic": "QUIC"}
VALID_RELATED_INFRA_IOC_TYPE = {"host": "Host", "web property": "Web Property", "certificate": "Certificate"}


class Client(BaseClient):
    def __init__(self, base_url: str, api_token: str, org_id: str | None = None, verify: bool = True, proxy: bool = False):
        """
        Initialize the Censys Client.

        Args:
            base_url: The base URL for the Censys API
            api_token: The API token for authentication
            org_id: Organization ID for multi-org accounts
            verify: Whether to verify SSL certificates
            proxy: Whether to use proxy settings
        """
        self.org_id = org_id
        # Build headers for v3 API
        headers = {"Authorization": f"Bearer {api_token}", "User-Agent": CONNECTOR_NAME_VERSION}
        super().__init__(base_url=base_url, headers=headers, verify=verify, proxy=proxy)

    def http_request(
        self,
        method: str,
        url_suffix: str,
        params: Union[dict[str, Any], list[tuple[str, Any]]] = None,
        data: dict[str, Any] = None,
        json_data: dict[str, Any] = None,
        response_type: str = "json",
        **kwargs,
    ) -> dict[str, Any]:
        """Makes an HTTP request to the Censys API with automatic retry logic.

        This method wraps the BaseClient._http_request with Censys-specific configuration
        including retry logic for transient failures (429, 5xx errors) and automatic
        response parsing based on the requested response_type.

        Args:
            method: The HTTP method (e.g., 'GET', 'POST', 'PUT', 'DELETE').
            url_suffix: The URL suffix to be appended to the base URL. Defaults to empty string.
            params: Query parameters to be appended to the URL. Defaults to None.
            data: Form data to be sent in the request body. Defaults to None.
            json_data: JSON data to be sent in the request body. Defaults to None.
            response_type: The expected response type. Options: 'json', 'content', 'response', 'text'.
                          Defaults to 'json'.
            **kwargs: Additional keyword arguments passed to _http_request.

        Returns:
            Parsed response based on response_type:
            - 'json': Parsed JSON dict
            - 'content': Raw bytes content
            - 'response': Raw Response object
            - 'text': Response text string
            Returns None if response parsing fails.

        Raises:
            DemistoException: If response parsing fails or if the API returns an error status.

        Note:
            Automatically retries up to TOTAL_RETRIES (4) times for rate limit (429) and
            server errors (5xx) with exponential backoff (BACKOFF_FACTOR=7.5).
        """
        demisto.debug(f"Making API request at {method} {url_suffix} with params: {params} and body: {data or json_data}")
        # Make the HTTP request using the _http_request method, passing the necessary parameters.
        res = self._http_request(
            method=method,
            url_suffix=url_suffix,
            data=data,
            json_data=json_data,
            params=params,
            retries=TOTAL_RETRIES,
            status_list_to_retry=STATUS_CODE_TO_RETRY,
            ok_codes=OK_CODES,
            backoff_factor=BACKOFF_FACTOR,
            resp_type="response",
            raise_on_status=True,
            **kwargs,
        )
        try:
            result = None
            if response_type == "json":
                result = res.json()
            if response_type == "content":
                result = res.content()
            if response_type == "response":
                result = res
            if response_type == "text":
                result = res.text
        except ValueError as exception:
            raise DemistoException(ERRORS["INVALID_OBJECT"].format(response_type, res.text), exception, res)

        return result  # type: ignore

    def censys_view_request(self, index: str, query: str) -> dict:
        if index == "ipv4":
            asset_type = "host"
        elif index == "webproperty":
            asset_type = "webproperty"
        else:
            asset_type = "certificate"
        demisto.debug(f"censys_view_request: index={index}, query={query}, asset_type={asset_type}")
        params = {"organization_id": self.org_id}
        result = self.http_request("GET", f"/v3/global/asset/{asset_type}/{query}", params=params)
        return result

    def censys_search_request(
        self, query: str, page_size: int | None = None, fields: list | None = None, page_token: str | None = None
    ) -> dict:
        """
        Execute a single search query request.

        Args:
            query: The search query string
            page_size: Number of results per page
            fields: List of fields to return
            page_token: Token for pagination (to get next page)

        Returns:
            API response dictionary
        """
        url_suffix = "/v3/global/search/query"
        data = assign_params(query=query, page_size=page_size, fields=fields, page_token=page_token)
        demisto.debug(f"censys_search_request: query={query}, page_size={page_size}, page_token={page_token}")
        params = {"organization_id": self.org_id}
        return self.http_request("POST", url_suffix, json_data=data, params=params)

    def censys_host_history_request(self, ip_address: str, start_time: str, end_time: str) -> dict:
        """Fetch host event history from the Censys API.

        The Censys API uses reversed time semantics for the timeline endpoint:
        - API start_time = newer/closer to now (user's end_time)
        - API end_time = older/further back (user's start_time)

        This method automatically reverses the provided times when making the API call.

        Args:
            ip_address: The IP address of the host to retrieve history for.
            start_time: Start time from the past (RFC3339 format) - will be reversed to API end_time.
            end_time: End time near current (RFC3339 format) - will be reversed to API start_time.

        Returns:
            Response object from the API containing host event history for the specified time range.
        """
        url_suffix = ENDPOINTS["HOST_EVENT_HISTORY"].format(ip_address)
        # Reverse the times for API call (API expects reverse chronological order)
        # User's end_time (recent) -> API start_time (newer)
        # User's start_time (past) -> API end_time (older)
        data = assign_params(start_time=end_time, end_time=start_time, organization_id=self.org_id)

        return self.http_request("GET", url_suffix, params=data)

    def censys_initiate_rescan_request(
        self, ioc_type: str, ioc_value: str, port: int | None, protocol: str, transport_protocol: str
    ) -> dict:
        """Initiate a rescan for a host service.

        Args:
            ioc_type: IOC type (service or web property).
            ioc_value: IP address of the host.
            port: Port number.
            protocol: Service protocol.
            transport_protocol: Transport protocol (TCP, UDP, etc.).

        Returns:
            API response containing scan ID and status
        """
        url_suffix = ENDPOINTS["INITIATE_RESCAN"].format(ioc_value, port, protocol)
        if ioc_type.lower() == "service":
            body = {
                "target": {
                    "service_id": {
                        "ip": ioc_value,
                        "port": port,
                        "protocol": protocol,
                        "transport_protocol": transport_protocol.lower(),
                    }
                }
            }
        else:
            body = {
                "target": {
                    "web_origin": {
                        "hostname": ioc_value,
                        "port": port,
                    }
                }
            }

        params = assign_params(organization_id=self.org_id)
        return self.http_request("POST", url_suffix, json_data=body, params=params)

    def censys_rescan_status_request(self, scan_id: str) -> dict:
        """Get the status of a rescan.

        Args:
            scan_id: The tracked scan ID

        Returns:
            API response containing scan status
        """

        url_suffix = ENDPOINTS["RESCAN_STATUS"].format(scan_id)
        params = assign_params(organization_id=self.org_id)
        demisto.debug(f"censys_rescan_status_request: scan_id={scan_id}")
        return self.http_request("GET", url_suffix, params=params)

    def censys_initiate_job_request(self, ioc_type: str, ioc_value: str) -> dict:
        """Initiate a CensEye related infrastructure job.

        Args:
            ioc_type: IOC type (Host, Web Property, or Certificate).
            ioc_value: The IOC value (IP for Host, hostname:port for Web Property, or certificate SHA-256 for Certificate).

        Returns:
            API response containing job ID and status.
        """
        url_suffix = ENDPOINTS["INITIATE_JOB"]

        ioc_type = ioc_type.replace(" ", "")
        body = {"target": {f"{ioc_type}_id": ioc_value}}

        params = assign_params(organization_id=self.org_id)
        return self.http_request("POST", url_suffix, json_data=body, params=params)

    def censys_job_status_request(self, job_id: str) -> dict:
        """Get the status of a CensEye job.

        Args:
            job_id: The job ID.

        Returns:
            API response containing job status.
        """
        url_suffix = ENDPOINTS["JOB_STATUS"].format(job_id)
        params = assign_params(organization_id=self.org_id)

        return self.http_request("GET", url_suffix, params=params)

    def censys_job_results_request(self, job_id: str) -> dict:
        """Get the results of a completed CensEye job.

        Args:
            job_id: The job ID.

        Returns:
            API response containing pivot data results.
        """
        url_suffix = ENDPOINTS["JOB_RESULTS"].format(job_id)
        params = assign_params(organization_id=self.org_id, page_size=DEFAULT_PAGE_SIZE)

        return self.http_request("GET", url_suffix, params=params)


""" HELPER FUNCTIONS """


def censys_search_with_pagination(
    client: Client, query: str, page_size: int | None = None, fields: list | None = None, limit: int | None = None
) -> dict:
    """
    Execute a search query with automatic pagination.

    This function handles pagination automatically by fetching multiple pages
    until either all results are retrieved or the limit is reached.

    Args:
        client: The Censys client instance
        query: The search query string
        page_size: Number of results per page (default: 50, max: 100)
        fields: List of fields to return
        limit: Maximum total number of results to return across all pages

    Returns:
        Dictionary with 'result' containing all hits and metadata:
        {
            "result": {
                "hits": [...],  # All collected hits
                "total_hits": int,  # Total available results
                "next_page_token": str,  # Token for next page (if any)
                "previous_page_token": str,  # Token for previous page (if any)
                "query_duration_millis": int  # Query duration
            }
        }
    """
    # Determine initial page size
    if page_size is None:
        page_size = 100
    if limit and limit < page_size:
        page_size = limit

    all_hits = []
    page_token = None
    total_fetched = 0
    total_hits = None
    last_result = {}

    # Pagination loop
    demisto.debug(f"censys_search_with_pagination: starting pagination for query={query}, limit={limit}")
    while True:
        # Make API request for current page
        response = client.censys_search_request(query, page_size, fields, page_token)
        result = response.get("result", {})
        hits = result.get("hits", [])

        # Store metadata from first response
        if total_hits is None:
            total_hits = result.get("total_hits")

        # Keep last result for metadata
        last_result = result

        # If no hits, break
        if not hits:
            break

        # Add hits to collection
        all_hits.extend(hits)
        total_fetched += len(hits)

        # Check for next page token (it's directly in result, not in links)
        next_page_token = result.get("next_page_token")

        # Stop if no more pages or reached limit
        if not next_page_token or (limit and total_fetched >= limit):
            break

        # Update for next iteration
        page_token = next_page_token

        # Adjust page_size if approaching limit
        if limit:
            remaining = limit - total_fetched
            if remaining < page_size:
                page_size = remaining

    demisto.debug(f"censys_search_with_pagination: finished pagination. total_fetched={total_fetched}, total_hits={total_hits}")

    # Trim to exact limit if specified
    if limit and len(all_hits) > limit:
        all_hits = all_hits[:limit]

    # Return response in same format as single request
    return {
        "result": {
            "hits": all_hits,
            "total_hits": total_hits,
            "next_page_token": last_result.get("next_page_token"),
            "previous_page_token": last_result.get("previous_page_token"),
            "query_duration_millis": last_result.get("query_duration_millis"),
        }
    }


def handle_exceptions(e: Exception, results: list[CommandResults], execution_metrics: ExecutionMetrics, item: str):
    demisto.debug(f"handle_exceptions: item={item}, error={str(e)}")
    status_code = 0
    message = str(e)

    if isinstance(e, DemistoException) and e.res is not None:
        status_code = e.res.status_code
        message = e.message

    if status_code == 403 and "quota" in message:
        # Handle quota exceeded error
        execution_metrics.quota_error += 1
        results.append(CommandResults(readable_output=f"Quota exceeded. Error: {message}"))
        return True

    elif status_code == 429:
        # Handle rate limits error
        execution_metrics.general_error += 1
        results.append(CommandResults(readable_output=f"Too many requests. Error: {message}"))
        return True

    elif status_code == 403 and "specific fields" in message:
        # Handle non-premium access error
        raise DemistoException(
            "Your user does not have permission for premium features. "
            "Please ensure that you deselect the 'Labels premium feature available' option "
            f"for non-premium access. Error: {message}"
        )

    elif status_code == 401 or status_code == 403:
        # Handle unauthorized access error
        raise e

    else:
        # Handle general error
        execution_metrics.general_error += 1
        error_msg = f"An error occurred for item: {item}. Error: {message}"
        results.append(CommandResults(readable_output=error_msg))
        return False


def get_dbot_score(params: dict, result_labels: list):
    malicious_labels = set(argToList(params.get("malicious_labels", [])))
    suspicious_labels = set(argToList(params.get("suspicious_labels", [])))
    malicious_threshold = arg_to_number(params.get("malicious_labels_threshold")) or 0
    suspicious_threshold = arg_to_number(params.get("suspicious_labels_threshold")) or 0
    num_malicious = len(malicious_labels.intersection(result_labels))
    if num_malicious >= malicious_threshold and num_malicious > 0:
        matched_labels = sorted(malicious_labels.intersection(result_labels))
        description = f"Matched malicious labels: {', '.join(matched_labels)}"
        return Common.DBotScore.BAD, description

    num_suspicious = len(suspicious_labels.intersection(result_labels))
    if num_suspicious >= suspicious_threshold and num_suspicious > 0:
        matched_labels = sorted(suspicious_labels.intersection(result_labels))
        description = f"Matched suspicious labels: {', '.join(matched_labels)}"
        return Common.DBotScore.SUSPICIOUS, description

    return Common.DBotScore.NONE, None


def trim_spaces_from_args(args: dict) -> dict:
    """Trim leading/trailing spaces from argument values and normalize comma-separated lists.

    For string values, removes leading and trailing whitespace. For comma-separated values,
    splits them into a list, trims each item, removes empty items, and rejoins with commas.

    Args:
        args: Dictionary of command arguments to process.

    Returns:
        The same dictionary with trimmed values (modifies in-place and returns).

    Example:
        >>> trim_spaces_from_args({'key': '  value  ', 'list': 'a, b , c'})
        {'key': 'value', 'list': 'a,b,c'}
    """
    for key, val in args.items():
        if isinstance(val, str):
            args[key] = val.strip()

    return args


def validate_required_argument(value: Any, name: str) -> Any:
    """
    Check if empty string is passed as value for argument and raise appropriate ValueError.

    Args:
        value: Value of the argument.
        name: Name of the argument.

    Returns:
        str: Value of the argument.

    Raises:
        ValueError: If the value is empty string.
    """
    if not value:
        raise ValueError(ERRORS["REQUIRED_ARGUMENT"].format(name))
    return value


def prepare_hr_for_host_history_list_command(events: list[dict], ip_address: str) -> str:
    """Prepare human-readable markdown output for host history events.

    Args:
        events: List of event dictionaries from the Censys API response.
        ip_address: The IP address of the host (used in summary message and links).

    Returns:
        Formatted markdown string with summary heading, event table, and optional
        note about record caps with link to Censys platform.
    """
    hr_data = []

    for event in events:
        resource = event.get("resource", {})
        event_time = resource.get("event_time", DEFAULT_VALUE_NA)

        resource_type = DEFAULT_VALUE_NA
        resource_details = DEFAULT_VALUE_NA

        if "service_scanned" in resource:
            resource_type = "service_scanned"
            port = demisto.get(resource, f"{resource_type}.scan.port", DEFAULT_VALUE_NA)
            protocol = demisto.get(resource, f"{resource_type}.scan.protocol", DEFAULT_VALUE_NA)
            transport = demisto.get(resource, f"{resource_type}.scan.transport_protocol", DEFAULT_VALUE_NA).upper()
            resource_details = f"{port}/{transport}/{protocol}"

        elif "reverse_dns_resolved" in resource:
            resource_type = "reverse_dns_resolved"
            names = demisto.get(resource, f"{resource_type}.names", [])
            resource_details = names[0] if names else DEFAULT_VALUE_NA

        elif "endpoint_scanned" in resource:
            resource_type = "endpoint_scanned"
            port = demisto.get(resource, f"{resource_type}.scan.port", DEFAULT_VALUE_NA)
            endpoint_type = demisto.get(resource, f"{resource_type}.scan.endpoint_type", DEFAULT_VALUE_NA)
            resource_details = f"{port}/{endpoint_type}"

        elif "forward_dns_resolved" in resource:
            resource_type = "forward_dns_resolved"
            name = demisto.get(resource, f"{resource_type}.name", DEFAULT_VALUE_NA)
            resource_details = name

        elif "jarm_scanned" in resource:
            resource_type = "jarm_scanned"
            port = demisto.get(resource, f"{resource_type}.scan.port", DEFAULT_VALUE_NA)
            fingerprint = demisto.get(resource, f"{resource_type}.scan.fingerprint", DEFAULT_VALUE_NA)
            resource_details = f"{port}/{fingerprint}"

        elif "location_updated" in resource:
            resource_type = "location_updated"
            city = demisto.get(resource, f"{resource_type}.location.city", DEFAULT_VALUE_NA)
            country = demisto.get(resource, f"{resource_type}.location.country", DEFAULT_VALUE_NA)
            resource_details = f"{city}/{country}"

        elif "route_updated" in resource:
            resource_type = "route_updated"
            asn = demisto.get(resource, f"{resource_type}.route.asn", DEFAULT_VALUE_NA)
            organization = demisto.get(resource, f"{resource_type}.route.organization", DEFAULT_VALUE_NA)
            resource_details = f"{asn}/{organization}"

        elif "whois_updated" in resource:
            resource_type = "whois_updated"
            org_name = demisto.get(resource, f"{resource_type}.whois.organization.name", DEFAULT_VALUE_NA)
            resource_details = org_name

        platform_url = f"{CENSYS_PLATFORM_URL}{HR_SUFFIX['HOST_EVENT_HISTORY'].format(ip_address, event_time)}"

        hr_data.append(
            {
                "Event Time": event_time,
                "Resource Type": resource_type,
                "Resource Details": resource_details,
                "Link to Censys": f"[View historical host on Censys platform]({platform_url})",
            }
        )

    hr_output = tableToMarkdown(
        "Host History Events",
        hr_data,
        headers=["Event Time", "Resource Type", "Resource Details", "Link to Censys"],
        removeNull=True,
    )

    return hr_output


def validate_port_argument(port: int) -> int:
    """Validate that the port number is within the valid range.

    Args:
        port: Port number to validate

    Returns:
        Validated port number

    Raises:
        ValueError: If port is not between MIN_PORT and MAX_PORT (1-65535)
    """
    if port < MIN_PORT or port > MAX_PORT:
        raise ValueError(ERRORS["INVALID_PORT"].format(port, MIN_PORT, MAX_PORT))

    return port


def validate_rescan_command_args(ioc_type: str, ioc_value: str, port: int | None, protocol: str, transport_protocol: str) -> None:
    """Validate arguments for the rescan command.

    Args:
        ioc_type: IOC type to validate
        ioc_value: IP address to validate
        port: Port number to validate
        protocol: Service protocol to validate
        transport_protocol: Transport protocol to validate

    Raises:
        ValueError: If any argument is invalid
    """
    ioc_type = validate_required_argument(ioc_type, "ioc_type")

    if ioc_type.lower() not in VALID_IOC_TYPE:
        raise ValueError(ERRORS["INVALID_SELECT"].format(ioc_type, "ioc_type", ", ".join(VALID_IOC_TYPE.values())))

    ioc_value = validate_required_argument(ioc_value, "ioc_value")

    if ioc_type.lower() == "service":
        if not is_ip_valid(ioc_value, accept_v6_ips=True):
            raise ValueError(ERRORS["INVALID_IP"].format(ioc_value))

        if not protocol:
            raise ValueError("Protocol is required when IOC Type is Service.")

        if transport_protocol.lower() not in VALID_TRANSPORT_PROTOCOL:
            raise ValueError(
                ERRORS["INVALID_SELECT"].format(
                    transport_protocol, "transport_protocol", ", ".join(VALID_TRANSPORT_PROTOCOL.values())
                )
            )

    port = validate_required_argument(port, "port")
    validate_port_argument(port)


def validate_related_infra_command_args(ioc_type: str, ioc_value: str) -> None:
    """Validate arguments for the related infrastructure command.

    Args:
        ioc_type: IOC type to validate (Host, Web Property, Certificate)
        ioc_value: IOC value to validate (for Web Property, should include port as hostname:port)

    Raises:
        ValueError: If any argument is invalid
    """
    ioc_type = validate_required_argument(ioc_type, "ioc_type")

    if ioc_type.lower() not in VALID_RELATED_INFRA_IOC_TYPE:
        raise ValueError(ERRORS["INVALID_SELECT"].format(ioc_type, "ioc_type", ", ".join(VALID_RELATED_INFRA_IOC_TYPE.values())))

    ioc_value = validate_required_argument(ioc_value, "ioc_value")

    if ioc_type.lower() == "host" and not is_ip_valid(ioc_value, accept_v6_ips=True):
        raise ValueError(ERRORS["INVALID_IP"].format(ioc_value))

    if ioc_type.lower() == "web property":
        # Validate that ioc_value includes port (format: hostname:port)
        if ":" not in ioc_value:
            raise ValueError("For Web Property IOC type, ioc_value must include port in the format hostname:port")
        parts = ioc_value.rsplit(":", 1)
        if len(parts) != 2:
            raise ValueError("For Web Property IOC type, ioc_value must include port in the format hostname:port")

        port = int(parts[1])
        validate_port_argument(port)


def prepare_hr_for_ip_resource(resources: list[dict] | dict) -> str:
    """Prepare human-readable output for IP resource(s).

    Args:
        resources: The host resource data from Censys API (single dict or list of dicts)
        params: Integration parameters

    Returns:
        Human-readable output string
    """
    # Handle both single resource and list of resources
    if isinstance(resources, dict):
        resources = [resources]

    hr_data = []

    for resource in resources:
        ioc_value = resource.get("ip")

        # Location data
        city = demisto.get(resource, "location.city")
        province = demisto.get(resource, "location.province")
        postal = demisto.get(resource, "location.postal_code")
        country_code = demisto.get(resource, "location.country_code")
        country = demisto.get(resource, "location.country")
        continent = demisto.get(resource, "location.continent")
        lat = demisto.get(resource, "location.coordinates.latitude")
        lon = demisto.get(resource, "location.coordinates.longitude")
        asn = demisto.get(resource, "autonomous_system.asn")
        asn_name = demisto.get(resource, "autonomous_system.name")

        # Labels and scoring
        labels_list = [label.get("value") for label in resource.get("labels", []) if label.get("value")]
        labels_str = ", ".join(labels_list) if labels_list else ""

        # DNS information
        dns_names = demisto.get(resource, "dns.names", [])
        forward_dns_names = demisto.get(resource, "dns.forward_dns.names", [])
        reverse_dns_names = demisto.get(resource, "dns.reverse_dns.names", [])

        # WHOIS information
        whois_network_name = demisto.get(resource, "whois.network.name")
        whois_cidrs = demisto.get(resource, "whois.network.cidrs", [])

        # Aggregate service information
        services = resource.get("services", [])
        service_ports = []
        service_protocols = []
        service_transport_protocols = []
        all_service_labels = []
        all_service_vulns = []
        all_service_threats = []
        service_scan_times = []

        for service in services:
            if service.get("port"):
                service_ports.append(str(service.get("port")))
            if service.get("protocol"):
                service_protocols.append(service.get("protocol"))
            if service.get("transport_protocol"):
                service_transport_protocols.append(service.get("transport_protocol"))

            service_labels = [label.get("value") for label in service.get("labels", []) if label.get("value")]
            all_service_labels.extend(service_labels)

            threats = [threat.get("name") for threat in service.get("threats", []) if threat.get("name")]
            all_service_threats.extend(threats)

            vulns = service.get("vulns", [])
            vuln_ids = [vuln.get("id") for vuln in vulns if vuln.get("id")]
            if vuln_ids:
                all_service_vulns.append(", ".join(vuln_ids))

            service_scan_time = service.get("scan_time")
            if service_scan_time:
                service_scan_times.append(service_scan_time)

        # Build comprehensive human-readable content
        hr_content = {
            "IP": ioc_value,
            "Labels": labels_str,
            "Service Count": resource.get("service_count"),
            "Service Ports": ", ".join(service_ports),
            "Service Protocols": ", ".join(service_protocols),
            "Service Transport Protocols": ", ".join(service_transport_protocols),
            "Service Labels": ", ".join(all_service_labels),
            "Service Vulns": ", ".join(all_service_vulns),
            "Service Threats": ", ".join(all_service_threats),
            "Service Scan Times": ", ".join(service_scan_times),
            "DNS Names": ", ".join(dns_names),
            "Forward DNS Names": ", ".join(forward_dns_names),
            "Reverse DNS Names": ", ".join(reverse_dns_names),
            "Network Name": whois_network_name,
            "CIDRs": ", ".join(whois_cidrs),
            "Autonomous System Name": asn_name,
            "Autonomous System ASN": asn,
            "City": city,
            "Province": province,
            "Postal Code": postal,
            "Country": country,
            "Country Code": country_code,
            "Continent": continent,
            "Latitude": lat,
            "Longitude": lon,
        }
        hr_data.append(hr_content)

    human_readable = tableToMarkdown("Enriched Host Data", hr_data, removeNull=True, sort_headers=False)

    return human_readable


def prepare_hr_for_web_property_resource(resources: list[dict] | dict) -> str:
    """Prepare human-readable output for web property resource(s).

    Args:
        resources: The web property resource data from Censys API (single dict or list of dicts)

    Returns:
        Human-readable output string
    """
    # Handle both single resource and list of resources
    if isinstance(resources, dict):
        resources = [resources]

    hr_data = []

    for resource in resources:
        hostname = resource.get("hostname", "")
        port = resource.get("port", "")
        scan_time = resource.get("scan_time", "")

        # Endpoints information
        endpoints = resource.get("endpoints", [])
        endpoint_types = ", ".join([str(ep.get("endpoint_type", "")) for ep in endpoints if ep.get("endpoint_type")])
        endpoint_paths = ", ".join([str(ep.get("path", "")) for ep in endpoints if ep.get("path")])

        # Labels and scoring
        labels_list = [label.get("value") for label in resource.get("labels", []) if label.get("value")]
        labels_str = ", ".join(labels_list) if labels_list else ""

        # Threats information
        threats = resource.get("threats", [])
        threat_names = ", ".join([threat.get("name") for threat in threats if threat.get("name")])

        # Vulnerabilities information
        vulns = resource.get("vulns", [])
        vulns_names = ", ".join([vuln.get("id") or vuln.get("name") for vuln in vulns if vuln.get("id") or vuln.get("name")])

        # Software information
        software_list = resource.get("software", [])
        vendors = ", ".join([str(sw.get("vendor", "")) for sw in software_list if sw.get("vendor")])
        products = ", ".join([str(sw.get("product", "")) for sw in software_list if sw.get("product")])
        versions = ", ".join([str(sw.get("version", "")) for sw in software_list if sw.get("version")])

        # Certificate information
        cert = resource.get("cert", {})
        sha256 = cert.get("fingerprint_sha256", "")
        subject_dn = demisto.get(cert, "parsed.subject_dn", "")
        issuer_dn = demisto.get(cert, "parsed.issuer_dn", "")
        common_name = demisto.get(cert, "parsed.subject.common_name", "")
        not_before = demisto.get(cert, "parsed.validity_period.not_before", "")
        not_after = demisto.get(cert, "parsed.validity_period.not_after", "")
        self_signed = demisto.get(cert, "parsed.signature.self_signed", "")

        # Build comprehensive human-readable content
        hr_content = {
            "Hostname": hostname,
            "Port": port,
            "Scan Time": scan_time,
            "Endpoint Types": endpoint_types,
            "Endpoint Paths": endpoint_paths,
            "Labels": labels_str,
            "Threat Names": threat_names,
            "Vulns Names": vulns_names,
            "Vendors": vendors,
            "Products": products,
            "Versions": versions,
            "sha256": sha256,
            "Self Signed": self_signed,
            "Subject DN": subject_dn,
            "Issuer DN": issuer_dn,
            "Common Names": common_name,
            "Not Before": not_before,
            "Not After": not_after,
        }
        hr_data.append(hr_content)

    human_readable = tableToMarkdown("Enriched Web Property Data", hr_data, removeNull=True, sort_headers=False)

    return human_readable


def prepare_hr_for_pivot_information(pivot_data: list[dict[str, Any]]) -> str:
    """Prepare human-readable output for pivot information command."""
    hr_data = []

    for pivot in pivot_data:
        count = pivot.get("count", 0)
        field_value_pairs = pivot.get("field_value_pairs", [])

        fields = "\n".join(fvp.get("field", "") for fvp in field_value_pairs)
        values = "\n".join(fvp.get("value", "") for fvp in field_value_pairs)

        # Check if this is a header field pattern (2 pairs with .key and .value)
        is_header_pattern = (
            len(field_value_pairs) == 2
            and field_value_pairs[0].get("field", "").endswith(".key")
            and field_value_pairs[1].get("field", "").endswith(".value")
        )

        if is_header_pattern:
            base_field = field_value_pairs[0].get("field", "")[:-4]  # Remove ".key"
            value1 = field_value_pairs[0].get("value", "")
            value2 = field_value_pairs[1].get("value", "")
            search_query = f'{base_field}: (key = "{value1}" and value = "{value2}")'
        else:
            search_query = " and ".join(f'{fvp.get("field", "")} = "{fvp.get("value", "")}"' for fvp in field_value_pairs)

        platform_url = f"{CENSYS_PLATFORM_URL}/search?q={urllib.parse.quote_plus(search_query)}"

        hr_data.append(
            {
                "Count": count,
                "Key": fields,
                "Value": values,
                "See results in Censys": f"[View Pivot Information on Censys platform]({platform_url})",
            }
        )

    # Sort hr_data by count in ascending order (low to high)
    hr_data.sort(key=lambda x: x["Count"])

    hr_output = tableToMarkdown(
        f"{len(hr_data)} Pivots Data",
        hr_data,
        headers=["Key", "Value", "Count", "See results in Censys"],
        removeNull=True,
    )

    return hr_output


""" COMMAND FUNCTIONS """


def test_module(client: Client, params: dict[str, Any]) -> str:
    # Check if the user has selected malicious or suspicious labels without premium access
    if not params.get("premium_access") and (params.get("malicious_labels") or params.get("suspicious_labels")):
        raise DemistoException(
            "The 'Determine IP score by label' feature only works for Censys paid subscribers (v3 API). "
            "If you have paid access select the 'Determine IP score by label' option "
            "to utilize this functionality, or deselect labels"
        )

    fields = ["labels"] if params.get("premium_access") else None

    try:
        # Build query for test IP
        query = 'host.ip="8.8.8.8"'
        censys_search_with_pagination(client, query, fields=fields, limit=1)
        return "ok"
    except DemistoException as e:
        if e.res is not None:
            if e.res.status_code == 401:
                raise DemistoException(
                    "401 Unauthorized: Access credentials are invalid. "
                    "Please verify your 'API Token' in the integration configuration."
                )
            if e.res.status_code == 403:
                # Handle permission error for non-premium users attempting to access premium features
                if "specific fields" in e.message:
                    raise DemistoException(
                        "Your user does not have permission for premium features (v3 API). "
                        "Please ensure that you deselect the 'Determine IP score by label' option "
                        "for non-premium access."
                    )
                # Handle organization authorization error
                raise DemistoException(
                    "403 Forbidden: The provided Organization ID is incorrect or the user is not authorized to access it. "
                    "Please verify your 'Organization ID' in the integration configuration."
                )
            # Handle organization ID format error
            if e.res.status_code == 422:
                raise DemistoException(
                    "422 Unprocessable Entity: The provided Organization ID is malformed. Please ensure it is a valid UUID."
                )
        raise e


def censys_view_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """
    Returns host information for the specified IP address or structured certificate data for the specified SHA-256
    """
    index = args.get("index", "")
    query = args.get("query", "")
    demisto.debug(f"censys_view_command: index={index}, query={query}")
    res = client.censys_view_request(index, query)
    resource = demisto.get(res, "result.resource", {})
    if index == "ipv4":
        city = demisto.get(resource, "location.city")
        province = demisto.get(resource, "location.province")
        postal = demisto.get(resource, "location.postal_code")
        country_code = demisto.get(resource, "location.country_code")
        country = demisto.get(resource, "location.country")

        description = ", ".join([str(x) for x in [city, province, postal, country_code] if x])
        lat = demisto.get(resource, "location.coordinates.latitude")
        lon = demisto.get(resource, "location.coordinates.longitude")

        params = demisto.params()
        labels = list({label.get("value") for label in resource.get("labels", [])})
        score, malicious_description = get_dbot_score(params, labels)
        dbot_score = Common.DBotScore(
            indicator=query,
            indicator_type=DBotScoreType.IP,
            integration_name="Censys",
            score=score,
            malicious_description=malicious_description,
            reliability=params.get("integration_reliability"),
        )
        indicator = Common.IP(
            ip=query,
            dbot_score=dbot_score,
            asn=demisto.get(resource, "autonomous_system.asn"),
            geo_latitude=str(lat) if lat else None,
            geo_longitude=str(lon) if lon else None,
            geo_description=description or None,
            geo_country=country,
            as_owner=demisto.get(resource, "autonomous_system.name"),
        )

        hr_content = {
            "Network": resource.get("autonomous_system", {}).get("name"),
            "Routing": resource.get("autonomous_system", {}).get("bgp_prefix"),
            "ASN": resource.get("autonomous_system", {}).get("asn"),
            "Protocols": ", ".join(
                [f"{service.get('port')}/{service.get('protocol')}" for service in resource.get("services", [])]
            ),
            "Whois Last Updated": demisto.get(resource, "whois.network.updated"),
        }
        human_readable = tableToMarkdown(f"Information for IP {query}", hr_content, removeNull=True)
        return CommandResults(
            readable_output=human_readable,
            outputs_prefix="Censys.View",
            outputs_key_field="ip",
            outputs=resource,
            indicator=indicator,
            raw_response=res,
        )
    else:
        hr_content = {
            "Added At": resource.get("added_at"),
            "Modified At": resource.get("modified_at"),
            "Browser Trust": [
                f"{name}: {'Valid' if val.get('ever_valid') else 'Invalid'}"
                for name, val in resource.get("validation", {}).items()
            ],
            "SHA 256": resource.get("fingerprint_sha256"),
            "Validated At": resource.get("validated_at"),
        }
        human_readable = tableToMarkdown("Information for certificate", hr_content, removeNull=True)
        return CommandResults(
            readable_output=human_readable,
            outputs_prefix="Censys.View",
            outputs_key_field="fingerprint_sha256",
            outputs=resource,
            raw_response=res,
        )


def censys_search_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """
    Returns previews of hosts matching a specified search query or a list of certificates that match the given query.
    """
    index = args.get("index")
    query = args.get("query", "")
    demisto.debug(f"censys_search_command: index={index}, query={query}")
    page_size: int = arg_to_number(args.get("page_size", 50))  # type: ignore[assignment]
    limit = arg_to_number(args.get("limit", 50))
    hr_contents = []

    if index == "ipv4":
        # Use pagination helper to fetch all results up to limit
        res = censys_search_with_pagination(client, query, page_size=page_size, limit=limit)
        hits = res.get("result", {}).get("hits", [])

        # Extract results
        results = []
        for hit in hits:
            # Extract resource for human readable output
            resource = demisto.get(hit, "host_v1.resource", {})
            results.append(resource)

            hr_contents.append(
                {
                    "IP": resource.get("ip"),
                    "Services": ", ".join(
                        [f"{service.get('port')}/{service.get('protocol')}" for service in resource.get("services", [])]
                    ),
                    "Country code": demisto.get(resource, "location.country_code"),
                    "ASN": demisto.get(resource, "autonomous_system.asn"),
                    "Description": demisto.get(resource, "autonomous_system.description"),
                    "Name": demisto.get(resource, "autonomous_system.name"),
                }
            )
        human_readable = tableToMarkdown(f'Search results for query "{query}"', hr_contents, removeNull=True)
        return CommandResults(
            readable_output=human_readable,
            outputs_prefix="Censys.Search",
            outputs_key_field="ip",
            outputs=results,
            raw_response=res,
        )
    else:
        response = search_certs_command(client, args, query, limit, page_size)
        return response


def search_certs_command(client: Client, args: dict[str, Any], query: str, limit: Optional[int], page_size: int | None = None):
    # Default fields to request (using new API field names with cert prefix)
    fields = [
        "cert.fingerprint_sha256",
        "cert.parsed.subject_dn",
        "cert.parsed.issuer_dn",
        "cert.parsed.issuer.organization",
        "cert.parsed.validity_period.not_before",
        "cert.parsed.validity_period.not_after",
        "cert.names",
        "cert.parsed.subject.common_name",
        "cert.parsed.signature.self_signed",
        "cert.valid_to",
        "cert.self_signed",
    ]

    # Add user-requested fields
    search_fields = argToList(args.get("fields"))
    if search_fields:
        fields.extend(search_fields)

    # Use pagination helper to fetch all results up to limit
    res = censys_search_with_pagination(client, query, page_size=page_size, fields=fields, limit=limit)
    raw_response = res.get("result", {})
    hits = raw_response.get("hits", [])

    if not hits or not isinstance(hits, list):
        error_msg = f"Unexpected response: 'hits' path not found in response.result. Response: {raw_response}"
        raise ValueError(error_msg)

    # Extract results
    results = []
    hr_contents = []

    for hit in hits:
        # Extract the certificate data
        resource = demisto.get(hit, "certificate_v1.resource", {})
        results.append(resource)

        # Extract data for human readable output
        parsed = resource.get("parsed", {})
        common_names = demisto.get(parsed, "subject.common_name") or []

        hr_contents.append(
            {
                "Fingerprint sha256": resource.get("fingerprint_sha256"),
                "Self Signed Signature": demisto.get(parsed, "signature.self_signed"),
                "Valid To": resource.get("valid_to"),
                "Self Signed": resource.get("self_signed"),
                "Subject DN": demisto.get(parsed, "subject_dn"),
                "Issuer DN": demisto.get(parsed, "issuer_dn"),
                "Common Names": ", ".join(common_names),
                "Not Valid Before": demisto.get(parsed, "validity_period.not_before"),
                "Not Valid After": demisto.get(parsed, "validity_period.not_after"),
                "Names": resource.get("names"),
                "Issuer": demisto.get(parsed, "issuer.organization"),
            }
        )

    human_readable = tableToMarkdown(f'Search results for query "{query}"', hr_contents, removeNull=True, sort_headers=False)
    return CommandResults(
        readable_output=human_readable,
        outputs_prefix="Censys.Search",
        outputs_key_field="fingerprint_sha256",
        outputs=results,
        raw_response=res,
    )


def ip_command(client: Client, args: dict, params: dict):
    fields = (
        [
            "host.labels.value",
            "host.ip",
            "host.autonomous_system.asn",
            "host.autonomous_system.name",
            "host.autonomous_system.bgp_prefix",
            "host.autonomous_system.country_code",
            "host.autonomous_system.description",
            "host.location.country_code",
            "host.location.timezone",
            "host.location.province",
            "host.location.postal_code",
            "host.location.coordinates.latitude",
            "host.location.coordinates.longitude",
            "host.location.city",
            "host.location.continent",
            "host.location.country",
            "host.services.protocol",
            "host.services.port",
            "host.services.transport_protocol",
            "host.services.extended_service_name",
            "host.services.cert",
            "host.whois.network.updated",
            "host.dns.reverse_dns.names",
            "host.operating_system.source",
            "host.operating_system.part",
            "host.operating_system.version",
            "host.service_count",
            "host.services.labels.value",
            "host.services.threats.name",
            "host.services.vulns",
            "host.services.scan_time",
            "host.dns.names",
            "host.dns.forward_dns.names",
            "host.whois.network.name",
            "host.whois.network.cidrs",
        ]
        if params.get("premium_access")
        else None
    )

    ips: list = argToList(args.get("ip"))
    demisto.debug(f"ip_command: processing IPs {ips}")
    results: List[CommandResults] = []
    execution_metrics = ExecutionMetrics()

    try:
        # Build query for all IPs
        query = " or ".join([f'host.ip="{ip_addr}"' for ip_addr in ips])

        # Send all IPs in a single API call with pagination
        raw_response = censys_search_with_pagination(client, query, fields=fields)
        hits = raw_response.get("result", {}).get("hits")
        if hits is None or not isinstance(hits, list):
            error_msg = f"Unexpected response: 'hits' path not found in response.result. Response: {raw_response}"
            raise ValueError(error_msg)

        # Track which IPs were found
        found_ips = set()

        # Process each hit from the response
        for hit in hits:
            # Extract resource from host_v1 wrapper
            resource = demisto.get(hit, "host_v1.resource", {})
            ip = resource.get("ip")
            found_ips.add(ip)
            labels = list({label.get("value") for label in resource.get("labels", [])})
            score, malicious_description = get_dbot_score(params, labels)
            dbot_score = Common.DBotScore(
                indicator=ip,
                indicator_type=DBotScoreType.IP,
                integration_name="Censys",
                score=score,
                malicious_description=malicious_description,
                reliability=params.get("integration_reliability"),
            )
            content = {
                "ip": ip,
                "asn": demisto.get(resource, "autonomous_system.asn"),
                "updated_date": demisto.get(resource, "whois.network.updated"),
                "geo_latitude": demisto.get(resource, "location.coordinates.latitude"),
                "geo_longitude": demisto.get(resource, "location.coordinates.longitude"),
                "geo_country": demisto.get(resource, "location.country"),
                "port": ", ".join([str(service.get("port")) for service in resource.get("services", [])]),
            }
            indicator = Common.IP(dbot_score=dbot_score, **content)

            hr_output = f"### Censys results for IP: {ip}\n\n"
            hr_output += prepare_hr_for_ip_resource(resource)
            results.append(
                CommandResults(
                    outputs_prefix="Censys.IP",
                    outputs_key_field="ip",
                    readable_output=hr_output,
                    outputs=resource,
                    raw_response=raw_response,
                    indicator=indicator,
                )
            )
            execution_metrics.success += 1

        # Report IPs that were not found
        for ip in ips:
            if ip not in found_ips:
                demisto.debug(f"ip_command: IP {ip} not found in search results")
                results.append(CommandResults(readable_output=f"No results found for IP: {ip}"))

    except Exception as e:
        # Handle exceptions for the entire batch
        handle_exceptions(e, results, execution_metrics, ", ".join(ips))

    if execution_metrics.metrics:
        demisto.debug(f"ip_command: adding execution metrics: {execution_metrics.metrics}")
        results.append(execution_metrics.metrics)

    demisto.debug(f"ip_command: returning {len(results)} results. Types: {[type(r) for r in results]}")
    return results


def domain_command(client: Client, args: dict, params: dict):
    domains: list = argToList(args.get("domain"))
    ports = argToList(args.get("port", DEFAULT_PORTS))
    ports = [validate_port_argument(arg_to_number(port, arg_name="port")) for port in ports if str(port).strip()]  # type: ignore
    ports_str = ", ".join(map(str, ports or DEFAULT_PORTS))

    demisto.debug(f"domain_command: processing domains {domains}, ports {ports}")
    results: List[CommandResults] = []
    execution_metrics = ExecutionMetrics()

    try:
        # Build query for all domains
        query = " or ".join(
            [f'host.dns.names="{dom}" or (web.hostname="{dom}" and web.port: {{{ports_str}}})' for dom in domains]
        )

        # Send all domains in a single API call with pagination
        raw_response = censys_search_with_pagination(client, query)
        response = raw_response.get("result", {})
        hits = response.get("hits")
        if hits is None or not isinstance(hits, list):
            error_msg = f"Unexpected response: 'hits' path not found in response.result. Response: {response}"
            raise ValueError(error_msg)

        # Track which domains were found
        found_domains = set()

        # Group hits by domain (based on dns.names field or hostname)
        domain_hits: dict[str, list] = {domain: [] for domain in domains}
        for hit in hits:
            # Check if this is a web property hit
            if "webproperty_v1" in hit:
                resource = demisto.get(hit, "webproperty_v1.resource", {})
                hostname = resource.get("hostname", "")
                domain_hits[hostname].append(hit)
                found_domains.add(hostname)
                continue

            resource = demisto.get(hit, "host_v1.resource", {})
            dns_names = demisto.get(resource, "dns.names", [])
            # Match this hit to the requested domain(s)
            for domain in domains:
                if domain in dns_names:
                    domain_hits[domain].append(hit)
                    found_domains.add(domain)

        # Create results for each domain
        for domain in domains:
            hits_for_domain = domain_hits.get(domain, [])

            if not hits_for_domain:
                # No results for this domain
                demisto.debug(f"domain_command: domain {domain} not found in search results")
                results.append(CommandResults(readable_output=f"No results found for domain: {domain}"))
                continue

            # Separate host and web property hits
            host_hits = [hit for hit in hits_for_domain if "host_v1" in hit]
            web_property_hits = [hit for hit in hits_for_domain if "webproperty_v1" in hit]

            # Extract resources from host_v1 wrapper
            host_resources = []
            for hit in host_hits:
                resource = demisto.get(hit, "host_v1.resource", {})
                host_resources.append(resource)

            # Extract resources from webproperty_v1 wrapper
            web_property_resources = []
            for hit in web_property_hits:
                resource = demisto.get(hit, "webproperty_v1.resource", {})
                web_property_resources.append(resource)

            relationships = [
                EntityRelationship(
                    name=EntityRelationship.Relationships.RELATED_TO,
                    entity_a=domain,
                    entity_a_type="Domain",
                    entity_b=demisto.get(hit, "host_v1.resource.ip"),
                    entity_b_type="IP",
                    reverse_name=EntityRelationship.Relationships.RELATED_TO,
                    brand="Censys",
                )
                for hit in host_hits
            ]
            # Collect all labels from all host hits for this domain
            all_labels = []
            for res in host_resources:
                all_labels.extend([label.get("value") for label in res.get("labels", [])])
            all_labels = list(set(all_labels))

            # Build combined HR output
            hr_outputs = []
            # Add host HR output if there are host hits
            if not all_labels:
                host_hr = f"### Censys results for Domain: {domain}"
            elif len(all_labels) == 1:
                host_hr = f"### Censys results for Domain: {domain} with label {all_labels[0]}"
            else:
                host_hr = f"### Censys results for Domain: {domain} with following labels:\n{', '.join(all_labels)}"
            hr_outputs.append(host_hr)

            # Add web property HR output if there are web property hits
            if web_property_resources:
                for res in web_property_resources:
                    all_labels.extend([label.get("value") for label in res.get("labels", [])])
                all_labels = list(set(all_labels))

                hr_output = prepare_hr_for_web_property_resource(web_property_resources)
                hr_outputs.append(hr_output)

            combined_hr_output = "\n\n".join(hr_outputs) if hr_outputs else f"No results found for domain: {domain}"

            score, malicious_description = get_dbot_score(params, all_labels)
            dbot_score = Common.DBotScore(
                indicator=domain,
                indicator_type=DBotScoreType.DOMAIN,
                integration_name="Censys",
                score=score,
                malicious_description=malicious_description,
                reliability=params.get("integration_reliability"),
            )
            indicator = Common.Domain(domain=domain, dbot_score=dbot_score, relationships=relationships)

            # Combine all resources for outputs
            all_resources = host_resources + web_property_resources

            results.append(
                CommandResults(
                    outputs_prefix="Censys.Domain",
                    outputs_key_field="Domain",
                    readable_output=combined_hr_output,
                    outputs=all_resources,
                    raw_response=raw_response,
                    indicator=indicator,
                    relationships=relationships,
                )
            )
            execution_metrics.success += 1

    except Exception as e:
        # Handle exceptions for the entire batch
        handle_exceptions(e, results, execution_metrics, ", ".join(domains))

    if execution_metrics.metrics:
        demisto.debug(f"domain_command: adding execution metrics: {execution_metrics.metrics}")
        results.append(execution_metrics.metrics)

    demisto.debug(f"domain_command: returning {len(results)} results. Types: {[type(r) for r in results]}")
    return results


def censys_host_history_list_command(client: Client, args: dict) -> CommandResults:
    """Retrieve the event history for a host (IP address) with automatic pagination.

    This command fetches historical scan data for an IP address from the Censys API,
    automatically handling pagination using the scanned_to cursor. It implements robust
    partial data handling: if an API error occurs mid-pagination after successfully
    collecting some events, the collected data is returned with a warning instead of
    failing completely.

    Pagination limits:
    - Maximum records: 1000 (MAX_HOST_HISTORY_RECORDS)
    - Maximum pages: 10 (MAX_NUMBER_OF_PAGES)
    - Timeout: 4 minutes (240 seconds)

    Args:
        client: The Censys client instance for making API requests.
        args: Command arguments containing:
            - ip_address (str, required): The IP address to retrieve history for.
            - start_time (str, required): Start time from the past (e.g., '7 days ago').
            - end_time (str, required): End time near current (e.g., 'now').

    Returns:
        CommandResults with host event history data and human-readable table.

    Raises:
        ValueError: If required arguments are missing or time range is invalid.
        DemistoException: If the API call fails before any data is collected.
    """
    ip_address: str = args.get("host_id", "")
    start_time: str = args.get("start_time", "")
    end_time: str = args.get("end_time", "")

    ip_address = validate_required_argument(ip_address, "host_id")
    start_time = validate_required_argument(start_time, "start_time")
    end_time = validate_required_argument(end_time, "end_time")

    if not is_ip_valid(ip_address, accept_v6_ips=True):
        raise ValueError(ERRORS["INVALID_IP"].format(ip_address))

    start_time: str = arg_to_datetime(start_time, arg_name="start_time").strftime(DATE_FORMAT)  # type: ignore
    end_time: str = arg_to_datetime(end_time, arg_name="end_time").strftime(DATE_FORMAT)  # type: ignore

    if start_time >= end_time:
        raise ValueError(ERRORS["INVALID_TIME_RANGE"].format("start_time", start_time, "end_time", end_time))

    all_events: list = []
    page_count = 0
    is_partial: bool = False
    # For pagination: current_end_time is the "recent" boundary that shifts with scanned_to.
    # censys_host_history_request internally reverses start/end for the API.
    current_end_time = end_time
    current_time_str = datetime.now(timezone.utc).strftime(DATE_FORMAT)

    demisto.debug(f"censys_host_history_list: starting pagination for {ip_address}, start_time={start_time}, end_time={end_time}")
    all_events_platform_url = f"{CENSYS_PLATFORM_URL}{HR_SUFFIX['HOST_ALL_EVENTS'].format(ip_address)}"
    while len(all_events) < MAX_NUMBER_OF_RECORDS and page_count < MAX_NUMBER_OF_PAGES:
        page_count += 1
        demisto.debug(f"censys_host_history_list: fetching page {page_count} for {ip_address}")

        # Check if pagination has exceeded the 4-minute timeout threshold
        if has_passed_time_threshold(current_time_str, DEFAULT_TIMEOUT_THRESHOLD_SECONDS):
            demisto.debug(
                f"censys_host_history_list: pagination timeout reached at page {page_count} "
                f"after collecting {len(all_events)} events. Stopping pagination due to 4-minute time limit."
            )
            partial_data_warning_mes = (
                f"Results limited due to command execution time constraint (4 minutes). "
                f"For complete results, visit: {all_events_platform_url}"
            )
            is_partial = True
            return_warning(partial_data_warning_mes)
            break

        try:
            response = client.censys_host_history_request(ip_address, start_time, current_end_time)
        except Exception as e:
            # Partial data handling: if we already collected some events, return them with a warning
            if all_events:
                demisto.debug(
                    f"censys_host_history_list: pagination failed at page {page_count} "
                    f"after collecting {len(all_events)} events. Error: {str(e)}"
                )
                partial_data_warning_mes = (
                    f"WARNING: Partial data collected ({len(all_events)} event(s)). "
                    f"Pagination stopped at page {page_count} due to error: {str(e)}"
                )
                is_partial = True
                return_warning(partial_data_warning_mes)
                break
            # No data collected yet — propagate the original error
            raise

        result = response.get("result", {})
        events = result.get("events", [])
        scanned_to = result.get("scanned_to")

        if not events:
            demisto.debug(f"censys_host_history_list: no events on page {page_count}. Pagination complete.")
            break

        # Respect the max records cap
        remaining_capacity = MAX_NUMBER_OF_RECORDS - len(all_events)
        all_events.extend(events[:remaining_capacity])

        demisto.debug(
            f"censys_host_history_list: page {page_count} returned {len(events)} events. Total collected: {len(all_events)}"
        )

        if len(all_events) >= MAX_NUMBER_OF_RECORDS:
            demisto.debug(f"censys_host_history_list: reached max {MAX_NUMBER_OF_RECORDS} records.")
            break

        if not scanned_to:
            demisto.debug("censys_host_history_list: no scanned_to cursor. Pagination complete.")
            break

        # If the cursor has gone past our time boundary, stop
        if scanned_to <= start_time:
            demisto.debug(
                f"censys_host_history_list: scanned_to ({scanned_to}) <= start_time ({start_time}). Pagination complete."
            )
            break

        # Advance the pagination cursor
        current_end_time = scanned_to

    if not all_events:
        return CommandResults(
            readable_output=(f"No historical data found for host {ip_address} within the specified time range."),
        )

    total_events = len(all_events)
    if is_partial:
        hr_output = (
            f"### Successfully retrieved {total_events} event(s) for host {ip_address} "
            f"(partial data - {page_count - 1} page(s) fetched).\n"
        )
    else:
        hr_output = f"### Successfully retrieved {total_events} event(s) for host {ip_address}.\n"

    if total_events >= MAX_NUMBER_OF_RECORDS:
        hr_output += (
            f"\nThere are more than {MAX_NUMBER_OF_RECORDS} host history records available for this host. "
            f"The first {MAX_NUMBER_OF_RECORDS} records are displayed. "
            f"Further exploration should be conducted on the [Censys platform]({all_events_platform_url}).\n"
        )

    hr_output += prepare_hr_for_host_history_list_command(all_events, ip_address)

    # Context data
    context_output = {
        "ip": ip_address,
        "events": all_events,
        "total_events": total_events,
        "partial_data": is_partial,
    }

    return CommandResults(
        readable_output=hr_output,
        outputs_prefix=OUTPUT_PREFIX["HOST_EVENT_HISTORY"],
        outputs_key_field="ip",
        outputs=context_output,
        raw_response={"result": {"events": all_events, "total_events": total_events, "partial_data": is_partial}},
    )


def censys_rescan_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Initiate a rescan and automatically retry until completion, then retrieve enrichment data.

    This command follows XSOAR scheduled command best practices:
    1. Initiates a live rescan on a host service
    2. Automatically retries every 30 seconds until the rescan is completed
    3. If the rescan fails, returns an error message
    4. Once completed, retrieves the updated enrichment data

    Args:
        client: The Censys client instance
        args: Command arguments

    Returns:
        CommandResults with scan status or list with ScheduledCommand
    """
    ioc_type = args.get("ioc_type", "service").strip()
    ioc_value = args.get("ioc_value", "").strip()
    port = arg_to_number(args.get("port", 443))
    protocol = args.get("protocol", "").strip()
    scan_id = args.get("scan_id", "").strip()
    transport_protocol = args.get("transport_protocol", DEFAULT_TRANSPORT_PROTOCOL).strip()
    polling = args.get("polling", False)

    validate_rescan_command_args(ioc_type, ioc_value, port, protocol, transport_protocol)

    outputs = {
        "ioc_value": ioc_value,
        "port": port,
        "status": "initiated",
        "scan_id": scan_id,
        "is_completed": False,
    }

    if not polling:
        response = client.censys_initiate_rescan_request(ioc_type, ioc_value, port, protocol, transport_protocol)
        result = response.get("result", {})
        scan_id = result.get("tracked_scan_id")

        if not scan_id:
            outputs.update({"status": "failed", "is_completed": True})
            return CommandResults(
                readable_output="### Scan initiated but no scan ID returned.",
                outputs_prefix=OUTPUT_PREFIX["INITIATE_RESCAN"],
                outputs=remove_empty_elements(outputs),
                raw_response=response,
            )

        outputs["scan_id"] = scan_id
        return CommandResults(
            readable_output=f"### Scan initiated successfully for {ioc_value}:{port}.\n#### Scan ID: {scan_id}.",
            outputs_prefix=OUTPUT_PREFIX["INITIATE_RESCAN"],
            outputs_key_field="scan_id",
            outputs=outputs,
            raw_response=response,
        )

    # Check rescan status
    status_response = client.censys_rescan_status_request(scan_id)
    result = status_response.get("result", {})
    completed = result.get("completed")

    if completed is None:
        outputs.update({"status": "in_progress", "is_completed": False})
        return CommandResults(
            readable_output=f"### Scan is still in progress for {ioc_value}:{port}.\n#### Scan ID: {scan_id}",
            outputs_prefix=OUTPUT_PREFIX["INITIATE_RESCAN"],
            outputs_key_field="scan_id",
            outputs=remove_empty_elements(outputs),
            raw_response=status_response,
        )

    if not completed:
        outputs.update({"status": "failed", "is_completed": True})
        return CommandResults(
            readable_output=f"### Scan failed for {ioc_value}:{port}.\n#### Scan ID: {scan_id}",
            outputs_prefix=OUTPUT_PREFIX["INITIATE_RESCAN"],
            outputs_key_field="scan_id",
            outputs=remove_empty_elements(outputs),
            raw_response=status_response,
        )

    # Determine index based on ioc_type
    if ioc_type.lower() == "service":
        index = "ipv4"
        query = ioc_value
    else:
        index = "webproperty"
        query = f"{ioc_value}:{port}"

    enrichment_response = client.censys_view_request(index, query)
    resource = enrichment_response.get("result", {}).get("resource", {})

    if ioc_type.lower() == "service":
        human_readable = prepare_hr_for_ip_resource(resource)
    else:
        human_readable = prepare_hr_for_web_property_resource(resource)

    hr_output = f"### Scan completed successfully for {ioc_value}:{port}.\n" + human_readable
    outputs.update({"enrichment_data": resource, "status": "completed", "is_completed": True})

    return CommandResults(
        readable_output=hr_output,
        outputs_prefix=OUTPUT_PREFIX["INITIATE_RESCAN"],
        outputs_key_field="scan_id",
        outputs=remove_empty_elements(outputs),
        raw_response=enrichment_response,
    )


def censys_related_infrastructure_list_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Initiate a CensEye related infrastructure job and poll until completion, then retrieve pivot data.

    This command follows XSOAR scheduled command best practices:
    1. Initiates a CensEye job for the given IOC
    2. Automatically retries every 10 seconds until the job is completed
    3. If the job fails, returns an error message
    4. Once completed, retrieves the pivot data results

    Args:
        client: The Censys client instance
        args: Command arguments

    Returns:
        CommandResults with job status or list with ScheduledCommand
    """
    ioc_type = args.get("ioc_type", "Host").strip()
    ioc_value = args.get("ioc_value", "").strip()
    job_id = args.get("job_id", "").strip()
    polling = args.get("polling", False)

    validate_related_infra_command_args(ioc_type, ioc_value)

    outputs = {
        "ioc_value": ioc_value,
        "status": "initiated",
        "job_id": job_id,
        "is_completed": False,
    }

    if not polling:
        response = client.censys_initiate_job_request(ioc_type.lower(), ioc_value)
        result = response.get("result", {})
        job_id = result.get("job_id")

        if not job_id:
            outputs.update({"status": "failed", "is_completed": True})
            return CommandResults(
                readable_output="### Job initiated but no job ID returned.",
                outputs_prefix=OUTPUT_PREFIX["RELATED_INFRASTRUCTURE"],
                outputs=remove_empty_elements(outputs),
                raw_response=response,
            )

        outputs["job_id"] = job_id
        return CommandResults(
            readable_output=f"### Job initiated successfully for {ioc_value}.\n#### Job ID: {job_id}",
            outputs_prefix=OUTPUT_PREFIX["RELATED_INFRASTRUCTURE"],
            outputs_key_field="job_id",
            outputs=outputs,
            raw_response=response,
        )

    # Check job status
    status_response = client.censys_job_status_request(job_id)
    result = status_response.get("result", {})
    state = result.get("state", "")

    if state == "failed":
        outputs.update({"status": "failed", "is_completed": True})
        return CommandResults(
            readable_output=f"### Job failed for {ioc_value}.\n#### Job ID: {job_id}",
            outputs_prefix=OUTPUT_PREFIX["RELATED_INFRASTRUCTURE"],
            outputs_key_field="job_id",
            outputs=remove_empty_elements(outputs),
            raw_response=status_response,
        )
    elif state != "completed":
        outputs.update({"status": "in_progress", "is_completed": False})
        return CommandResults(
            readable_output=f"### Job is still in progress for {ioc_value}.\n#### Job ID: {job_id}",
            outputs_prefix=OUTPUT_PREFIX["RELATED_INFRASTRUCTURE"],
            outputs_key_field="job_id",
            outputs=remove_empty_elements(outputs),
            raw_response=status_response,
        )

    # Job completed - fetch results
    results_response = client.censys_job_results_request(job_id)
    pivot_data = demisto.get(results_response, "result.results", [])

    hr_output = f"### Job completed successfully for {ioc_value}.\n\n"
    if pivot_data:
        pivot_data_hr = prepare_hr_for_pivot_information(pivot_data)
        hr_output += pivot_data_hr
    else:
        hr_output += "#### No pivot data found."

    outputs.update({"pivot_data": pivot_data, "status": "completed", "is_completed": True})

    return CommandResults(
        readable_output=hr_output,
        outputs_prefix=OUTPUT_PREFIX["RELATED_INFRASTRUCTURE"],
        outputs_key_field="job_id",
        outputs=remove_empty_elements(outputs),
        raw_response=results_response,
    )


def run_polling_command(
    client: Client, args: dict[str, Any], command_name: str, search_function: Callable
) -> list[CommandResults] | CommandResults:
    """Generic polling command handler following XSOAR best practices.

    Args:
        client: The Censys client instance
        args: Command arguments
        command_name: Name of the command for scheduling
        search_function: Function to execute for status checking

    Returns:
        List of CommandResults with ScheduledCommand or single CommandResults
    """
    result = search_function(client, args)
    outputs = result.outputs or {}
    is_completed = outputs.get("is_completed")

    if is_completed:
        return result

    if not is_completed:
        polling_args = {**args, "polling": True}
        scan_id = outputs.get("scan_id")
        job_id = outputs.get("job_id")
        if scan_id:
            polling_args["scan_id"] = scan_id
        if job_id:
            polling_args["job_id"] = job_id
        scheduled_command = ScheduledCommand(
            command=command_name,
            next_run_in_seconds=DEFAULT_POLLING_INTERVAL,
            args=polling_args,
            timeout_in_seconds=DEFAULT_POLLING_TIMEOUT,
        )
        command_results = CommandResults(scheduled_command=scheduled_command)
        return [result, command_results]

    return result


""" MAIN FUNCTION """


def main() -> None:
    params = demisto.params()
    api_token = params.get("api_token", {}).get("password")
    org_id = params.get("organization_id")
    verify_certificate = not params.get("insecure", False)
    proxy = params.get("proxy", False)
    base_url = params.get("server_url") or "https://api.platform.censys.io"

    command = demisto.command()
    demisto.debug(f"Command being called is {command}")

    commands: dict = {
        "cen-host-history-list": censys_host_history_list_command,
    }
    scheduled_commands: dict = {
        "cen-rescan": censys_rescan_command,
        "cen-related-infrastructure-list": censys_related_infrastructure_list_command,
    }

    try:
        args = demisto.args()
        client = Client(base_url=base_url, api_token=api_token, org_id=org_id, verify=verify_certificate, proxy=proxy)

        if command == "test-module":
            return_results(test_module(client, params))

        elif command == "cen-view":
            return_results(censys_view_command(client, args))
        elif command == "cen-search":
            return_results(censys_search_command(client, args))
        elif command == "ip":
            return_results(ip_command(client, args, params))
        elif command == "domain":
            return_results(domain_command(client, args, params))
        elif command in commands:
            # remove nulls from dictionary and trim space from args
            remove_nulls_from_dictionary(trim_spaces_from_args(args))
            result = commands[command](client, args)
            return_results(result)
        elif command in scheduled_commands:
            remove_nulls_from_dictionary(trim_spaces_from_args(args))

            return_results(
                run_polling_command(client=client, args=args, search_function=scheduled_commands[command], command_name=command)
            )
    # Log exceptions and return errors
    except Exception as e:
        return_error(f"Failed to execute {command} command.\nError:\n{e!s}")


""" ENTRY POINT """

if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
