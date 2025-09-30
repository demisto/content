from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from CommonServerPython import *  # noqa: F401 # pylint: disable=unused-wildcard-import
from CommonServerPython import Common, DBotScoreReliability, DBotScoreType
from datadog_api_client import ApiClient, Configuration
from datadog_api_client.exceptions import ForbiddenException, UnauthorizedException
from datadog_api_client.model_utils import unset
from datadog_api_client.v1.api.authentication_api import AuthenticationApi
from datadog_api_client.v1.api.events_api import EventsApi
from datadog_api_client.v2.api.logs_api import LogsApi
from datadog_api_client.v2.api.security_monitoring_api import SecurityMonitoringApi
from datadog_api_client.v2.model.logs_list_request import LogsListRequest
from datadog_api_client.v2.model.logs_list_request_page import LogsListRequestPage
from datadog_api_client.v2.model.logs_query_filter import LogsQueryFilter
from datadog_api_client.v2.model.logs_sort import LogsSort
from datadog_api_client.v2.model.security_monitoring_signal_assignee_update_attributes import (
    SecurityMonitoringSignalAssigneeUpdateAttributes,
)
from datadog_api_client.v2.model.security_monitoring_signal_assignee_update_data import (
    SecurityMonitoringSignalAssigneeUpdateData,
)
from datadog_api_client.v2.model.security_monitoring_signal_assignee_update_request import (
    SecurityMonitoringSignalAssigneeUpdateRequest,
)
from datadog_api_client.v2.model.security_monitoring_signal_state_update_attributes import (
    SecurityMonitoringSignalStateUpdateAttributes,
)
from datadog_api_client.v2.model.security_monitoring_signal_state_update_data import (
    SecurityMonitoringSignalStateUpdateData,
)
from datadog_api_client.v2.model.security_monitoring_signal_state_update_request import (
    SecurityMonitoringSignalStateUpdateRequest,
)
from datadog_api_client.v2.model.security_monitoring_signals_sort import (
    SecurityMonitoringSignalsSort,
)
from datadog_api_client.v2.model.security_monitoring_triage_user import (
    SecurityMonitoringTriageUser,
)
from dateparser import parse
from urllib3 import disable_warnings

from CommonServerUserPython import *  # noqa: F401

# Disable insecure warnings
disable_warnings()

""" CONSTANTS """

DEFAULT_PAGE_SIZE = 50
PAGE_SIZE_ERROR_MSG = "Invalid Input Error: page size should be greater than zero."
DEFAULT_FROM_DATE = "-7days"
DEFAULT_TO_DATE = "now"
INTEGRATION_NAME = "DatadogCloudSIEM"
INTEGRATION_CONTEXT_NAME = "Datadog"
SECURITY_SIGNAL_CONTEXT_NAME = f"{INTEGRATION_CONTEXT_NAME}.SecuritySignal"
NO_RESULTS_FROM_API_MSG = "API didn't return any results for given search parameters."
ERROR_MSG = "Something went wrong!\n"
AUTHENTICATION_ERROR_MSG = "Authentication Error: Invalid API Key. Make sure API Key and Server URL are correct."


""" DATACLASSES """


@dataclass
class Assignee:
    id: int
    uuid: str
    name: str


@dataclass
class Triage:
    state: str
    comment: str
    reason: str
    assignee: Assignee


@dataclass
class Rule:
    id: str
    name: str
    type: str
    tags: List[str]


@dataclass
class Log:
    id: str
    timestamp: Optional[datetime] = None
    message: Optional[str] = None
    service: Optional[str] = None
    host: Optional[str] = None
    source: Optional[str] = None
    status: Optional[str] = None
    tags: Optional[List[str]] = None

    # Raw log data
    raw: Optional[Dict[str, Any]] = None

    def to_display_dict(self) -> Dict[str, Any]:
        """
        Convert Log to a dictionary optimized for human-readable display.

        Excludes the raw field and formats content appropriately for markdown tables.
        Truncates long messages and limits tag display for readability.

        Returns:
            Dict[str, Any]: Dictionary with display-friendly field names and values.
        """
        return {
            "ID": self.id,
            "Timestamp": str(self.timestamp) if self.timestamp else None,
            "Message": (
                self.message[:100] + "..."
                if self.message and len(self.message) > 100
                else self.message
            ),
            "Service": self.service,
            "Host": self.host,
            "Source": self.source,
            "Status": self.status,
            "Tags": (
                ", ".join(self.tags[:3]) + ("..." if len(self.tags) > 3 else "")
                if self.tags
                else None
            ),
        }

    def to_dict(self) -> Dict[str, Any]:
        """
        Convert Log to a plain dictionary for XSOAR context output.

        Converts nested objects to dictionaries and handles datetime serialization.
        Excludes None values to prevent overriding existing fields during partial updates.

        Returns:
            Dict[str, Any]: Dictionary for context output.
                           Only includes fields with non-None values.
        """
        result = {
            "id": self.id,
            "timestamp": str(self.timestamp) if self.timestamp else None,
            "message": self.message,
            "service": self.service,
            "host": self.host,
            "source": self.source,
            "status": self.status,
            "tags": self.tags,
            "raw": self.raw,
        }

        # Remove None values recursively
        return remove_none_values(result)


@dataclass
class SecuritySignal:
    id: str
    timestamp: Optional[datetime] = None
    host: Optional[str] = None
    service: Optional[List[str]] = None
    severity: Optional[str] = None
    title: Optional[str] = None
    message: Optional[str] = None
    rule: Optional[Rule] = None
    triage: Optional[Triage] = None
    tags: Optional[List[str]] = None
    triggering_log_id: Optional[str] = None

    # Raw signal
    raw: Optional[Dict[str, Any]] = None

    def to_display_dict(self) -> Dict[str, Any]:
        """
        Convert SecuritySignal to a dictionary optimized for human-readable display.

        Excludes the raw field and formats nested objects appropriately for markdown tables.

        Returns:
            Dict[str, Any]: Dictionary with display-friendly field names and values.
        """
        result = {
            "ID": self.id,
            "Title": self.title,
            "Message": self.message,
            "Severity": self.severity,
            "State": self.triage.state if self.triage else None,
            "Rule Name": self.rule.name if self.rule else None,
            "Rule Type": self.rule.type if self.rule else None,
            "Host": self.host,
            "Services": ", ".join(self.service) if self.service else None,
            "Timestamp": str(self.timestamp) if self.timestamp else None,
            "Assignee": (
                self.triage.assignee.name
                if (self.triage and self.triage.assignee)
                else None
            ),
            "Tags": (
                ", ".join(self.tags[:5]) + ("..." if len(self.tags) > 5 else "")
                if self.tags
                else None
            ),
        }
        return remove_none_values(result)

    def to_dict(self) -> Dict[str, Any]:
        """
        Convert SecuritySignal to a plain dictionary for XSOAR context output.

        Converts nested dataclass objects to dictionaries and handles datetime serialization.
        Excludes None values to prevent overriding existing fields during partial updates.

        Returns:
            Dict[str, Any]: Dictionary with snake_case field names matching YAML contextPath.
                           Only includes fields with non-None values.
        """
        result = {
            "id": self.id,
            "timestamp": str(self.timestamp) if self.timestamp else None,
            "host": self.host,
            "service": self.service,
            "severity": self.severity,
            "title": self.title,
            "message": self.message,
            "tags": self.tags,
            "triggering_log_id": self.triggering_log_id,
            "raw": self.raw,
        }

        # Convert rule to dict if present
        if self.rule:
            result["rule"] = {
                "id": self.rule.id,
                "name": self.rule.name,
                "type": self.rule.type,
                "tags": self.rule.tags,
            }

        # Convert triage to dict if present
        if self.triage:
            result["triage"] = {
                "state": self.triage.state,
                "comment": self.triage.comment,
                "reason": self.triage.reason,
            }
            # Convert assignee to dict if present
            if self.triage.assignee:
                result["triage"]["assignee"] = {  # type: ignore
                    "id": self.triage.assignee.id,
                    "uuid": self.triage.assignee.uuid,
                    "name": self.triage.assignee.name,
                }

        # Remove None values recursively
        return remove_none_values(result)


""" HELPER FUNCTIONS """


def extract_iocs_from_signal(signal: SecuritySignal) -> List[Common.Indicator]:
    """
    Extract Indicators of Compromise (IOCs) from a SecuritySignal and create standard XSOAR contexts.

    Searches through signal data for IP addresses, URLs, and file hashes,
    then creates appropriate Common.IP, Common.URL, Common.File objects with DBotScore.

    SIEM doesn't provide reputation, just detection, so indicators score is always Common.DBotScore.NONE

    Args:
        signal (SecuritySignal): SecuritySignal object to extract IOCs from

    Returns:
        List[Common.Indicator]: List of standard XSOAR indicator objects (IP, URL, File)
    """
    import re

    indicators = []

    # Combine text fields to search for IOCs
    searchable_text = " ".join(
        filter(
            None,
            [
                signal.message or "",
                signal.title or "",
                " ".join(signal.tags or []),
                json.dumps(signal.raw or {}),
            ],
        )
    )

    # Extract IP addresses
    ip_pattern = r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"
    ips = set(re.findall(ip_pattern, searchable_text))

    for ip in ips:
        # Skip private/local IPs for security signals (focus on external threats)
        if not (
            ip.startswith(
                (
                    "10.",
                    "172.16.",
                    "172.17.",
                    "172.18.",
                    "172.19.",
                    "172.20.",
                    "172.21.",
                    "172.22.",
                    "172.23.",
                    "172.24.",
                    "172.25.",
                    "172.26.",
                    "172.27.",
                    "172.28.",
                    "172.29.",
                    "172.30.",
                    "172.31.",
                    "192.168.",
                    "127.",
                )
            )
        ):

            dbot_score = Common.DBotScore(
                indicator=ip,
                indicator_type=DBotScoreType.IP,
                integration_name=INTEGRATION_NAME,
                score=Common.DBotScore.NONE,
                reliability=DBotScoreReliability.B,
                malicious_description=f"IP found in Datadog security signal: {signal.title} [id:{signal.id}]",
            )
            ip_indicator = Common.IP(ip=ip, dbot_score=dbot_score)
            indicators.append(ip_indicator)

    # Extract URLs
    url_pattern = r'https?://[^\s<>"{}|\\^`\[\]]+'
    urls = set(re.findall(url_pattern, searchable_text))

    for url in urls:
        dbot_score = Common.DBotScore(
            indicator=url,
            indicator_type=DBotScoreType.URL,
            integration_name=INTEGRATION_NAME,
            score=Common.DBotScore.NONE,
            reliability=DBotScoreReliability.B,
            malicious_description=f"URL found in Datadog security signal: {signal.title} [id:{signal.id}]",
        )
        url_indicator = Common.URL(url=url, dbot_score=dbot_score)
        indicators.append(url_indicator)

    # Extract file hashes (MD5, SHA1, SHA256)
    md5_pattern = r"\b[a-fA-F0-9]{32}\b"
    sha1_pattern = r"\b[a-fA-F0-9]{40}\b"
    sha256_pattern = r"\b[a-fA-F0-9]{64}\b"

    md5_hashes = set(re.findall(md5_pattern, searchable_text))
    sha1_hashes = set(re.findall(sha1_pattern, searchable_text))
    sha256_hashes = set(re.findall(sha256_pattern, searchable_text))

    # Group hashes by type
    for hash_value in md5_hashes:
        dbot_score = Common.DBotScore(
            indicator=hash_value,
            indicator_type=DBotScoreType.FILE,
            integration_name=INTEGRATION_NAME,
            score=Common.DBotScore.NONE,
            reliability=DBotScoreReliability.B,
            malicious_description=f"MD5 hash found in Datadog security signal: {signal.title} [id:{signal.id}]",
        )
        file_indicator = Common.File(md5=hash_value, dbot_score=dbot_score)
        indicators.append(file_indicator)

    for hash_value in sha1_hashes:
        dbot_score = Common.DBotScore(
            indicator=hash_value,
            indicator_type=DBotScoreType.FILE,
            integration_name=INTEGRATION_NAME,
            score=Common.DBotScore.NONE,
            reliability=DBotScoreReliability.B,
            malicious_description=f"SHA1 hash found in Datadog security signal: {signal.title} [id:{signal.id}]",
        )
        file_indicator = Common.File(sha1=hash_value, dbot_score=dbot_score)
        indicators.append(file_indicator)

    for hash_value in sha256_hashes:
        dbot_score = Common.DBotScore(
            indicator=hash_value,
            indicator_type=DBotScoreType.FILE,
            integration_name=INTEGRATION_NAME,
            score=Common.DBotScore.NONE,
            reliability=DBotScoreReliability.B,
            malicious_description=f"SHA256 hash found in Datadog security signal: {signal.title} [id:{signal.id}]",
        )
        file_indicator = Common.File(sha256=hash_value, dbot_score=dbot_score)
        indicators.append(file_indicator)

    return indicators


def remove_none_values(data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Recursively remove keys with None values from a dictionary.

    Args:
        data (Dict[str, Any]): Dictionary that may contain None values

    Returns:
        Dict[str, Any]: New dictionary with None values removed recursively
    """
    if not isinstance(data, dict):
        return data

    result = {}
    for key, value in data.items():
        if value is None:
            continue
        elif isinstance(value, dict):
            cleaned_dict = remove_none_values(value)
            if cleaned_dict:  # Only add if the cleaned dict is not empty
                result[key] = cleaned_dict
        elif isinstance(value, list):
            # Handle lists by removing None values and recursively cleaning dict items
            cleaned_list = []
            for item in value:
                if item is None:
                    continue
                elif isinstance(item, dict):
                    cleaned_item = remove_none_values(item)
                    if cleaned_item:  # Only add if the cleaned dict is not empty
                        cleaned_list.append(cleaned_item)
                else:
                    cleaned_list.append(item)
            if cleaned_list:  # Only add if the cleaned list is not empty
                result[key] = cleaned_list
        else:
            result[key] = value

    return result


def add_utc_offset(dt_str: str):
    """
    Converts a datetime string in ISO format to the equivalent datetime object
    with a UTC offset, and returns the resulting datetime string in ISO format.

    Args:
        dt_str (str): A string representing a datetime in ISO format (YYYY-MM-DDTHH:MM:SS[.ffffff][+/-HH:MM])

    Returns:
        str: A string representing the input datetime with a UTC offset, in ISO format (YYYY-MM-DDTHH:MM:SS[.ffffff]+00:00)
    """
    dt = datetime.fromisoformat(dt_str)
    dt_with_offset = dt.replace(tzinfo=timezone.utc)
    return dt_with_offset.isoformat()


def convert_datetime_to_str(data: dict) -> dict:
    """
    Converts any datetime objects found in the input dictionary to ISO-formatted strings.

    Args:
        data (Dict): The input dictionary to be converted.

    Returns:
        Dict: A new dictionary with the same structure as the input dictionary, but with datetime objects
        replaced by ISO-formatted strings.
    """
    for key, value in data.items():
        if isinstance(value, dict):
            convert_datetime_to_str(value)
        elif isinstance(value, datetime):
            data[key] = add_utc_offset(value.strftime("%Y-%m-%dT%H:%M:%S"))
    return data


def lookup_to_markdown(results: list[dict], title: str) -> str:
    """
    Convert a list of dictionaries to a Markdown table.

    Args:
        results (List[Dict]): A list of dictionaries representing the lookup results.
        title (str): The title of the Markdown table.

    Returns:
        str: A string containing the Markdown table.

    """
    headers = results[0] if results else {}
    return tableToMarkdown(
        title,
        results,
        headers=list(headers.keys()),
        removeNull=True,
    )


def as_list(v: Any) -> List[Any]:
    """
    Convert a value to a list format.

    Args:
        v (Any): Value to convert to list. Can be None, a single value, or already a list.

    Returns:
        List[Any]: A list containing the value(s). Empty list if input is None.

    Examples:
        >>> as_list(None)
        []
        >>> as_list("single")
        ["single"]
        >>> as_list([1, 2, 3])
        [1, 2, 3]
    """
    if v is None:
        return []
    if isinstance(v, list):
        return v
    return [v]


def flatten_tag_map(tag_map: Dict[str, Any]) -> List[str]:
    """
    Flatten a tag dictionary into a list of key:value strings.

    Args:
        tag_map (Dict[str, Any]): Dictionary where keys are tag names and values are tag values.
                                 Values can be strings, numbers, or lists.

    Returns:
        List[str]: List of strings in "key:value" format.

    Examples:
        >>> flatten_tag_map({"env": "prod", "team": ["security", "ops"]})
        ["env:prod", "team:security", "team:ops"]
    """
    flat: List[str] = []
    for k, v in (tag_map or {}).items():
        if isinstance(v, list):
            flat.extend([f"{k}:{str(item)}" for item in v])
        else:
            flat.append(f"{k}:{str(v)}")
    return flat


def parse_security_signal(data: Dict[str, Any]) -> SecuritySignal:
    """
    Parse raw security signal data from Datadog API into a structured SecuritySignal object.

    Extracts and organizes key fields from the nested API response structure, handling
    optional fields gracefully and flattening complex nested data.

    Args:
        data (Dict[str, Any]): Raw security signal data from Datadog API response.
                              Expected to contain 'attributes', 'custom', and other nested fields.

    Returns:
        SecuritySignal: Structured dataclass containing parsed signal information with
                       nested Rule, Triage, and Assignee objects as applicable.

    Example:
        >>> api_data = {"id": "signal-123", "attributes": {"message": "Alert", ...}}
        >>> signal = parse_security_signal(api_data)
        >>> signal.id
        "signal-123"
    """

    data = convert_datetime_to_str(data)
    attrs = data.get("attributes", {}) or {}
    custom = attrs.get("custom", {}) or {}
    workflow = custom.get("workflow", {}) or {}
    rule_d = workflow.get("rule", {}) or {}
    triage_d = workflow.get("triage", {}) or {}
    assignee_d = triage_d.get("assignee", {}) or {}
    rule = (
        Rule(
            id=rule_d.get("id", ""),
            name=rule_d.get("name", ""),
            type=rule_d.get("type", ""),
            tags=as_list(rule_d.get("tags", "")),
        )
        if rule_d
        else None
    )
    triage = (
        Triage(
            state=triage_d.get("state", ""),
            reason=triage_d.get("archiveReason", ""),
            comment=triage_d.get("archiveComment", ""),
            assignee=(
                Assignee(
                    id=assignee_d.get("id", -1),
                    uuid=assignee_d.get("uuid", ""),
                    name=assignee_d.get("name", "Unassigned"),
                )
            ),
        )
        if triage_d
        else None
    )
    tag_map = data.get("tag") or attrs.get("tag") or {}
    tags_list = as_list(data.get("tags")) or as_list(attrs.get("tags"))
    flat_map = flatten_tag_map(tag_map)
    seen = set(tags_list)
    tags = tags_list + [t for t in flat_map if t not in seen]
    services = as_list(data.get("service")) or as_list(attrs.get("service"))

    return SecuritySignal(
        id=data.get("id", "security-signal"),
        timestamp=attrs.get("timestamp"),
        host=attrs.get("host"),
        service=services,
        severity=custom.get("severity"),
        title=custom.get("title") or attrs.get("title") or rule_d.get("name"),
        message=attrs.get("message"),
        rule=rule,
        triage=triage,
        tags=tags,
        triggering_log_id=attrs.get("triggering_log_id"),
        raw=data,
    )


def parse_log(data: Dict[str, Any]) -> Log:
    """
    Parse raw log data from Datadog API into a structured Log object.

    Extracts and organizes key fields from the nested API response structure, handling
    optional fields gracefully and converting timestamps to datetime objects.

    Args:
        data (Dict[str, Any]): Raw log data from Datadog API response.
                              Expected to contain 'attributes' and other nested fields.

    Returns:
        Log: Structured dataclass containing parsed log information.

    Example:
        >>> api_data = {"id": "log-123", "attributes": {"message": "Error occurred", ...}}
        >>> log = parse_log(api_data)
        >>> log.id
        "log-123"
    """
    data = convert_datetime_to_str(data)
    attrs = data.get("attributes", {}) or {}

    # Parse timestamp if available
    timestamp = None
    if attrs.get("timestamp"):
        try:
            timestamp = datetime.fromisoformat(
                attrs.get("timestamp", "").replace("Z", "+00:00")
            )
        except (ValueError, AttributeError):
            # Keep as string if parsing fails
            timestamp = None

    # Extract tags - can be in different formats
    tags = attrs.get("tags", [])
    if isinstance(tags, dict):
        # Convert tag dict to list of "key:value" strings
        tags = [f"{k}:{v}" for k, v in tags.items()]
    elif not isinstance(tags, list):
        tags = []

    return Log(
        id=data.get("id", "log-id"),
        timestamp=timestamp,
        message=attrs.get("message"),
        service=attrs.get("service"),
        host=attrs.get("host"),
        source=attrs.get("source"),
        status=attrs.get("status"),
        tags=tags,
        raw=data,
    )


def security_signals_search_query(args: Dict[str, Any]) -> str:
    """
    Build a Datadog search query string for filtering security signals based on provided arguments.

    Constructs a query using Datadog's search syntax with AND operators between conditions.
    Supports filtering by state, severity, rule name, source, and custom queries.

    Args:
        args (Dict[str, Any]): Dictionary containing search parameters. Supported keys:
            - state (str): Signal state (e.g., "open", "under_review", "archived")
            - severity (str): Severity level (e.g., "low", "medium", "high", "critical")
            - rule_name (str): Name of the security rule
            - source (str): Signal source
            - query (str): Additional custom query string

    Returns:
        str: Formatted query string for Datadog API. Returns "*" if no conditions provided.

    Examples:
        >>> args = {"state": "open", "severity": "high"}
        >>> security_signals_search_query(args)
        "state:open AND severity:high"
    """
    query_parts = []

    if args.get("state"):
        query_parts.append(f"state:{args.get('state')}")

    if args.get("severity"):
        query_parts.append(f"severity:{args.get('severity')}")

    if args.get("rule_name"):
        query_parts.append(f"rule.name:{args.get('rule_name')}")

    if args.get("source"):
        query_parts.append(f"source:{args.get('source')}")

    if args.get("query"):
        query_parts.append(args.get("query"))

    return " AND ".join(query_parts) if query_parts else "*"


def build_logs_search_query(args: Dict[str, Any]) -> str:
    """
    Build a Datadog search query string for filtering logs based on provided arguments.

    Constructs a query using Datadog's search syntax with AND operators between conditions.
    Supports filtering by service, host, source, status, and custom query.

    Args:
        args (Dict[str, Any]): Dictionary containing search parameters. Supported keys:
            - query (str): Custom search query
            - service (str): Service name filter
            - host (str): Host name filter
            - source (str): Log source filter
            - status (str): Log status/level filter (info, warn, error, etc.)

    Returns:
        str: Formatted query string for Datadog Logs API. Returns "*" if no conditions provided.

    Examples:
        >>> args = {"service": "web-api", "status": "error"}
        >>> build_logs_search_query(args)
        "service:web-api AND status:error"

        >>> build_logs_search_query({})
        "*"
    """
    query_parts = []

    if args.get("query"):
        query_parts.append(args.get("query"))

    if args.get("service"):
        query_parts.append(f"service:{args.get('service')}")

    if args.get("host"):
        query_parts.append(f"host:{args.get('host')}")

    if args.get("source"):
        query_parts.append(f"source:{args.get('source')}")

    if args.get("status"):
        query_parts.append(f"status:{args.get('status')}")

    return " AND ".join(query_parts) if query_parts else "*"


def calculate_limit(
    limit: int | None,
    page_size: int | None,
) -> int:
    """
    Calculate the limit for API requests.

    Datadog API uses simple limit-based pagination (page_limit parameter).
    This function normalizes limit/page_size parameters from XSOAR commands.

    Args:
        limit: Maximum number of results to retrieve
        page_size: Number of results per page (alternative to limit)

    Returns:
        int: The calculated limit for the API request

    Raises:
        DemistoException: If page_size is invalid (≤ 0)
    """
    if page_size and page_size <= 0:
        raise DemistoException(PAGE_SIZE_ERROR_MSG)

    # page_size takes precedence over limit if both provided
    if page_size:
        return page_size

    # Use limit or default
    return limit or DEFAULT_PAGE_SIZE


def map_severity_to_xsoar(severity: Optional[str]) -> int:
    """
    Map Datadog signal severity to XSOAR incident severity.

    Args:
        severity: Datadog severity level (info, low, medium, high, critical)

    Returns:
        int: XSOAR severity (0=Unknown, 1=Low, 2=Medium, 3=High, 4=Critical)
    """
    severity_map = {
        "info": 1,  # Low
        "low": 1,  # Low
        "medium": 2,  # Medium
        "high": 3,  # High
        "critical": 4,  # Critical
    }
    return severity_map.get((severity or "").lower(), 0)  # Default to Unknown


""" COMMAND FUNCTIONS """


def fetch_security_signals(
    configuration: Configuration,
    filter_query: str,
    from_datetime: Optional[datetime],
    to_datetime: Optional[datetime],
    limit: int,
    sort: str = "desc",
) -> List[SecuritySignal]:
    """
    Fetch security signals from Datadog API.

    Helper function to retrieve security signals with filtering and sorting.
    Used by both get_security_signals_command and fetch_incidents.

    Args:
        configuration: Datadog API configuration
        filter_query: Query string for filtering signals (Datadog search syntax)
        from_datetime: Start time for signal search
        to_datetime: End time for signal search
        limit: Maximum number of signals to retrieve
        sort: Sort order - "asc" or "desc" (default: "desc")

    Returns:
        List[SecuritySignal]: List of parsed SecuritySignal objects

    Raises:
        DemistoException: If API call fails
    """
    try:
        with ApiClient(configuration) as api_client:
            api_instance = SecurityMonitoringApi(api_client)

            sort_order = (
                SecurityMonitoringSignalsSort.TIMESTAMP_DESCENDING
                if sort == "desc"
                else SecurityMonitoringSignalsSort.TIMESTAMP_ASCENDING
            )

            signal_list_response = api_instance.list_security_monitoring_signals(
                filter_query=filter_query if filter_query != "*" else unset,
                filter_from=from_datetime or unset,
                filter_to=to_datetime or unset,
                sort=sort_order,
                page_limit=limit,
            )

            results = signal_list_response.to_dict()
            data_list = results.get("data", [])

            # Parse all signals
            signals = []
            for signal_data in data_list:
                signal = parse_security_signal(signal_data)
                signals.append(signal)

            return signals

    except Exception as e:
        raise DemistoException(f"Failed to fetch security signals: {str(e)}")


def module_test(configuration: Configuration) -> str:
    """Tests API connectivity and authentication'

    Returning 'ok' indicates that the integration works like it is supposed to.
    Connection to the service is successful.
    Raises exceptions if something goes wrong.

    :return: 'ok' if test passed, anything else will fail the test.
    :rtype: ``str``
    """
    with ApiClient(configuration) as api_client:
        # Testing api key
        try:
            api_instance = AuthenticationApi(api_client)
            api_instance.validate()
        except Exception:
            return AUTHENTICATION_ERROR_MSG
        return "ok"


def get_security_signal_command(
    configuration: Configuration,
    args: dict[str, Any],
) -> CommandResults:
    """
    Get a specific security signal by ID.

    Args:
        configuration: Datadog API configuration
        args: Command arguments containing signal_id

    Returns:
        CommandResults: XSOAR command results with signal data

    Raises:
        DemistoException: If signal_id is not provided or API call fails
    """
    signal_id = args.get("signal_id")

    if not signal_id:
        raise DemistoException(
            "Signal ID is required. Please provide signal_id parameter."
        )

    try:
        with ApiClient(configuration) as api_client:
            api_instance = SecurityMonitoringApi(api_client)
            signal_response = api_instance.get_security_monitoring_signal(
                signal_id=signal_id
            )
            results = signal_response.to_dict()
            data = results.get("data", {})

            if not data:
                readable_output = f"No security signal found with ID: {signal_id}"
                return CommandResults(
                    readable_output=readable_output,
                    outputs_prefix=SECURITY_SIGNAL_CONTEXT_NAME,
                    outputs_key_field="id",
                    outputs={},
                )

            signal = parse_security_signal(data)

            # Extract IOCs from the signal for standard XSOAR context
            indicators = extract_iocs_from_signal(signal)

            # Create human-readable summary using the display dictionary
            signal_display = signal.to_display_dict()

            # Add IOC summary to readable output if found
            ioc_summary = ""
            if indicators:
                ioc_counts = {}
                for indicator in indicators:
                    ioc_type = type(indicator).__name__.replace("Common", "")
                    ioc_counts[ioc_type] = ioc_counts.get(ioc_type, 0) + 1

                ioc_summary = "\n\n**IOCs Extracted:** " + ", ".join(
                    [f"{count} {ioc_type}" for ioc_type, count in ioc_counts.items()]
                )

            readable_output = (
                lookup_to_markdown([signal_display], "Security Signal Details")
                + ioc_summary
            )

            return CommandResults(
                readable_output=readable_output,
                outputs_prefix=SECURITY_SIGNAL_CONTEXT_NAME,
                outputs_key_field="id",
                outputs=signal.to_dict(),
                indicators=indicators,  # This populates standard XSOAR contexts (IP, Domain, URL, File, etc.)
            )

    except Exception as e:
        raise DemistoException(f"Failed to get security signal {signal_id}: {str(e)}")


def get_security_signals_command(
    configuration: Configuration,
    args: Dict[str, Any],
) -> CommandResults:
    """
    Get a list of security signals with optional filtering.

    Supports filtering by state, severity, rule name, source, and time range.
    Returns paginated results with configurable sorting.

    Args:
        configuration: Datadog API configuration
        args: Command arguments containing optional filters and pagination parameters

    Returns:
        CommandResults: XSOAR command results with list of security signals

    Raises:
        DemistoException: If API call fails or invalid arguments provided
    """
    try:
        page_size = arg_to_number(args.get("page_size"), arg_name="page_size")
        limit = arg_to_number(args.get("limit"), arg_name="limit")
        limit = calculate_limit(limit, page_size)

        sort = args.get("sort", "desc")
        if sort not in ["asc", "desc"]:
            raise DemistoException("Sort must be either 'asc' or 'desc'")

        filter_query = security_signals_search_query(args)

        from_date = args.get("from_date", DEFAULT_FROM_DATE)
        to_date = args.get("to_date", DEFAULT_TO_DATE)

        try:
            from_datetime = parse(from_date, settings={"TIMEZONE": "UTC"})
            to_datetime = parse(to_date, settings={"TIMEZONE": "UTC"})
        except Exception as e:
            raise DemistoException(
                f"Invalid date format. Use formats like '7 days ago', '2023-01-01T00:00:00Z': {str(e)}"
            )

        # Use helper function to fetch signals
        signals_objs = fetch_security_signals(
            configuration=configuration,
            filter_query=filter_query,
            from_datetime=from_datetime,
            to_datetime=to_datetime,
            limit=limit,
            sort=sort,
        )

        if not signals_objs:
            readable_output = (
                "No security signals found matching the specified criteria."
            )
            return CommandResults(
                readable_output=readable_output,
                outputs_prefix=SECURITY_SIGNAL_CONTEXT_NAME,
                outputs_key_field="id",
                outputs=[],
            )

        # Process signals for output
        signals = []
        display_data = []
        all_indicators = []

        for signal in signals_objs:
            signals.append(signal.to_dict())
            display_data.append(signal.to_display_dict())

            # Extract IOCs from each signal
            signal_indicators = extract_iocs_from_signal(signal)
            all_indicators.extend(signal_indicators)

        # Create summary of all IOCs found across signals
        ioc_summary = ""
        if all_indicators:
            ioc_counts = {}
            for indicator in all_indicators:
                ioc_type = type(indicator).__name__.replace("Common", "")
                ioc_counts[ioc_type] = ioc_counts.get(ioc_type, 0) + 1

            ioc_summary = "\n\n**IOCs Extracted:** " + ", ".join(
                [f"{count} {ioc_type}" for ioc_type, count in ioc_counts.items()]
            )

        # Create human-readable output
        readable_output = (
            lookup_to_markdown(
                display_data, f"Security Signals ({len(signals)} results)"
            )
            + ioc_summary
        )

        return CommandResults(
            readable_output=readable_output,
            outputs_prefix=SECURITY_SIGNAL_CONTEXT_NAME,
            outputs_key_field="id",
            outputs=signals,
            indicators=all_indicators,  # This populates standard XSOAR contexts from all signals
        )

    except Exception as e:
        raise DemistoException(f"Failed to get security signals: {str(e)}")


def update_security_signal_assignee_command(
    configuration: Configuration,
    args: Dict[str, Any],
) -> CommandResults:
    """
    Update the assignee of a security signal.

    Assigns a security signal to a specific user by providing their UUID.
    The signal must exist and the user must have appropriate permissions.

    Args:
        configuration: Datadog API configuration
        args: Command arguments containing signal_id and assignee_uuid

    Returns:
        CommandResults: XSOAR command results with updated signal data

    Raises:
        DemistoException: If signal_id is missing or API call fails
    """
    signal_id = args.get("signal_id")
    assignee_uuid = args.get("assignee_uuid", "")  # unassign when ""

    if not signal_id:
        raise DemistoException("signal_id is required")

    body = SecurityMonitoringSignalAssigneeUpdateRequest(
        data=SecurityMonitoringSignalAssigneeUpdateData(
            attributes=SecurityMonitoringSignalAssigneeUpdateAttributes(
                assignee=SecurityMonitoringTriageUser(uuid=assignee_uuid),
            ),
        ),
    )

    with ApiClient(configuration) as api_client:
        api_instance = SecurityMonitoringApi(api_client)
        response = api_instance.edit_security_monitoring_signal_assignee(
            signal_id=str(signal_id), body=body
        )
        data = response.to_dict()
        attributes = data.get("attributes", {})
        assignee = Assignee(
            id=attributes.get("assignee", {}).get("id", -1),
            uuid=attributes.get("assignee", {}).get("uuid", ""),
            name=attributes.get("assignee", {}).get("name", "Unassigned"),
        )
        state = attributes.get("state", "")
        comment = attributes.get("archive_comment", "")
        reason = attributes.get("archive_reason", "")

        signal_update = SecuritySignal(
            id=signal_id,
            triage=Triage(
                state=state,
                comment=comment,
                reason=reason,
                assignee=assignee,
            ),
        )
        signal_display = signal_update.to_display_dict()
        readable_output = lookup_to_markdown(
            [signal_display], f"Security Signals assignee update"
        )

        return CommandResults(
            readable_output=readable_output,
            outputs_prefix=SECURITY_SIGNAL_CONTEXT_NAME,
            outputs_key_field="id",
            outputs=signal_update.to_dict(),
        )


def update_security_signal_state_command(
    configuration: Configuration,
    args: dict[str, Any],
) -> CommandResults:
    """
    Update the state of a security signal.

    Changes the triage state of a security signal (e.g., open, under_review, archived).
    The signal must exist and the user must have appropriate permissions.

    Args:
        configuration: Datadog API configuration
        args: A dictionary of arguments for the command.
            - signal_id (str): The ID of the signal to update
            - state (str): The new state for the signal (open, under_review, resolved, etc.)
            - reason (str): Reason for the state change
            - comment (str): Comment about the state change

    Returns:
        CommandResults: XSOAR command results with updated signal data

    Raises:
        DemistoException: If signal_id or state is missing, or API call fails
    """
    signal_id = args.get("signal_id")
    state = args.get("state")
    reason = args.get("reason")
    comment = args.get("comment")

    if not signal_id:
        raise DemistoException("signal_id is required")

    if not state:
        raise DemistoException("state is required")

    # Valid states based on Datadog API documentation
    valid_states = ["open", "under_review", "archived"]
    if state not in valid_states:
        raise DemistoException(
            f"Invalid state '{state}'. Valid states are: {', '.join(valid_states)}"
        )

    body = SecurityMonitoringSignalStateUpdateRequest(
        data=SecurityMonitoringSignalStateUpdateData(
            attributes=SecurityMonitoringSignalStateUpdateAttributes(
                state=state,
                reason=reason,
                comment=comment,
            ),
        ),
    )

    with ApiClient(configuration) as api_client:
        api_instance = SecurityMonitoringApi(api_client)
        response = api_instance.edit_security_monitoring_signal_state(
            signal_id=str(signal_id), body=body
        )
        data = response.to_dict()
        attributes = data.get("attributes", {})
        assignee = Assignee(
            id=attributes.get("assignee", {}).get("id", -1),
            uuid=attributes.get("assignee", {}).get("uuid", ""),
            name=attributes.get("assignee", {}).get("name", "Unassigned"),
        )
        updated_state = attributes.get("state", "")
        comment = attributes.get("archive_comment", "")
        reason = attributes.get("archive_reason", "")

        signal_update = SecuritySignal(
            id=signal_id,
            triage=Triage(
                state=updated_state,
                comment=comment,
                reason=reason,
                assignee=assignee,
            ),
        )
        signal_display = signal_update.to_display_dict()
        readable_output = lookup_to_markdown(
            [signal_display], f"Security Signal State Update"
        )

        return CommandResults(
            readable_output=readable_output,
            outputs_prefix=SECURITY_SIGNAL_CONTEXT_NAME,
            outputs_key_field="id",
            outputs=signal_update.to_dict(),
        )


def logs_search_command(
    configuration: Configuration,
    args: Dict[str, Any],
) -> CommandResults:
    """
    Search for logs in Datadog Cloud SIEM with optional filtering.

    Supports filtering by service, host, source, status, and time range.
    Returns paginated results with configurable sorting for security investigations.

    Args:
        configuration: Datadog API configuration
        args: Command arguments containing optional filters and pagination parameters

    Returns:
        CommandResults: XSOAR command results with list of logs

    Raises:
        DemistoException: If API call fails or invalid arguments provided
    """
    try:
        page_size = arg_to_number(args.get("page_size"), arg_name="page_size")
        limit = arg_to_number(args.get("limit"), arg_name="limit")
        limit = calculate_limit(limit, page_size)

        sort = args.get("sort", "desc")
        if sort not in ["asc", "desc"]:
            raise DemistoException("Sort must be either 'asc' or 'desc'")

        sort_order = (
            LogsSort.TIMESTAMP_ASCENDING
            if sort == "asc"
            else LogsSort.TIMESTAMP_DESCENDING
        )

        search_query = build_logs_search_query(args)

        # Parse date range
        from_date = args.get("from_date", DEFAULT_FROM_DATE)
        to_date = args.get("to_date", DEFAULT_TO_DATE)

        try:
            from_datetime = parse(from_date, settings={"TIMEZONE": "UTC"})
            to_datetime = parse(to_date, settings={"TIMEZONE": "UTC"})
        except Exception as e:
            raise DemistoException(
                f"Invalid date format. Use formats like '7 days ago', '2023-01-01T00:00:00Z': {str(e)}"
            )

        with ApiClient(configuration) as api_client:
            api_instance = LogsApi(api_client)

            # Build request body
            body = LogsListRequest(
                filter=LogsQueryFilter(
                    query=search_query,
                    _from=from_datetime.isoformat() if from_datetime else unset,
                    to=to_datetime.isoformat() if to_datetime else unset,
                ),
                page=LogsListRequestPage(limit=limit),
                sort=sort_order,
            )

            # Execute search
            response = api_instance.list_logs(body=body)
            results = response.to_dict()
            data_list = results.get("data", [])

            if not data_list:
                readable_output = "No logs found matching the specified criteria."
                return CommandResults(
                    readable_output=readable_output,
                    outputs_prefix=f"{INTEGRATION_CONTEXT_NAME}.Log",
                    outputs_key_field="id",
                    outputs=[],
                )

            # Process logs using Log dataclass
            logs = []
            display_data = []

            for log_data in data_list:
                log = parse_log(log_data)
                logs.append(log.to_dict())
                display_data.append(log.to_display_dict())

            # Create human-readable output
            readable_output = lookup_to_markdown(
                display_data, f"Security Logs ({len(logs)} results)"
            )

            return CommandResults(
                readable_output=readable_output,
                outputs_prefix=f"{INTEGRATION_CONTEXT_NAME}.Log",
                outputs_key_field="id",
                outputs=logs,
            )

    except Exception as e:
        raise DemistoException(f"Failed to search logs: {str(e)}")


def fetch_incidents(configuration: Configuration, params: dict) -> None:
    """
    Fetch security signals from Datadog Cloud SIEM and create XSOAR incidents.

    Retrieves new security signals since the last fetch and converts them to XSOAR incidents.
    Supports incremental fetch using last_run timestamp and configurable filters.

    Args:
        configuration: Datadog API configuration
        params: Integration parameters from XSOAR configuration
            - first_fetch: Time range for initial fetch (e.g., "3 days", "7 days")
            - max_fetch: Maximum number of incidents to fetch per cycle (default: 50)
            - fetch_severity: Comma-separated list of severities to fetch (e.g., "high,critical")
            - fetch_state: Signal state to fetch (default: "open")
            - fetch_query: Additional custom query filter

    Returns:
        None. Creates incidents via demisto.incidents() and updates last_run via demisto.setLastRun()
    """
    try:
        # Get integration parameters
        first_fetch = params.get("first_fetch", "3 days")
        max_fetch = int(params.get("max_fetch", 50))
        fetch_severity = params.get("fetch_severity", "")
        fetch_state = params.get("fetch_state", "open")
        fetch_query = params.get("fetch_query", "")

        # Get last run to handle incremental fetch
        last_run = demisto.getLastRun()
        last_fetch_time = last_run.get("last_fetch_time")

        # Calculate fetch time range
        if last_fetch_time:
            # Incremental fetch - get signals since last fetch
            from_datetime = parse(last_fetch_time, settings={"TIMEZONE": "UTC"})
            demisto.debug(f"Fetching incidents since last run: {last_fetch_time}")
        else:
            # First fetch - use first_fetch parameter
            from_datetime = parse(f"-{first_fetch}", settings={"TIMEZONE": "UTC"})
            demisto.debug(f"First fetch - fetching incidents from: {first_fetch} ago")

        to_datetime = datetime.now(timezone.utc)

        # Build filter query
        filter_args = {
            "state": fetch_state,
            "query": fetch_query,
        }
        if fetch_severity:
            # If multiple severities, build OR query
            severities = [s.strip() for s in fetch_severity.split(",")]
            if len(severities) == 1:
                filter_args["severity"] = severities[0]
            else:
                # Build custom severity query
                severity_query = " OR ".join([f"severity:{s}" for s in severities])
                filter_args["query"] = f"({severity_query})" + (
                    f" AND {fetch_query}" if fetch_query else ""
                )

        filter_query = security_signals_search_query(filter_args)

        # Fetch security signals
        demisto.debug(f"Fetching signals with query: {filter_query}")
        signals = fetch_security_signals(
            configuration=configuration,
            filter_query=filter_query,
            from_datetime=from_datetime,
            to_datetime=to_datetime,
            limit=max_fetch,
            sort="asc",  # Oldest first for chronological incident creation
        )

        demisto.debug(f"Fetched {len(signals)} security signals")

        # Convert signals to XSOAR incidents
        incidents = []
        latest_signal_time = last_fetch_time

        for signal in signals:
            # Create incident from signal
            # Note: IOCs are embedded in signal.raw and can be extracted via
            # datadog-security-signal-get command or playbooks
            incident = {
                "name": signal.title or f"Datadog Security Signal {signal.id}",
                "occurred": (
                    str(signal.timestamp)
                    if signal.timestamp
                    else to_datetime.isoformat()
                ),
                "severity": map_severity_to_xsoar(signal.severity),
                "dbotMirrorId": signal.id,
                "rawJSON": json.dumps(signal.to_dict()),
            }

            incidents.append(incident)

            # Track latest signal timestamp for next fetch
            if signal.timestamp:
                signal_time = str(signal.timestamp)
                if not latest_signal_time or signal_time > latest_signal_time:
                    latest_signal_time = signal_time

        demisto.debug(f"Created {len(incidents)} incidents")

        # Update last run with latest timestamp
        if incidents and latest_signal_time:
            demisto.setLastRun({"last_fetch_time": latest_signal_time})
            demisto.debug(f"Updated last_fetch_time to: {latest_signal_time}")
        elif not last_fetch_time:
            # First run with no incidents - still save the from_datetime
            demisto.setLastRun({"last_fetch_time": from_datetime.isoformat()})  # type: ignore

        # Send incidents to XSOAR
        demisto.incidents(incidents)

    except Exception as e:
        demisto.error(f"Error in fetch_incidents: {str(e)}")
        raise DemistoException(f"Failed to fetch incidents: {str(e)}")


""" MAIN FUNCTION """


def main() -> None:
    command: str = demisto.command()
    params: dict[str, Any] = demisto.params()
    args: dict[str, Any] = demisto.args()
    demisto.debug(f"Command being called is {command}")
    try:
        configuration = Configuration()
        configuration.api_key["apiKeyAuth"] = params.get("api_key")
        configuration.api_key["appKeyAuth"] = params.get("app_key")
        configuration.server_variables["site"] = params.get("site")

        commands = {
            "datadog-security-signal-get": get_security_signal_command,
            "datadog-security-signals-list": get_security_signals_command,
            "datadog-security-signal-assignee-update": update_security_signal_assignee_command,
            "datadog-security-signal-state-update": update_security_signal_state_command,
            "datadog-logs-search": logs_search_command,
        }
        if command == "test-module":
            return_results(module_test(configuration))
        elif command == "fetch-incidents":
            fetch_incidents(configuration, params)
        elif command in commands:
            return_results(commands[command](configuration, args))
        else:
            raise NotImplementedError
    except (ForbiddenException, UnauthorizedException, Exception) as e:
        error = None
        if type(e) in (ForbiddenException, UnauthorizedException):
            error = AUTHENTICATION_ERROR_MSG
        return_error(error or f"Failed to execute {command} command. Error: {e!s}")


""" ENTRY POINT """

if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
