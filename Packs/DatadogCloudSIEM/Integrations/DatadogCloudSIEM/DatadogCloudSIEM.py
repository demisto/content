from dataclasses import dataclass
from datetime import datetime
from typing import Any

from CommonServerPython import *  # noqa: F401 # pylint: disable=unused-wildcard-import
from datadog_api_client import ApiClient, Configuration
from datadog_api_client.exceptions import ForbiddenException, UnauthorizedException
from datadog_api_client.model_utils import unset
from datadog_api_client.v1.api.authentication_api import AuthenticationApi
from datadog_api_client.v2.api.logs_api import LogsApi
from datadog_api_client.v2.api.security_monitoring_api import SecurityMonitoringApi
from datadog_api_client.v2.api.users_api import UsersApi
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
from datadog_api_client.v2.model.security_monitoring_signal_list_request import (
    SecurityMonitoringSignalListRequest,
)
from datadog_api_client.v2.model.security_monitoring_signal_list_request_filter import (
    SecurityMonitoringSignalListRequestFilter,
)
from datadog_api_client.v2.model.security_monitoring_signal_list_request_page import (
    SecurityMonitoringSignalListRequestPage,
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
from datadog_api_client.v2.model.security_monitoring_suppression_create_attributes import (
    SecurityMonitoringSuppressionCreateAttributes,
)
from datadog_api_client.v2.model.security_monitoring_suppression_create_data import (
    SecurityMonitoringSuppressionCreateData,
)
from datadog_api_client.v2.model.security_monitoring_suppression_create_request import (
    SecurityMonitoringSuppressionCreateRequest,
)
from datadog_api_client.v2.model.security_monitoring_suppression_type import (
    SecurityMonitoringSuppressionType,
)
from datadog_api_client.v2.model.security_monitoring_suppression_update_attributes import (
    SecurityMonitoringSuppressionUpdateAttributes,
)
from datadog_api_client.v2.model.security_monitoring_suppression_update_data import (
    SecurityMonitoringSuppressionUpdateData,
)
from datadog_api_client.v2.model.security_monitoring_suppression_update_request import (
    SecurityMonitoringSuppressionUpdateRequest,
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

SITE = "datadoghq.com"
DEFAULT_PAGE_SIZE = 50
PAGE_SIZE_ERROR_MSG = "Invalid Input Error: page size should be greater than zero."
DEFAULT_FROM_DATE = "-7days"
DEFAULT_TO_DATE = "now"
INTEGRATION_NAME = "DatadogCloudSIEM"
INTEGRATION_CONTEXT_NAME = "Datadog"
SECURITY_SIGNAL_CONTEXT_NAME = f"{INTEGRATION_CONTEXT_NAME}.SecuritySignal"
SECURITY_RULE_CONTEXT_NAME = f"{INTEGRATION_CONTEXT_NAME}.SecurityRule"
SECURITY_COMMENT_CONTEXT_NAME = f"{INTEGRATION_CONTEXT_NAME}.SecurityComment"
LOG_CONTEXT_NAME = f"{INTEGRATION_CONTEXT_NAME}.Log"
NO_RESULTS_FROM_API_MSG = "API didn't return any results for given search parameters."
ERROR_MSG = "Something went wrong!\n"
AUTHENTICATION_ERROR_MSG = "Authentication Error: Invalid API Key. Make sure API Key and Server URL are correct."


""" DATACLASSES """


@dataclass
class Assignee:
    name: str
    handle: str


@dataclass
class Triage:
    state: str
    archive_comment: str
    archive_reason: str
    assignee: Assignee | None = None


@dataclass
class Comment:
    id: str
    created_at: str
    user_uuid: str
    text: str
    user_name: str | None = None
    user_handle: str | None = None

    def to_display_dict(self) -> dict[str, Any]:
        """
        Convert a Comment to a dictionary optimized for human-readable display.

        Returns:
            Dict[str, Any]: Dictionary with display-friendly field names and values.
        """
        return {
            "Created At": self.created_at,
            "User": f"{self.user_name} <{self.user_handle}>" or self.user_uuid,
            "Text": self.text,
        }

    def to_dict(self) -> dict[str, Any]:
        """
        Convert a Comment to a plain dictionary for XSOAR context output.

        Returns:
            Dict[str, Any]: Dictionary for context output.
        """
        result = {
            "id": self.id,
            "created_at": self.created_at,
            "user_uuid": self.user_uuid,
            "text": self.text,
        }

        if self.user_name or self.user_handle:
            result["user"] = {  # type: ignore
                "name": self.user_name,
                "handle": self.user_handle,
            }

        return remove_none_values(result)


@dataclass
class SecurityRule:
    id: str
    name: str
    type: str
    is_enabled: bool
    created_at: str | None = None
    message: str | None = None
    queries: list[dict[str, Any]] | None = None
    cases: list[dict[str, Any]] | None = None
    options: dict[str, Any] | None = None
    tags: list[str] | None = None

    # Raw rule data
    raw: dict[str, Any] | None = None

    def build_url(self) -> str:
        """
        Construct the Datadog Cloud SIEM URL for this security rule.

        Returns:
            str: Full URL to view the rule in the Datadog UI
        """
        return f"https://app.{SITE}/security/rules/view/{self.id}"

    def extract_query(self) -> str:
        """
        Extract this rule's log queries and combine them using the OR operator.

        Returns:
            str: Combined query string using OR, or "*" if no queries found

        Example:
            >>> rule = SecurityRule(id="123", queries=[{"query": "source:nginx"}, {"query": "source:apache"}])
            >>> rule.extract_query()
            "(source:nginx) OR (source:apache)"
        """
        if not self.queries or len(self.queries) == 0:
            return "*"

        # Extract all query strings, filtering out None/empty values
        query_strings = []
        for query_obj in self.queries:
            query_str = query_obj.get("query")
            if query_str:
                query_strings.append(query_str)

        if not query_strings:
            return "*"

        # If only one query, return it directly
        if len(query_strings) == 1:
            return query_strings[0]

        # Combine multiple queries with OR
        combined = " OR ".join(f"({q})" for q in query_strings)
        return combined

    def to_display_dict(self) -> dict[str, Any]:
        """
        Convert a SecurityRule to a dictionary optimized for human-readable display.

        Returns:
            Dict[str, Any]: Dictionary with display-friendly field names and values.
        """
        return {
            "Name": self.name,
            "Type": self.type,
            "Is Enabled": self.is_enabled,
            "Created At": self.created_at,
            "Tags": (", ".join(self.tags[:5]) + ("..." if len(self.tags) > 5 else "") if self.tags else None),
            "URL": self.build_url(),
        }

    def to_dict(self) -> dict[str, Any]:
        """
        Convert a SecurityRule to a plain dictionary for XSOAR context output.

        Returns:
            Dict[str, Any]: Dictionary for context output.
        """
        result = {
            "id": self.id,
            "name": self.name,
            "type": self.type,
            "isEnabled": self.is_enabled,
            "createdAt": self.created_at,
            "message": self.message,
            "queries": self.queries,
            "cases": self.cases,
            "options": self.options,
            "tags": self.tags,
            "url": self.build_url(),
            "raw": self.raw,
        }

        return remove_none_values(result)


@dataclass
class Log:
    id: str
    timestamp: datetime | None = None
    message: str | None = None
    service: str | None = None
    host: str | None = None
    source: str | None = None
    status: str | None = None
    tags: list[str] | None = None

    # Raw log data
    raw: dict[str, Any] | None = None

    def build_url(self) -> str:
        """
        Construct the Datadog Cloud URL for this log.

        Returns:
            str: Full URL to view the log in the Datadog UI
        """
        return f"https://app.{SITE}/logs?event={self.id}"

    def to_display_dict(self) -> dict[str, Any]:
        """
        Convert Log to a dictionary optimized for human-readable display.

        Excludes the raw field and formats content appropriately for markdown tables.
        Truncates long messages and limits tag display for readability.

        Returns:
            Dict[str, Any]: Dictionary with display-friendly field names and values.
        """
        return {
            "Timestamp": str(self.timestamp) if self.timestamp else None,
            "Message": (self.message[:100] + "..." if self.message and len(self.message) > 100 else self.message),
            "Service": self.service,
            "Host": self.host,
            "Source": self.source,
            "Status": self.status,
            "Tags": (", ".join(self.tags[:3]) + ("..." if len(self.tags) > 3 else "") if self.tags else None),
            "URL": self.build_url(),
        }

    def to_dict(self) -> dict[str, Any]:
        """
        Convert Log to a plain dictionary for XSOAR context output.

        Converts nested objects to dictionaries and serializes datetime objects.
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
            "url": self.build_url(),
            "raw": self.raw,
        }

        # Remove None values recursively
        return remove_none_values(result)


@dataclass
class SecuritySignal:
    id: str
    event_id: str
    timestamp: datetime | None = None
    host: str | None = None
    service: str | None = None
    severity: str | None = None
    title: str | None = None
    message: str | None = None
    rule_id: str | None = None
    triage: Triage | None = None
    tags: list[str] | None = None
    triggering_log_id: str | None = None

    # Raw signal
    raw: dict[str, Any] | None = None

    def build_url(self) -> str:
        """
        Construct the Datadog Cloud SIEM URL for this security signal.

        Returns:
            str: Full URL to view the signal in Datadog UI
        """
        return f"https://app.{SITE}/security/signal?event={self.id}"

    def to_display_dict(self) -> dict[str, Any]:
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
            "Rule URL": (SecurityRule(id=self.rule_id, name="", type="", is_enabled=False).build_url() if self.rule_id else None),
            "Host": self.host,
            "Services": self.service,
            "Timestamp": str(self.timestamp) if self.timestamp else None,
            "Assignee": (self.triage.assignee.name if (self.triage and self.triage.assignee) else None),
            "Tags": (", ".join(self.tags[:5]) + ("..." if len(self.tags) > 5 else "") if self.tags else None),
            "URL": self.build_url(),
        }
        return remove_none_values(result)

    def to_dict(self) -> dict[str, Any]:
        """
        Convert SecuritySignal to a plain dictionary for XSOAR context output.

        Converts nested dataclass objects to dictionaries and serializes datetime objects.
        Excludes None values to prevent overriding existing fields during partial updates.

        Returns:
            Dict[str, Any]: Dictionary with snake_case field names matching YAML contextPath.
                           Only includes fields with non-None values.
        """
        result = {
            "id": self.id,
            "event_id": self.event_id,
            "timestamp": str(self.timestamp) if self.timestamp else None,
            "host": self.host,
            "service": self.service,
            "severity": self.severity,
            "title": self.title,
            "message": self.message,
            "tags": self.tags,
            "triggering_log_id": self.triggering_log_id,
            "url": self.build_url(),
            "raw": self.raw,
        }

        # Convert rule to dict if present
        if self.rule_id:
            result["rule"] = {
                "id": self.rule_id,
                "url": SecurityRule(id=self.rule_id, name="", type="", is_enabled=False).build_url(),
            }

        # Convert triage to dict if present
        if self.triage:
            result["triage"] = {
                "state": self.triage.state,
                "archive_comment": self.triage.archive_comment,
                "archive_reason": self.triage.archive_reason,
            }
            # Convert assignee to dict if present
            if self.triage.assignee:
                result["triage"]["assignee"] = {  # type: ignore
                    "name": self.triage.assignee.name,
                    "handle": self.triage.assignee.handle,
                }

        # Remove None values recursively
        return remove_none_values(result)


""" HELPER FUNCTIONS """


def remove_none_values(data: dict[str, Any]) -> dict[str, Any]:
    """
    Recursively remove keys with None values from a dictionary.

    Args:
        data (Dict[str, Any]): Dictionary that may contain None values

    Returns:
        Dict[str, Any]: New dictionary with None values removed recursively
    """
    if not isinstance(data, dict):
        return data

    result: dict[str, Any] = {}
    for key, value in data.items():
        if value is None:
            continue
        elif isinstance(value, dict):
            cleaned_dict = remove_none_values(value)
            if cleaned_dict:  # Only add if the cleaned dict is not empty
                result[key] = cleaned_dict
        elif isinstance(value, list):
            # Handle lists by removing None values and recursively cleaning dict items
            cleaned_list: list[Any] = []
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
    Converts datetime objects found in the input dictionary to ISO-formatted strings.

    Args:
        data (Dict): The input dictionary to be converted.

    Returns:
        Dict: A new dictionary with the same structure as the input dictionary, but with all datetime objects
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


def as_list(v: Any) -> list[Any]:
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


def flatten_tag_map(tag_map: dict[str, Any]) -> list[str]:
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
    flat: list[str] = []
    for k, v in (tag_map or {}).items():
        if isinstance(v, list):
            flat.extend([f"{k}:{str(item)}" for item in v])
        else:
            flat.append(f"{k}:{str(v)}")
    return flat


def parse_security_comment(data: dict[str, Any]) -> Comment:
    """
    Parse raw comment data from Datadog API into a structured Comment object.

    Args:
        data: Raw comment data from Datadog API response containing 'id' and 'attributes'

    Returns:
        Comment: Structured dataclass containing parsed comment information

    Example:
        >>> data = {
        ...     'id': '123',
        ...     'attributes': {'comment_id': '123', 'created_at': '2025-10-07', 'text': 'test', 'user_uuid': 'abc'}
        ... }
        >>> comment = parse_security_comment(data)
        >>> comment.text
        'test'
    """
    attrs = data.get("attributes", {})

    return Comment(
        id=data.get("id", "") or attrs.get("comment_id", ""),
        created_at=attrs.get("created_at", ""),
        user_uuid=attrs.get("user_uuid", ""),
        text=attrs.get("text", ""),
    )


def parse_security_signal(data: dict[str, Any]) -> SecuritySignal:
    """
    Parse raw security signal data from the Datadog API and convert it into a structured SecuritySignal object.

    Extracts and organizes key fields from the nested API response structure, handles
    optional fields gracefully and flattens complex nested data.

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
    attrs = {
        # list endpoint returns workflow data in attributes.attributes.workflow
        **data.get("attributes", {}).get("attributes", {}),
        **data.get("attributes", {}),
    }

    signal_id = data.get("id")
    event_id = data.get("event_id") or attrs.get("event_id") or attrs.get("id")

    if not signal_id or not event_id:
        raise ValueError("Cannot get signal_id and/or event_id")

    custom = {
        **data.get("custom", {}),
        **attrs.get("custom", {}),
    }
    workflow = {
        **data.get("workflow", {}),
        **attrs.get("workflow", {}),
        **custom.get("workflow", {}),
    }
    rule_d = workflow.get("rule", {})
    triage_d = workflow.get("triage", {})
    assignee_d = triage_d.get("assignee", {})
    triage = (
        Triage(
            state=triage_d.get("state", ""),
            archive_reason=triage_d.get("archiveReason", ""),
            archive_comment=triage_d.get("archiveComment", ""),
            assignee=(
                Assignee(
                    name=assignee_d.get("name", "Unassigned"),
                    handle=assignee_d.get("handle", ""),
                )
                if assignee_d
                else None
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
    service_str = ", ".join(services) if services else None

    return SecuritySignal(
        id=signal_id,
        event_id=event_id,
        timestamp=attrs.get("timestamp"),
        host=attrs.get("host"),
        service=service_str,
        severity=attrs.get("status", "info"),
        title=custom.get("title") or attrs.get("title") or rule_d.get("name"),
        message=attrs.get("message"),
        rule_id=rule_d.get("id", ""),
        triage=triage,
        tags=tags,
        triggering_log_id=attrs.get("triggering_log_id"),
        raw=data,
    )


def parse_security_rule(data: dict[str, Any]) -> SecurityRule:
    """
    Parse raw security rule data from the Datadog API into a structured SecurityRule object.

    Args:
        data (Dict[str, Any]): Raw security rule data from the Datadog API response.

    Returns:
        SecurityRule: Structured dataclass containing parsed rule information.

    Example:
        >>> api_data = {"id": "rule-123", "name": "My Rule", ...}
        >>> rule = parse_security_rule(api_data)
        >>> rule.id
        "rule-123"
    """
    return SecurityRule(
        id=data.get("id", ""),
        name=data.get("name", ""),
        type=data.get("type", ""),
        is_enabled=data.get("isEnabled", False),
        created_at=data.get("createdAt"),
        message=data.get("message"),
        queries=data.get("queries"),
        cases=data.get("cases"),
        options=data.get("options"),
        tags=as_list(data.get("tags")),
        raw=data,
    )


def parse_log(data: dict[str, Any]) -> Log:
    """
    Parse raw log data from the Datadog API into a structured Log object.

    Extracts and organizes key fields from the nested API response structure, handling
    optional fields gracefully and converting timestamps to datetime objects.

    Args:
        data (Dict[str, Any]): Raw log data from the Datadog API response.
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
            timestamp = datetime.fromisoformat(attrs.get("timestamp", "").replace("Z", "+00:00"))
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


def security_signals_search_query(args: dict[str, Any]) -> str:
    """
    Builds a Datadog search query string to filter security signals based on the provided arguments.

    Constructs a query using Datadog's search syntax, combining conditions with AND operators.
    Supports filtering by state, severity, rule name, source, and custom queries.

    Args:
        args (Dict[str, Any]): Dictionary containing search parameters. Supported keys:
            - state (str): Signal state (e.g., "open", "under_review", "archived")
            - severity (str): Severity level (e.g., "low", "medium", "high", "critical")
            - source (str): Signal source
            - query (str): Additional custom query string

    Returns:
       str: Formatted Datadog API query string. Returns "*" if no conditions are provided.

    Examples:
        >>> args = {"state": "open", "severity": "high"}
        >>> security_signals_search_query(args)
        "state:open AND severity:high"
    """
    query_parts: list[str] = [
        # This is required to return only Cloud SIEM signals
        '@workflow.rule.type:("Log Detection" OR "Signal Correlation")'
    ]

    if args.get("state"):
        query_parts.append(f"@workflow.triage.state:{args.get('state')}")

    if args.get("severity"):
        # Fetch given an higher severity: low > info > medium > high > critical
        severity_levels = ["info", "low", "medium", "high", "critical"]
        sev = args.get("severity", "medium").lower()
        if sev in severity_levels:
            idx = severity_levels.index(sev)
            higher_or_equal = severity_levels[idx:]
            query_parts.append(f"status:({' OR '.join(higher_or_equal)})")

    if args.get("source"):
        query_parts.append(f"source:{args.get('source')}")

    query = args.get("query")
    if query:
        query_parts.append(str(query))

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


def map_severity_to_xsoar(severity: str | None) -> int:
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
    from_datetime: datetime | None,
    to_datetime: datetime | None,
    limit: int,
    sort: str = "desc",
) -> list[SecuritySignal]:
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

            body = SecurityMonitoringSignalListRequest(
                filter=SecurityMonitoringSignalListRequestFilter(
                    query=filter_query if filter_query != "*" else unset,
                    _from=from_datetime or unset,
                    to=to_datetime or unset,
                ),
                page=SecurityMonitoringSignalListRequestPage(
                    limit=limit,
                ),
                sort=sort_order,
            )

            signal_list_response = api_instance.search_security_monitoring_signals(
                body=body,
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
        args: Command arguments containing:
            - signal_id (str, optional): The ID of the signal to retrieve; falls back to the incident signal ID if not provided.

    Returns:
        CommandResults: XSOAR command results with signal data

    Raises:
        DemistoException: If signal_id is not provided or API call fails
    """
    signal_id = args.get("signal_id")

    # If signal_id not provided, try to get it from the current incident
    if not signal_id:
        incident = demisto.incident()
        signal_id = incident.get("CustomFields", {}).get("datadogsecuritysignalid")
        if not signal_id:
            raise DemistoException(
                "signal_id is required. Provide it as an argument or run from an incident with a Datadog Security Signal ID."
            )

    try:
        with ApiClient(configuration) as api_client:
            api_instance = SecurityMonitoringApi(api_client)
            signal_response = api_instance.get_security_monitoring_signal(signal_id=signal_id)
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

            # Create human-readable summary using the display dictionary
            signal_display = signal.to_display_dict()

            readable_output = lookup_to_markdown([signal_display], "Security Signal Details")

            return CommandResults(
                readable_output=readable_output,
                outputs_prefix=SECURITY_SIGNAL_CONTEXT_NAME,
                outputs_key_field="id",
                outputs=signal.to_dict(),
            )

    except Exception as e:
        raise DemistoException(f"Failed to get security signal {signal_id}: {str(e)}")


def suppress_rule_command(
    configuration: Configuration,
    args: dict[str, Any],
) -> CommandResults:
    """
    Create a suppression rule for a security monitoring rule.

    Suppressions allow you to exclude signals that match specific criteria from generating alerts.
    This is useful for filtering out known false positives or signals from testing environments.

    Args:
        configuration: Datadog API configuration
        args: Command arguments containing:
            - rule_id (str, optional): The ID of the security rule to suppress;
              falls back to the incident's rule ID if not provided.

    Returns:
        CommandResults: XSOAR command results with suppression details

    Raises:
        DemistoException: If rule_id or name is missing, or API call fails
    """
    rule_id = args.get("rule_id")
    data_exclusion_query = args.get("data_exclusion_query", "*")

    # If rule_id not provided, try to get it from the current incident
    if not rule_id:
        incident = demisto.incident()
        rule_id = incident.get("CustomFields", {}).get("datadogsecuritysignalruleid")
        if not rule_id:
            raise DemistoException(
                "rule_id is required. Provide it as an argument or run from an incident with a Datadog Security Rule ID."
            )

    try:
        with ApiClient(configuration) as api_client:
            api_instance = SecurityMonitoringApi(api_client)

            # Build the rule query to target this specific rule
            rule_query = f"type:(log_detection OR signal_correlation) ruleId:{rule_id}"

            # Prepare attributes
            attrs = SecurityMonitoringSuppressionCreateAttributes(
                enabled=True,
                name=f"[XSOAR suppression] {rule_id}",
                description="Created from Cortex XSOAR",
                rule_query=rule_query,
                data_exclusion_query=data_exclusion_query,
            )

            body = SecurityMonitoringSuppressionCreateRequest(
                data=SecurityMonitoringSuppressionCreateData(
                    attributes=attrs,
                    type=SecurityMonitoringSuppressionType.SUPPRESSIONS,
                )
            )

            response = api_instance.create_security_monitoring_suppression(body=body)
            suppression_data = response.to_dict().get("data", {})
            suppression_id = suppression_data.get("id")
            readable_output = f"Successfully created suppression for rule {rule_id}\n"
            readable_output += f"Suppression URL: https://app.{SITE}/security/configuration/suppressions/view/{suppression_id}"

            return CommandResults(readable_output=readable_output)

    except Exception as e:
        raise DemistoException(f"Failed to suppress security rule {rule_id}: {str(e)}")


def unsuppress_rule_command(
    configuration: Configuration,
    args: dict[str, Any],
) -> CommandResults:
    """
    Delete a suppression rule by ID.

    Args:
        configuration: Datadog API configuration
        args: Command arguments containing:
            - rule_id (str, optional): The ID of the security rule to suppress - fallback to incident rule id if not provided

    Returns:
        CommandResults: XSOAR command results confirming deletion

    Raises:
        DemistoException: If rule_id is missing or API call fails
    """
    rule_id = args.get("rule_id")

    # If rule_id not provided, try to get it from the current incident
    if not rule_id:
        incident = demisto.incident()
        rule_id = incident.get("CustomFields", {}).get("datadogsecuritysignalruleid")
        if not rule_id:
            raise DemistoException(
                "rule_id is required. Provide it as an argument or run from an incident with a Datadog Security Rule ID."
            )

    try:
        with ApiClient(configuration) as api_client:
            api_instance = SecurityMonitoringApi(api_client)
            response = api_instance.get_suppressions_affecting_rule(rule_id=rule_id)
            supressions_data = response.to_dict().get("data", [])
            suppressions_ids = [s.get("id") for s in supressions_data]

            readable_output = "Succesfully disabled suppressions:\n"
            for suppression_id in suppressions_ids:
                attrs = SecurityMonitoringSuppressionUpdateAttributes(enabled=False)
                body = SecurityMonitoringSuppressionUpdateRequest(
                    data=SecurityMonitoringSuppressionUpdateData(
                        attributes=attrs,
                        type=SecurityMonitoringSuppressionType.SUPPRESSIONS,
                    ),
                )
                api_instance.update_security_monitoring_suppression(
                    suppression_id=suppression_id,
                    body=body,
                )
                url = f"https://app.{SITE}/security/configuration/suppressions/view/{suppression_id}"
                readable_output += f"- {url}\n"

            return CommandResults(readable_output=readable_output)

    except Exception as e:
        raise DemistoException(f"Failed to unsuppress rule {rule_id}: {str(e)}")


def get_security_rule_command(
    configuration: Configuration,
    args: dict[str, Any],
) -> CommandResults:
    """
    Get a specific security monitoring rule by ID.

    Args:
        configuration: Datadog API configuration
        args: Command arguments containing:
            - rule_id (str, optional): The ID of the security rule to retrieve - fallback to incident rule id if not provided

    Returns:
        CommandResults: XSOAR command results with rule data

    Raises:
        DemistoException: If rule_id is not provided or API call fails
    """
    rule_id = args.get("rule_id")

    # If rule_id not provided, try to get it from the current incident
    if not rule_id:
        incident = demisto.incident()
        rule_id = incident.get("CustomFields", {}).get("datadogsecuritysignalruleid")
        if not rule_id:
            raise DemistoException(
                "rule_id is required. Provide it as an argument or run from an incident with a Datadog Security Rule ID."
            )

    try:
        with ApiClient(configuration) as api_client:
            api_instance = SecurityMonitoringApi(api_client)
            rule_response = api_instance.get_security_monitoring_rule(rule_id=rule_id)
            rule_data = rule_response.to_dict()

            if not rule_data:
                readable_output = f"No security rule found with ID: {rule_id}"
                return CommandResults(
                    readable_output=readable_output,
                    outputs_prefix=SECURITY_RULE_CONTEXT_NAME,
                    outputs_key_field="id",
                    outputs={},
                )

            rule = parse_security_rule(rule_data)

            # Create human-readable summary using the display dictionary
            rule_display = rule.to_display_dict()

            readable_output = lookup_to_markdown([rule_display], "Security Rule Details")

            return CommandResults(
                readable_output=readable_output,
                outputs_prefix=SECURITY_RULE_CONTEXT_NAME,
                outputs_key_field="id",
                outputs=rule.to_dict(),
            )

    except Exception as e:
        raise DemistoException(f"Failed to get security rule {rule_id}: {str(e)}")


def get_security_signal_list_command(
    configuration: Configuration,
    args: dict[str, Any],
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
            raise DemistoException(f"Invalid date format. Use formats like '7 days ago', '2023-01-01T00:00:00Z': {str(e)}")

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
            readable_output = "No security signals found matching the specified criteria."
            return CommandResults(
                readable_output=readable_output,
                outputs_prefix=SECURITY_SIGNAL_CONTEXT_NAME,
                outputs_key_field="id",
                outputs=[],
            )

        # Process signals for output
        signals = []
        display_data = []

        for signal in signals_objs:
            signals.append(signal.to_dict())
            display_data.append(signal.to_display_dict())

        # Create human-readable output
        readable_output = lookup_to_markdown(display_data, f"Security Signals ({len(signals)} results)")

        return CommandResults(
            readable_output=readable_output,
            outputs_prefix=SECURITY_SIGNAL_CONTEXT_NAME,
            outputs_key_field="id",
            outputs=signals,
        )

    except Exception as e:
        raise DemistoException(f"Failed to get security signals: {str(e)}")


def update_security_signal_command(
    configuration: Configuration,
    args: dict[str, Any],
) -> CommandResults:
    """
    Update a security signal's assignee and/or state.

    Updates the triage properties of a security signal including assignee, state,
    and archive details. The signal must exist and the user must have appropriate permissions.

    Args:
        configuration: Datadog API configuration
        args: Command arguments containing:
            - signal_id (str, optional): The ID of the signal to update - fallback to incident signal id if not provided
            - assignee (str, optional): Name or email of user to assign (empty string to unassign)
            - state (str, optional): New state (open, under_review, archived)
            - reason (str, optional): Reason for state change
            - comment (str, optional): Comment about the state change

    Returns:
        CommandResults: XSOAR command results with updated signal data

    Raises:
        DemistoException: If signal_id is missing, invalid state provided, or API call fails
    """
    signal_id = args.get("signal_id")
    assignee = args.get("assignee")
    state = args.get("state")
    reason = args.get("archive_reason")
    comment = args.get("archive_comment")

    # If signal_id not provided, try to get it from the current incident
    if not signal_id:
        incident = demisto.incident()
        signal_id = incident.get("CustomFields", {}).get("datadogsecuritysignalid")
        if not signal_id:
            raise DemistoException(
                "signal_id is required. Provide it as an argument or run from an incident with a Datadog Security Signal ID."
            )

    # At least one update parameter must be provided
    if assignee is None and state is None:
        raise DemistoException("At least one of 'assignee' or 'state' must be provided")

    # Validate state if provided
    if state is not None:
        valid_states = ["open", "under_review", "archived"]
        if state not in valid_states:
            raise DemistoException(f"Invalid state '{state}'. Valid states are: {', '.join(valid_states)}")

    try:
        with ApiClient(configuration) as api_client:
            api_instance = SecurityMonitoringApi(api_client)
            user_api_instance = UsersApi(api_client)

            if assignee is not None:
                assignee_uuid = ""

                # Resolve assignee_uuid if assignee is provided
                if assignee != "":
                    res = user_api_instance.list_users(
                        filter_status="Active,Pending",
                        filter=assignee,
                    )
                    users = res.get("data", [])
                    if len(users) == 0:
                        raise DemistoException(f"Could not determine any user for name or email: {assignee}")
                    if len(users) > 1:
                        users = {u.get("attributes", {}).get("email", "") for u in users}
                        raise DemistoException(f"Could not determine the user to assign to from list: {users}")
                    assignee_uuid = users[0].get("id")

                # Always update assignee - either with found assignee_uuid or by unassigning
                assignee_body = SecurityMonitoringSignalAssigneeUpdateRequest(
                    data=SecurityMonitoringSignalAssigneeUpdateData(
                        attributes=SecurityMonitoringSignalAssigneeUpdateAttributes(
                            assignee=SecurityMonitoringTriageUser(uuid=assignee_uuid or ""),
                        ),
                    ),
                )
                api_instance.edit_security_monitoring_signal_assignee(
                    signal_id=signal_id,
                    body=assignee_body,
                )

            # Update state if provided
            if state is not None:
                state_body = SecurityMonitoringSignalStateUpdateRequest(
                    data=SecurityMonitoringSignalStateUpdateData(
                        attributes=SecurityMonitoringSignalStateUpdateAttributes(
                            state=state,
                            reason=reason,
                            comment=comment,
                        ),
                    ),
                )
                api_instance.edit_security_monitoring_signal_state(
                    signal_id=signal_id,
                    body=state_body,
                )

            return get_security_signal_command(configuration, {"signal_id": signal_id})

    except Exception as e:
        raise DemistoException(f"Failed to update security signals: {str(e)}")


def add_security_signal_comment_command(
    configuration: Configuration,
    args: dict[str, Any],
) -> CommandResults:
    """
    Add a comment to a security signal.

    Args:
        configuration: Datadog API configuration
        args: Command arguments containing:
            - event_id (str, required): The event ID of the security signal
            - comment (str, required): The comment text to add

    Returns:
        CommandResults: XSOAR command results with comment data

    Raises:
        DemistoException: If required parameters are missing or API call fails
    """
    event_id = args.get("event_id")
    comment = args.get("comment")

    if not comment:
        raise DemistoException("comment is required")

    # If event_id not provided, try to get it from the current incident
    if not event_id:
        incident = demisto.incident()
        event_id = incident.get("CustomFields", {}).get("datadogsecuritysignaleventid")
        if not event_id:
            raise DemistoException(
                "event_id is required. Provide it as an argument or run from an incident with a Datadog Security Signal Event ID."
            )

    try:
        # This is not exposed by the Datadog API client, but still accessible via API tokens
        comments_response = requests.post(
            f"https://app.{SITE}/api/ui/security/appsec/comment/signal/{event_id}",
            headers={
                "dd-api-key": configuration.api_key["apiKeyAuth"],
                "dd-application-key": configuration.api_key["appKeyAuth"],
                "Content-Type": "application/json",
            },
            data=json.dumps(
                {
                    "data": {"type": "note", "attributes": {"text": comment}},
                }
            ),
        )

        if not comments_response.ok:
            raise DemistoException(f"API request failed with status {comments_response.status_code}: {comments_response.text}")

        data = comments_response.json().get("data", {})
        comment_obj = parse_security_comment(data)

        # Resolve user UUID to name and handle
        with ApiClient(configuration) as api_client:
            user_api_instance = UsersApi(api_client)
            try:
                user_response = user_api_instance.get_user(user_id=comment_obj.user_uuid)
                user_data = user_response.to_dict().get("data", {})
                attrs = user_data.get("attributes", {})
                comment_obj.user_name = attrs.get("name")
                comment_obj.user_handle = attrs.get("handle")
            except Exception:
                pass  # Keep UUID if resolution fails

        # Prepare outputs
        display_data = comment_obj.to_display_dict()
        output = comment_obj.to_dict()

        readable_output = lookup_to_markdown([display_data], "Comment Added Successfully")

        return CommandResults(
            readable_output=readable_output,
            outputs_prefix=SECURITY_COMMENT_CONTEXT_NAME,
            outputs_key_field="id",
            outputs=output,
        )

    except Exception as e:
        raise DemistoException(f"Failed to add comment to security signal: {str(e)}")


def list_security_signal_comments_command(
    configuration: Configuration,
    args: dict[str, Any],
) -> CommandResults:
    """
    List all comments for a security signal.

    Args:
        configuration: Datadog API configuration
        args: Command arguments containing:
            - event_id (str, optional): The event ID of the security signal

    Returns:
        CommandResults: XSOAR command results with list of comments

    Raises:
        DemistoException: If event_id is missing or API call fails
    """
    event_id = args.get("event_id")

    # If event_id not provided, try to get it from the current incident
    if not event_id:
        incident = demisto.incident()
        event_id = incident.get("CustomFields", {}).get("datadogsecuritysignaleventid")
        if not event_id:
            raise DemistoException(
                "event_id is required. Provide it as an argument or run from an incident with a Datadog Security Signal Event ID."
            )

    try:
        # This is not exposed by the Datadog API client, but still accessible via API tokens
        comments_response = requests.get(
            f"https://app.{SITE}/api/ui/security/appsec/comment/signal/{event_id}",
            headers={
                "dd-api-key": configuration.api_key["apiKeyAuth"],
                "dd-application-key": configuration.api_key["appKeyAuth"],
            },
        )
        data = comments_response.json().get("data", [])
        comments = [parse_security_comment(c) for c in data]

        # Resolve all unique user UUIDs in bulk
        with ApiClient(configuration) as api_client:
            user_api_instance = UsersApi(api_client)
            unique_uuids = {c.user_uuid for c in comments}
            user_map = {}  # uuid -> (name, handle)

            for uuid in unique_uuids:
                try:
                    user_response = user_api_instance.get_user(user_id=uuid)
                    user_data = user_response.to_dict().get("data", {})
                    attrs = user_data.get("attributes", {})
                    user_map[uuid] = (attrs.get("name"), attrs.get("handle"))
                except Exception:
                    pass  # Keep UUID if resolution fails

            # Enrich comments with user info
            for comment in comments:
                if comment.user_uuid in user_map:
                    comment.user_name, comment.user_handle = user_map[comment.user_uuid]

        if not comments:
            readable_output = f"No comments found for security signal: {event_id}"
            return CommandResults(
                readable_output=readable_output,
                outputs_prefix=SECURITY_COMMENT_CONTEXT_NAME,
                outputs_key_field="id",
                outputs=[],
            )

        # Prepare outputs
        display_data = [c.to_display_dict() for c in comments]
        outputs = [c.to_dict() for c in comments]

        readable_output = lookup_to_markdown(display_data, f"Security Signal Comments ({len(comments)} results)")

        return CommandResults(
            readable_output=readable_output,
            outputs_prefix=SECURITY_COMMENT_CONTEXT_NAME,
            outputs_key_field="id",
            outputs=outputs,
        )

    except Exception as e:
        raise DemistoException(f"Failed to list comments: {str(e)}")


def logs_query_command(
    configuration: Configuration,
    args: dict[str, Any],
) -> CommandResults:
    """
    Query logs in Datadog Cloud SIEM.

    Supports filtering by query and time range.
    Returns paginated results with configurable sorting for security investigations.
    If no query is provided and running from an incident, will use the rule's query as fallback.

    Args:
        configuration: Datadog API configuration
        args: Command arguments containing filters and pagination parameters

    Returns:
        CommandResults: XSOAR command results with list of logs

    Raises:
        DemistoException: If no query provided and not in incident context, or API call fails
    """
    try:
        # Check if query is provided
        query = args.get("query")
        has_query = query is not None

        # If no query provided, try to get it from incident's rule
        if not has_query:
            incident = demisto.incident()
            rule_id = incident.get("CustomFields", {}).get("datadogsecuritysignalruleid")

            if not rule_id:
                raise DemistoException(
                    "query is required. Provide it as an argument or run from an incident with a Datadog Security Signal."
                )

            # Fetch the rule and extract the query
            with ApiClient(configuration) as api_client:
                api_instance = SecurityMonitoringApi(api_client)
                rule_response = api_instance.get_security_monitoring_rule(rule_id=rule_id)
                rule_data = rule_response.to_dict()
                rule = parse_security_rule(rule_data)

            # Extract query from rule
            query = rule.extract_query()
            args["query"] = query

        limit = arg_to_number(args.get("limit"), arg_name="limit") or DEFAULT_PAGE_SIZE

        sort = args.get("sort", "desc")
        if sort not in ["asc", "desc"]:
            raise DemistoException("Sort must be either 'asc' or 'desc'")

        sort_order = LogsSort.TIMESTAMP_ASCENDING if sort == "asc" else LogsSort.TIMESTAMP_DESCENDING

        search_query = args.get("query", "*")

        # Parse date range
        from_date = args.get("from_date", DEFAULT_FROM_DATE)
        to_date = args.get("to_date", DEFAULT_TO_DATE)

        try:
            from_datetime = parse(from_date, settings={"TIMEZONE": "UTC"})
            to_datetime = parse(to_date, settings={"TIMEZONE": "UTC"})
        except Exception as e:
            raise DemistoException(f"Invalid date format. Use formats like '7 days ago', '2023-01-01T00:00:00Z': {str(e)}")

        with ApiClient(configuration) as api_client:
            logs_api_instance = LogsApi(api_client)

            # Build request body
            body = LogsListRequest(
                filter=LogsQueryFilter(
                    query=search_query,
                    _from=from_datetime.isoformat() if from_datetime else unset,
                    to=to_datetime.isoformat() if to_datetime else unset,
                    storage_tier=args.get("storage_tier", unset),
                ),
                page=LogsListRequestPage(limit=limit),
                sort=sort_order,
            )

            # Execute search
            response = logs_api_instance.list_logs(body=body)
            results = response.to_dict()
            data_list = results.get("data", [])

            if not data_list:
                readable_output = "No logs found matching the specified criteria."
                return CommandResults(
                    readable_output=readable_output,
                    outputs_prefix=LOG_CONTEXT_NAME,
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

            # Build Datadog logs URL with query parameters
            from urllib.parse import quote

            from_ms = int(from_datetime.timestamp() * 1000) if from_datetime else 0
            to_ms = int(to_datetime.timestamp() * 1000) if to_datetime else 0
            logs_url = f"https://app.{SITE}/logs?query={quote(search_query)}&from_ts={from_ms}&to_ts={to_ms}&live=false"

            # Create human-readable output with query info
            query_info = f"**Query:** `{search_query}`\n**Results:** {len(logs)}\n**URL:** {logs_url}\n\n"
            logs_table = lookup_to_markdown(display_data, "Security Logs")
            readable_output = query_info + logs_table

            return CommandResults(
                readable_output=readable_output,
                outputs_prefix=LOG_CONTEXT_NAME,
                outputs_key_field="id",
                outputs=logs,
            )

    except Exception as e:
        raise DemistoException(f"Failed to search logs: {str(e)}")


def fetch_incidents(
    configuration: Configuration,
    params: dict,
) -> None:
    """
    Fetch security signals from Datadog Cloud SIEM and create XSOAR incidents.

    Retrieves new security signals since the last fetch and converts them to XSOAR incidents.
    Supports incremental fetch using last_run timestamp and configurable filters.

    Args:
        configuration: Datadog API configuration
        params: Integration parameters from XSOAR configuration
            - first_fetch: Time range for initial fetch (e.g., "3 days", "7 days")
            - max_fetch: Maximum number of incidents to fetch per cycle (default: 50)
            - fetch_severity: Comma-separated list of severities to fetch (e.g., "medium,high,critical")
            - fetch_state: Signal state to fetch (default: "open")
            - fetch_query: Additional custom query filter

    Returns:
        None. Creates incidents via demisto.incidents() and updates last_run via demisto.setLastRun()
    """
    try:
        # Get integration parameters
        first_fetch = params.get("first_fetch", "3 days")
        max_fetch = int(params.get("max_fetch", 50))
        fetch_severity = params.get("fetch_severity", "medium")
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

        to_datetime = datetime.now()

        # Build filter query
        filter_args = {
            "state": fetch_state,
            "query": fetch_query,
            "severity": fetch_severity,
        }
        filter_query = security_signals_search_query(filter_args)

        # Fetch security signals
        demisto.debug(f"Fetching signals with query: {filter_query}")
        signals = fetch_security_signals(
            configuration=configuration,
            filter_query=filter_query,
            from_datetime=from_datetime,
            to_datetime=to_datetime,
            limit=max_fetch,
            sort="asc",
        )

        demisto.debug(f"Fetched {len(signals)} security signals")

        # Convert signals to XSOAR incidents
        incidents = []
        latest_signal_time = last_fetch_time
        for signal in signals:
            signal_dict = signal.to_dict()
            owner = signal_dict.get("triage", {}).get("assignee", {}).get("name", "")
            labels = []

            if signal.tags:
                for tag in signal.tags:
                    labels.append({"type": "tag", "value": tag})

            incident = {
                "name": signal.title or f"Datadog Security Signal {signal.id}",
                "occurred": (str(signal.timestamp) if signal.timestamp else to_datetime.isoformat()),
                "details": signal.message,
                "severity": map_severity_to_xsoar(signal.severity),
                "dbotMirrorId": signal.id,
                "owner": owner,
                "labels": labels,
                "rawJSON": json.dumps(signal_dict),
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
        global SITE
        SITE = params.get("site", "datadoghq.com")
        configuration = Configuration()
        # Handle credentials type (type 9) - extract password from dict
        api_key_creds = params.get("api_key", {})
        app_key_creds = params.get("app_key", {})
        configuration.api_key["apiKeyAuth"] = api_key_creds.get("password") if isinstance(api_key_creds, dict) else api_key_creds
        configuration.api_key["appKeyAuth"] = app_key_creds.get("password") if isinstance(app_key_creds, dict) else app_key_creds
        configuration.server_variables["site"] = SITE
        configuration.verify_ssl = not params.get("insecure", False)

        if params.get("proxy"):
            proxies = handle_proxy()
            configuration.proxy = proxies.get("https") or proxies.get("http")

        commands = {
            "datadog-signal-get": get_security_signal_command,
            "datadog-signal-list": get_security_signal_list_command,
            "datadog-signal-update": update_security_signal_command,
            "datadog-signal-comment-add": add_security_signal_comment_command,
            "datadog-signal-comment-list": list_security_signal_comments_command,
            "datadog-rule-suppress": suppress_rule_command,
            "datadog-rule-unsuppress": unsuppress_rule_command,
            "datadog-rule-get": get_security_rule_command,
            "datadog-logs-query": logs_query_command,
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
