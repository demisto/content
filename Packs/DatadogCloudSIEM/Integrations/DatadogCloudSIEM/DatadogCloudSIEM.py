from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from CommonServerPython import *  # noqa: F401 # pylint: disable=unused-wildcard-import
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
from datadog_api_client.v2.model.security_monitoring_triage_user import (
    SecurityMonitoringTriageUser,
)
from dateparser import parse
from urllib3 import disable_warnings

from CommonServerUserPython import *  # noqa: F401

# Disable insecure warnings
disable_warnings()

""" CONSTANTS """

DEFAULT_OFFSET = 0
DEFAULT_PAGE_SIZE = 50
PAGE_NUMBER_ERROR_MSG = "Invalid Input Error: page number should be greater than zero."
PAGE_SIZE_ERROR_MSG = "Invalid Input Error: page size should be greater than zero."
DEFAULT_FROM_DATE = "-7days"
DEFAULT_TO_DATE = "now"
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
    assignee: Assignee


@dataclass
class Rule:
    id: str
    name: str
    type: str
    tags: List[str]


@dataclass
class SecuritySignal:
    id: str
    timestamp: Optional[datetime] = None
    host: Optional[str] = None
    service: Optional[List[str]] = None
    level: Optional[str] = None
    severity: Optional[str] = None
    title: Optional[str] = None
    message: Optional[str] = None
    rule: Optional[Rule] = None
    triage: Optional[Triage] = None
    tags: Optional[List[str]] = None
    triggering_log_id: Optional[str] = None
    source: Optional[str] = None

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
            "Source": self.source,
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
            "level": self.level,
            "severity": self.severity,
            "title": self.title,
            "message": self.message,
            "tags": self.tags,
            "triggering_log_id": self.triggering_log_id,
            "source": self.source,
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
            result["triage"] = {"state": self.triage.state}
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
        level=custom.get("level") or attrs.get("level"),
        severity=custom.get("severity"),
        title=custom.get("title") or attrs.get("title") or rule_d.get("name"),
        message=attrs.get("message"),
        rule=rule,
        triage=triage,
        tags=tags,
        triggering_log_id=attrs.get("triggering_log_id"),
        raw=data,
    )


def security_signals_search_query(args: Dict[str, Any]) -> str:
    """
    Build a Datadog search query string for filtering security signals based on provided arguments.

    Constructs a query using Datadog's search syntax with AND operators between conditions.
    Supports filtering by state, severity, rule name, source, and tags.

    Args:
        args (Dict[str, Any]): Dictionary containing search parameters. Supported keys:
            - state (str): Signal state (e.g., "open", "under_review", "archived")
            - severity (str): Severity level (e.g., "low", "medium", "high", "critical")
            - rule_name (str): Name of the security rule
            - source (str): Signal source
            - tags (str or List[str]): Comma-separated tags or list of tags
            - query (str): Additional custom query string

    Returns:
        str: Formatted query string for Datadog API. Returns "*" if no conditions provided.

    Examples:
        >>> args = {"state": "open", "severity": "high"}
        >>> security_signals_search_query(args)
        "@signal.state:open AND @signal.severity:high"

        >>> security_signals_search_query({})
        "*"
    """
    query_parts = []

    if args.get("state"):
        query_parts.append(f"@signal.state:{args.get('state')}")

    if args.get("severity"):
        query_parts.append(f"@signal.severity:{args.get('severity')}")

    if args.get("rule_name"):
        query_parts.append(f"@rule.name:{args.get('rule_name')}")

    if args.get("source"):
        query_parts.append(f"@signal.source:{args.get('source')}")

    if args.get("tags"):
        tags = (
            args.get("tags", "").split(",")
            if isinstance(args.get("tags"), str)
            else args.get("tags", [])
        )
        for tag in tags:
            query_parts.append(f"@signal.tags:{tag.strip()}")

    if args.get("query"):
        query_parts.append(args.get("query"))

    return " AND ".join(query_parts) if query_parts else "*"


def pagination(
    limit: int | None,
    page: int | None,
    page_size: int | None,
) -> tuple[int, int]:
    """
    Define pagination.

    Args:
        page: The page number.
        page_size: The number of requested results per page.
        limit: The number of requested results limit per page.

    Returns:
        limit (int): Records per page.
        offset (int): The number of records to be skipped.
    """
    if page and page <= 0:
        raise DemistoException(PAGE_NUMBER_ERROR_MSG)
    if page_size and page_size <= 0:
        raise DemistoException(PAGE_SIZE_ERROR_MSG)

    if page_size and limit:
        limit = page_size
    page = page - 1 if page else DEFAULT_OFFSET
    page_size = page_size or DEFAULT_PAGE_SIZE

    limit = limit or page_size or DEFAULT_PAGE_SIZE
    offset = page * page_size

    return limit, offset


""" COMMAND FUNCTIONS """


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

            # Create human-readable summary using the display dictionary
            signal_display = signal.to_display_dict()
            readable_output = lookup_to_markdown(
                [signal_display], "Security Signal Details"
            )

            return CommandResults(
                readable_output=readable_output,
                outputs_prefix=SECURITY_SIGNAL_CONTEXT_NAME,
                outputs_key_field="id",
                outputs=signal.to_dict(),
            )

    except Exception as e:
        raise DemistoException(f"Failed to get security signal {signal_id}: {str(e)}")


def get_security_signals_command(
    configuration: Configuration,
    args: Dict[str, Any],
) -> CommandResults:
    """
    Get a list of security signals with optional filtering.

    Supports filtering by state, severity, rule name, source, tags, and time range.
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
        page = arg_to_number(args.get("page"), arg_name="page")
        page_size = arg_to_number(args.get("page_size"), arg_name="page_size")
        limit = arg_to_number(args.get("limit"), arg_name="limit")
        limit, _ = pagination(limit, page, page_size)

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

            if not data_list:
                readable_output = (
                    "No security signals found matching the specified criteria."
                )
                return CommandResults(
                    readable_output=readable_output,
                    outputs_prefix=SECURITY_SIGNAL_CONTEXT_NAME,
                    outputs_key_field="id",
                    outputs=[],
                )

            signals = []
            display_data = []

            for signal_data in data_list:
                signal = parse_security_signal(signal_data)
                signals.append(signal.to_dict())
                display_data.append(signal.to_display_dict())

            # Create human-readable output
            readable_output = lookup_to_markdown(
                display_data, f"Security Signals ({len(signals)} results)"
            )

            return CommandResults(
                readable_output=readable_output,
                outputs_prefix=SECURITY_SIGNAL_CONTEXT_NAME,
                outputs_key_field="id",
                outputs=signals,
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

        signal_update = SecuritySignal(
            id=signal_id,
            triage=Triage(state=state, assignee=assignee),
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
        args: Command arguments containing signal_id and state

    Returns:
        CommandResults: XSOAR command results with updated signal data

    Raises:
        DemistoException: If signal_id or state is missing, or API call fails
    """
    signal_id = args.get("signal_id")
    state = args.get("state")

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
        updated_state = attributes.get("state", state)

        signal_update = SecuritySignal(
            id=signal_id,
            triage=Triage(state=updated_state, assignee=assignee),
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
    args: dict[str, Any],
) -> CommandResults | DemistoException:
    return DemistoException("not implemented")


def fetch_incidents(configuration: Configuration, params: dict):
    # first_fetch_time = params.get("first_fetch", "3 days")
    # fetch_limit = params.get("max_fetch", 50)
    # first_fetch_time = dateparser.parse(f"-{first_fetch_time}")
    # last_run = demisto.getLastRun()
    # with ApiClient(configuration) as api_client:
    #     incidents = []
    #     api_instance = IncidentsApi(api_client)
    #     configuration.unstable_operations["search_incidents"] = True

    #     response = api_instance.search_incidents(
    #         query=incident_serach_query({}),
    #         page_size=min(200, int(fetch_limit)),
    #         sort=IncidentSearchSortOrder("-created"),
    #     )
    #     results = response.to_dict()
    #     data = results.get("data", {}).get("attributes", {}).get("incidents", [])
    #     data = [convert_datetime_to_str(incident.get("data")) for incident in data]
    #     data_list = [
    #         incident
    #         for incident in data
    #         if (
    #             datetime.fromisoformat(incident["attributes"]["modified"])
    #             .replace(tzinfo=None)
    #             .timestamp()
    #             > datetime.fromisoformat(last_run.get("lastRun", "")).timestamp()
    #             if last_run.get("lastRun")
    #             else first_fetch_time.timestamp() if first_fetch_time else None
    #         )
    #     ]
    #     for obj in data_list:
    #         new_obj = obj["attributes"]
    #         new_obj["type"] = obj["type"]
    #         new_obj["detected"] = datetime.fromisoformat(
    #             obj["attributes"]["detected"]
    #         ).strftime(UI_DATE_FORMAT)
    #         new_obj["relationships"] = obj["relationships"]
    #         new_obj["id"] = obj["id"]
    #         new_obj["detection_method"] = obj["attributes"]["fields"][
    #             "detection_method"
    #         ]["value"]
    #         new_obj["root_cause"] = obj["attributes"]["fields"]["root_cause"]["value"]
    #         new_obj["summary"] = obj["attributes"]["fields"]["summary"]["value"]
    #         new_obj["notification_display_name"] = (
    #             obj["attributes"]["notification_handles"][0]["display_name"]
    #             if obj["attributes"]["notification_handles"]
    #             else None
    #         )
    #         new_obj["notification_handle"] = (
    #             obj["attributes"]["notification_handles"][0]["handle"]
    #             if obj["attributes"]["notification_handles"]
    #             else None
    #         )
    #         incident = {
    #             "name": obj["attributes"]["title"],
    #             "occurred": obj["attributes"]["modified"],
    #             "dbotMirrorId": obj["id"],
    #             "rawJSON": json.dumps({"incidents": new_obj}),
    #             "type": "Datadog Cloud SIEM",
    #         }
    #         incidents.append(incident)
    #     if data_list:
    #         demisto.setLastRun(
    #             {"lastRun": data_list[0].get("attributes", {}).get("modified", "")}
    #         )
    # demisto.incidents(incidents)
    return "OK"


""" MAIN FUNCTION """


def main() -> None:
    command: str = demisto.command()
    params: dict[str, Any] = demisto.params()
    args: dict[str, Any] = demisto.args()
    demisto.debug(f"Command being called is {command}")
    try:
        configuration = Configuration()
        configuration.api_key["apiKeyAuth"] = params.get("api_key")
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
            return_results(fetch_incidents(configuration, params))
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
