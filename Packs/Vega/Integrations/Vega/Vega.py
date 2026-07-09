import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
import html as html_module
import http.client as http_client
import math
import re
import time
from collections.abc import Callable
from datetime import datetime, timedelta, UTC
from typing import Any
# ?-------------------------- Import --------------------------------------

# ? ---------------------------- HEADERS LOGS SUPPRESSION --------------------------------------


def _suppress_noisy_http_integration_logs() -> None:
    """Suppress http.client wire logs such as CloudFront response headers from integration logs."""
    try:
        http_client.HTTPConnection.debuglevel = 0
    except Exception as exc:
        demisto.debug(f"Vega: unable to disable HTTP wire logging: {exc}")

    if not is_debug_mode():
        return

    integration_logger = LOG
    if getattr(integration_logger, "_vega_http_log_filter_installed", False):
        return

    original_write = integration_logger.write

    def filtered_write(msg: Any) -> None:
        encoding = getattr(integration_logger, "encoding", "utf-8")
        text = msg.decode(encoding) if isinstance(msg, bytes) else str(msg)
        if text.lstrip().startswith("header:"):
            return
        original_write(msg)

    integration_logger.write = filtered_write  # type: ignore[method-assign]
    integration_logger._vega_http_log_filter_installed = True  # type: ignore[attr-defined]


# ? ---------------------------- HEADERS LOGS SUPPRESSION --------------------------------------


# ? ------------------------------------CONSTANTS --------------------------------------
VEGA_SEVERITY_TO_XSOAR = {
    "LOW": IncidentSeverity.LOW,
    "MEDIUM": IncidentSeverity.MEDIUM,
    "HIGH": IncidentSeverity.HIGH,
    "CRITICAL": IncidentSeverity.CRITICAL,
}

VALID_DETECTION_STATES = frozenset({"ENABLED", "DISABLED", "TEST_MODE"})
VALID_DETECTION_SEVERITIES = frozenset({"LOW", "MEDIUM", "HIGH", "CRITICAL"})

MIRROR_ENTITY_SUFFIX_ALERT = "alert"
MIRROR_ENTITY_SUFFIX_INCIDENT = "incident"
VEGA_ALERT_STATUS_FIELD = "vegastatus"
VEGA_ALERT_SEVERITY_FIELD = "vegaalertseverity"
VEGA_INCIDENT_STATUS_FIELD = "vegaincidentstatus"
VEGA_SEVERITY_FIELD = "vegaseverity"
VEGA_VERDICT_FIELD = "vegaverdict"
VEGA_VERDICT_REASONING_FIELD = "vegaverdictreasoning"
VEGA_NEW_COMMENT_FIELD = "veganewcomment"
VEGA_NEW_COMMENT_LAYOUT_DEFAULT = "comment"
VEGA_MIRROR_TAG_FROM_VEGA = "From Vega"
VEGA_MIRROR_TAG_TO_VEGA = "To Vega"
GET_MODIFIED_REMOTE_DATA_LIMIT = 100
MIRROR_POLL_LOOKBACK = timedelta(minutes=1)
MIRROR_LAST_UPDATE_SAFETY_MARGIN = timedelta(minutes=1)
MIRROR_UPDATED_TO_BUFFER = timedelta(minutes=1)

MITRE_TACTIC_KEYS = ("mitreTactics", "mitre_tactics", "tactics")
MITRE_TECHNIQUE_KEYS = ("mitreTechniques", "mitre_techniques", "techniques")


VEGA_NUMERIC_SEVERITY_TO_API: dict[int, str] = {
    1: "LOW",
    2: "MEDIUM",
    3: "HIGH",
    4: "CRITICAL",
}
VEGA_OUTGOING_MIRROR_FIELDS: dict[str, dict[str, tuple[str, ...]]] = {
    "Vega Alert": {
        VEGA_ALERT_STATUS_FIELD: ("Vega alert status",),
        VEGA_ALERT_SEVERITY_FIELD: ("Vega alert severity",),
        VEGA_VERDICT_FIELD: ("Vega alert verdict",),
        VEGA_VERDICT_REASONING_FIELD: ("Vega alert verdict reasoning",),
        VEGA_NEW_COMMENT_FIELD: ("Comment to add on the Vega alert",),
    },
    "Vega Incident": {
        VEGA_SEVERITY_FIELD: ("Vega incident severity",),
        VEGA_INCIDENT_STATUS_FIELD: ("Vega incident status",),
        VEGA_VERDICT_FIELD: ("Vega incident verdict",),
        VEGA_VERDICT_REASONING_FIELD: ("Vega incident verdict reasoning",),
        VEGA_NEW_COMMENT_FIELD: ("Comment to add on the Vega incident",),
    },
}
OUTGOING_MIRROR_FIELD_STATUS = "Status"
OUTGOING_MIRROR_FIELD_SEVERITY = "Severity"
OUTGOING_MIRROR_FIELD_VERDICT = "Verdict"
OUTGOING_MIRROR_FIELD_VERDICT_REASONING = "Verdict Reasoning"
OUTGOING_MIRROR_FIELD_COMMENTS = "Comments"
OUTGOING_MIRROR_FIELD_LABELS: tuple[str, ...] = (
    OUTGOING_MIRROR_FIELD_STATUS,
    OUTGOING_MIRROR_FIELD_SEVERITY,
    OUTGOING_MIRROR_FIELD_VERDICT,
    OUTGOING_MIRROR_FIELD_VERDICT_REASONING,
    OUTGOING_MIRROR_FIELD_COMMENTS,
)
VALID_OUTGOING_MIRROR_FIELD_LABELS = frozenset(OUTGOING_MIRROR_FIELD_LABELS)
VEGA_CLOSE_STATUSES = frozenset({"RESOLVED"})
VEGA_ALERT_OPEN_STATUSES = frozenset({"REOPENED", "OPEN", "NEW", "INVESTIGATING", "IN_PROGRESS", "PEER_REVIEW"})
VEGA_INCIDENT_OPEN_STATUSES = frozenset(
    {
        "REOPENED",
        "OPEN",
        "NEW",
        "INVESTIGATING",
        "IN_PROGRESS",
        "ON_HOLD",
        "EXTERNAL_ESCALATION",
        "REVIEW_RECOMMENDED",
        "RESPONSE_REQUIRED",
        "UNDER_REVIEW",
    }
)

RATE_LIMIT_MAX_RETRIES = 10
RATE_LIMIT_INITIAL_WAIT_SECONDS = 2
RATE_LIMIT_WAIT_INCREMENT_SECONDS = 2
FETCH_ENTITIES_PAGE_SIZE = 100
_RETRYABLE_HTTP_STATUS_CODES = frozenset({429, 502, 503, 504})
DEFAULT_ALERT_EVENTS_PAGE_SIZE = 200
ALERT_EVENT_JSON_MERGE_KEYS = frozenset({"fields"})
ALERT_EVENT_JSON_TRUNCATE_KEYS = frozenset({"raw", "_raw"})
ALERT_EVENTS_NOT_AVAILABLE_MARKDOWN = "### Alert Events\n\nNo alert events found."
ALERT_EVENT_MAX_FLATTEN_DEPTH = 3
ALERT_EVENT_MAX_COLUMNS = 20
ALERT_EVENT_MAX_CELL_LENGTH = 300
ALERT_EVENT_PREFERRED_COLUMNS: tuple[str, ...] = (
    "timestamp",
    "index_timestamp",
    "timeframe",
    "timeFrame",
    "source",
    "storage",
    "catalog",
    "class",
    "data_source",
    "operation",
    "log_type",
    "actor.user.uid",
    "actor.user.name",
    "actor.user.username",
    "user.username",
    "event_count",
    "eventCount",
    "unique_events_count",
    "uniqueEventsCount",
    "regions_count",
    "regionsCount",
    "unique_events",
    "uniqueEvents",
    "status_code",
    "request.uri",
    "resource.name",
    "cluster.name",
    "namespace.name",
    "account.uid",
    "user_agent",
    "src_endpoint.ip",
    "verb",
    "raw",
    "_raw",
)

VEGA_TIMELINE_ALERT_SEVERITY_LABELS: dict[int, str] = {
    1: "Low",
    2: "Medium",
    3: "High",
    4: "Critical",
}

BACKFILL_DAYS_MIN = 0
BACKFILL_DAYS_MAX = 365
DEFAULT_BACKFILL_DAYS = 30
MAX_FETCH_MIN = 1
MAX_FETCH_CAP = 50
DEFAULT_MAX_FETCH = 50
MAX_FETCH_ERROR = "Incorrect value please enter between 1-50."
DEFAULT_LOOKBACK_MINUTES = 5
MAX_LOOKBACK_MINUTES = 60
INCIDENTS_OFFSET_KEY = "incidents_offset"
INCIDENTS_PAGINATION_FROM_KEY = "incidents_pagination_from"
ALERTS_OFFSET_KEY = "alerts_offset"
ALERTS_PAGINATION_FROM_KEY = "alerts_pagination_from"

VALID_ALERT_STATUSES = frozenset({"OPEN", "IN_PROGRESS", "PEER_REVIEW", "RESOLVED"})
ALERT_STATUS_DISPLAY_TO_API: dict[str, str] = {
    "OPEN": "OPEN",
    "IN PROGRESS": "IN_PROGRESS",
    "PEER REVIEW": "PEER_REVIEW",
    "RESOLVED": "RESOLVED",
}

VALID_INCIDENT_STATUSES = frozenset(
    {
        "NEW",
        "INVESTIGATING",
        "ON_HOLD",
        "EXTERNAL_ESCALATION",
        "RESOLVED",
        "REOPENED",
        "REVIEW_RECOMMENDED",
        "RESPONSE_REQUIRED",
        "UNDER_REVIEW",
    }
)
INCIDENT_STATUS_DISPLAY_TO_API: dict[str, str] = {
    "NEW": "NEW",
    "INVESTIGATING": "INVESTIGATING",
    "ON HOLD": "ON_HOLD",
    "EXTERNAL ESCALATION": "EXTERNAL_ESCALATION",
    "RESOLVED": "RESOLVED",
    "REOPENED": "REOPENED",
    "REVIEW RECOMMENDED": "REVIEW_RECOMMENDED",
    "RESPONSE REQUIRED": "RESPONSE_REQUIRED",
    "UNDER REVIEW": "UNDER_REVIEW",
}

VALID_SEVERITIES = frozenset({"LOW", "MEDIUM", "HIGH", "CRITICAL"})
VALID_VERDICTS = frozenset({"MALICIOUS", "SUSPICIOUS", "BENIGN", "INCONCLUSIVE", "NA"})
VERDICT_DISPLAY_TO_API: dict[str, str] = {
    "MALICIOUS": "MALICIOUS",
    "SUSPICIOUS": "SUSPICIOUS",
    "BENIGN": "BENIGN",
    "INCONCLUSIVE": "INCONCLUSIVE",
    "NA": "NA",
    "N/A": "NA",
}

_CONNECTION_ERROR_MARKERS = (
    "connection timeout error",
    "verify that the server url",
    "connection error",
    "ssl certificate verification failed",
    "proxy error",
    "max retries error",
    "name or service not known",
    "nodename nor servname",
    "failed to establish a new connection",
    "temporary failure in name resolution",
    "read timed out",
)
_URL_UNREACHABLE_STATUS_CODES = frozenset({404, 405, 502, 503, 504})
_AUTH_FAILURE_STATUS_CODES = frozenset({401, 403})
TEST_CONNECTION_URL_ERROR = (
    "Unable to connect to the Vega API. Please verify the Base URL is correct " "and reachable from the Cortex XSOAR engine."
)
TEST_CONNECTION_BASE_URL_ERROR = "Unable to reach the Vega API at the configured Base URL. Please verify the Base URL is correct."
TEST_CONNECTION_ACCESS_KEY_ERROR = "Incorrect Access Key. Please check your credentials."
TEST_CONNECTION_ACCESS_KEY_ID_ERROR = "Incorrect Access Key ID. Please check your credentials."

# ? ------------------------------------CONSTANTS --------------------------------------


# ? ---------------------------- GRAPHQL QUERIES --------------------------------------
GET_ALERTS_QUERY = (
    "query GetAlerts($alertNames: [String!], $alertIds: [ID!], $alertSeverities: [AlertSeverity!], "
    "$statuses: [AlertStatus!], $detectionIds: [ID!], $dataSourceNames: [String!], "
    "$alertVerdicts: [AlertVerdict!], $hasRelatedIncidents: Boolean, $from: Time, "
    "$updatedFrom: Time, $updatedTo: Time, $limit: Int, $offset: Int) { "
    " getAlerts(alertNames: $alertNames, alertIds: $alertIds, alertSeverities: $alertSeverities, "
    "statuses: $statuses, detectionIds: $detectionIds, dataSourceNames: $dataSourceNames, "
    "alertVerdicts: $alertVerdicts, hasRelatedIncidents: $hasRelatedIncidents, from: $from, "
    "updatedFrom: $updatedFrom, updatedTo: $updatedTo, limit: $limit, offset: $offset) { "
    "  alerts { id vegaAlertId detectionId name description severity status "
    "   assignee { userId displayName email } "
    "   assignees { userId displayName email } "
    "   dataSources createdAt updatedAt "
    "   mitre { mitreTactics mitreTechniques } "
    "   relatedIncidents { incidentId name } "
    "   detectionSource detectionDescription detectionQuery eventCount isTestMode verdict verdictReasoning dedupCount "
    "   comments { text addedBy addedAt } } "
    "  total limit offset "
    "  error { code message } } }"
)

GET_ALERT_MIRROR_QUERY = (
    "query GetAlerts($alertIds: [ID!], $from: Time, $limit: Int, $offset: Int) { "
    " getAlerts(alertIds: $alertIds, from: $from, limit: $limit, offset: $offset) { "
    "  alerts { id vegaAlertId status severity verdict verdictReasoning updatedAt "
    "   comments { text addedBy addedAt } } "
    "  total limit offset "
    "  error { code message } } }"
)

GET_INCIDENT_MIRROR_QUERY = (
    "query GetIncidents($incidentIds: [ID!], $from: Time, $limit: Int, $offset: Int) { "
    " getIncidents(incidentIds: $incidentIds, from: $from, limit: $limit, offset: $offset) { "
    "  incidents { id status severity verdict verdictReasoning lastUpdated "
    "   comments { text addedBy addedAt } } "
    "  total limit offset "
    "  error { code message } } }"
)

GET_INCIDENTS_QUERY = (
    "query GetIncidents($incidentNames: [String!], $incidentIds: [ID!], $severities: [IncidentSeverity!], "
    "$statuses: [IncidentStatusPublic!], $verdicts: [IncidentVerdictPublic!], "
    "$from: Time, $updatedFrom: Time, $updatedTo: Time, $limit: Int, $offset: Int) { "
    " getIncidents(incidentNames: $incidentNames, incidentIds: $incidentIds, severities: $severities, "
    "statuses: $statuses, verdicts: $verdicts, from: $from, updatedFrom: $updatedFrom, "
    "updatedTo: $updatedTo, limit: $limit, offset: $offset) { "
    "  incidents { id name createdBy createdAt lastUpdated severity status dataSources verdict verdictReasoning "
    "   assignee { userId displayName email } "
    "   assignees { userId displayName email } "
    "   comments { text addedBy addedAt } "
    "   incidentSummary incidentFindings assets observables alertsCount "
    "   alerts { alertId name createdAt } "
    "   recommendedActions { name description actionKey targetParams } "
    "   investigationPlan { stepName stepConclusion cells { cellName query queryId } } "
    "   link } "
    "  total limit offset "
    "  error { code message } } }"
)

GET_INCIDENT_TIMELINE_QUERY = (
    "query GetIncidentTimeline($incidentId: ID!, $limit: Int, $offset: Int) { "
    " getIncidentTimeline(incidentId: $incidentId, limit: $limit, offset: $offset) { "
    "  events { "
    "   id timestamp summary dataSources assets observables "
    "   alert { alertId name createdAt } "
    "  } "
    "  total limit offset "
    "  error { code message } } }"
)

UPDATE_ALERTS_MUTATION = (
    "mutation UpdateAlerts($input: UpdateAlertsInput!) { "
    " updateAlerts(input: $input) { "
    "  alerts { id vegaAlertId detectionId name description severity status "
    "   assignee { userId displayName email } "
    "   assignees { userId displayName email } "
    "   dataSources createdAt updatedAt "
    "   mitre { mitreTactics mitreTechniques } "
    "   relatedIncidents { incidentId name } "
    "   detectionSource detectionDescription detectionQuery eventCount isTestMode "
    "   verdict verdictReasoning dedupCount "
    "   comments { text addedBy addedAt } } "
    "  error { code message } } }"
)

UPDATE_INCIDENTS_MUTATION = (
    "mutation UpdateIncidents($input: UpdateIncidentsInput!) { "
    " updateIncidents(input: $input) { "
    "  incidents { incidentId incidentName status "
    "   assignee { userId displayName email } "
    "   assignees { userId displayName email } "
    "   verdict verdictReasoning updatedAt } "
    "  errors { code message } } }"
)

SET_DETECTIONS_STATE_MUTATION = (
    "mutation SetDetectionsState($input: SetDetectionsStateInput!) { " " setDetectionsState(input: $input) { " "  ids } }"
)

UPDATE_DETECTIONS_MUTATION = (
    "mutation UpdateDetections($input: UpdateDetectionsInput!) { "
    " updateDetections(input: $input) { "
    "  results { "
    "   name status "
    "   errors { code message field } "
    "   detection { id name severity status state tags } "
    "  } "
    "  summary { requested valid invalid committed } "
    " } }"
)

GET_ALERTS_EVENTS_QUERY = (
    "query GetAlertsEvents($alertId: ID!, $limit: Int, $offset: Int) { "
    " getAlertsEvents(alertId: $alertId, limit: $limit, offset: $offset) { "
    "  total limit offset results "
    "  error { code message } } }"
)
# ? ---------------------------- GRAPHQL QUERIES --------------------------------------

# ? ---------------------------- HELPER FUNCTIONS --------------------------------------


def parse_backfill_days(backfill_days: str | int | float | None) -> str:
    """Convert backfill day count to an ISO 8601 UTC start time for the first fetch."""
    raw = "" if backfill_days is None else str(backfill_days).strip()
    try:
        days = int(float(raw)) if raw else DEFAULT_BACKFILL_DAYS
    except (TypeError, ValueError):
        days = DEFAULT_BACKFILL_DAYS
    if days < BACKFILL_DAYS_MIN or days > BACKFILL_DAYS_MAX:
        days = DEFAULT_BACKFILL_DAYS
    start = datetime.now(UTC).replace(hour=0, minute=0, second=0, microsecond=0) - timedelta(days=days)
    return start.strftime("%Y-%m-%dT%H:%M:%SZ")


def validate_lookback_minutes(lookback_minutes: int | str | None) -> None:
    """Validate that lookback_minutes is an integer between 1 and MAX_LOOKBACK_MINUTES inclusive."""
    parsed = arg_to_number(lookback_minutes, arg_name="lookback_minutes", required=False)
    if parsed is None or parsed < 1 or parsed > MAX_LOOKBACK_MINUTES:
        raise ValueError(f"Fetch Lookback (minutes) must be an integer between 1 and {MAX_LOOKBACK_MINUTES}.")


def _parse_lookback_minutes(raw_value: str | int | None) -> int:
    """Parse the lookback_minutes parameter, clamping to [1, MAX_LOOKBACK_MINUTES]."""
    if raw_value is None or str(raw_value).strip() == "":
        return DEFAULT_LOOKBACK_MINUTES
    try:
        minutes = int(str(raw_value).strip())
    except (TypeError, ValueError):
        return DEFAULT_LOOKBACK_MINUTES
    return max(1, min(minutes, MAX_LOOKBACK_MINUTES))


def _apply_lookback_to_from_time(from_time: str, lookback_minutes: int) -> str:
    """Shift a fetch from_time backwards by lookback_minutes for late-indexed entity detection."""
    parsed = _parse_entity_created_at(from_time)
    if parsed is None:
        return from_time
    shifted = parsed - timedelta(minutes=lookback_minutes)
    return _format_fetch_timestamp(shifted)


def _mirror_bool(value: Any) -> bool:
    """Parse XSOAR mirror boolean args that may be bool, int, or string."""
    if value is None or value == "":
        return False
    try:
        return argToBoolean(value)
    except (ValueError, TypeError):
        return bool(value)


def _mirror_custom_fields(source: dict[str, Any]) -> dict[str, Any]:
    """Return CustomFields from a mirror payload, parsing JSON strings when needed."""
    custom_fields = source.get("CustomFields")
    if custom_fields is None:
        custom_fields = source.get("customFields")
    if isinstance(custom_fields, str):
        return _mirror_dict(custom_fields)
    return dict(custom_fields) if isinstance(custom_fields, dict) else {}


def validate_backfill_days(backfill_days: str | int | None) -> None:
    """Validate that backfill_days is an integer between 0 and 365 inclusive."""
    if backfill_days is None:
        raise ValueError("backfill_days must be an integer between 0 and 365.")
    try:
        days = int(backfill_days)
    except (TypeError, ValueError):
        raise ValueError("backfill_days must be an integer between 0 and 365.")

    if days < BACKFILL_DAYS_MIN or days > BACKFILL_DAYS_MAX:
        raise ValueError("backfill_days must be between 0 and 365.")


def _filter_fetch_values(
    values: list[str] | None,
    valid_api_values: frozenset[str],
    display_to_api: dict[str, str] | None = None,
) -> list[str] | None:
    """Keep only recognized fetch filters and map UI labels to Vega API enum values.
    Unknown or custom multi-select values are ignored. When provided, display_to_api
    maps human-readable labels to API values; values already in valid_api_values are
    also accepted (e.g. legacy underscore-separated statuses).
    """
    if not values:
        return None

    label_map = display_to_api or {}
    api_values: list[str] = []
    seen: set[str] = set()
    for raw in values:
        if raw is None or not str(raw).strip():
            continue
        token = str(raw).strip().upper()
        api_value = label_map.get(token)
        if api_value is None and token in valid_api_values:
            api_value = token
        if api_value and api_value in valid_api_values and api_value not in seen:
            seen.add(api_value)
            api_values.append(api_value)

    return api_values or None


def filter_alert_statuses(values: list[str] | None) -> list[str] | None:
    """Validate alert status filters and return Vega API status values."""
    return _filter_fetch_values(values, VALID_ALERT_STATUSES, ALERT_STATUS_DISPLAY_TO_API)


def filter_incident_statuses(values: list[str] | None) -> list[str] | None:
    """Validate incident status filters and return Vega API status values."""
    return _filter_fetch_values(values, VALID_INCIDENT_STATUSES, INCIDENT_STATUS_DISPLAY_TO_API)


def filter_alert_severities(values: list[str] | None) -> list[str] | None:
    """Validate alert severity filters and return Vega API severity values."""
    return _filter_fetch_values(values, VALID_SEVERITIES)


def filter_incident_severities(values: list[str] | None) -> list[str] | None:
    """Validate incident severity filters and return Vega API severity values."""
    return _filter_fetch_values(values, VALID_SEVERITIES)


def filter_alert_verdicts(values: list[str] | None) -> list[str] | None:
    """Validate alert verdict filters and return Vega API verdict values."""
    return _filter_fetch_values(values, VALID_VERDICTS, VERDICT_DISPLAY_TO_API)


def filter_incident_verdicts(values: list[str] | None) -> list[str] | None:
    """Validate incident verdict filters and return Vega API verdict values."""
    return _filter_fetch_values(values, VALID_VERDICTS, VERDICT_DISPLAY_TO_API)


def _resolve_outgoing_mirror_fields(params: dict[str, Any] | None = None) -> set[str]:
    """Return enabled outgoing mirror field labels. Empty selection mirrors all fields."""
    params = params or demisto.params()
    selected = argToList(params.get("outgoing_mirror_fields"))
    if not selected:
        return set(OUTGOING_MIRROR_FIELD_LABELS)

    enabled = {
        str(value).strip() for value in selected if value is not None and str(value).strip() in VALID_OUTGOING_MIRROR_FIELD_LABELS
    }
    return enabled if enabled else set(OUTGOING_MIRROR_FIELD_LABELS)


def resolve_has_related_incidents(values: list[str] | None) -> bool | None:
    """Resolve the Vega hasRelatedIncidents filter from Yes/No multi-select values.

    Returns True when only Yes is selected, False when only No is selected,
    and None when both or neither are selected so the API filter is omitted.
    """
    if not values:
        return None

    normalized = {str(value).strip().upper() for value in values if str(value).strip()}
    has_yes = "YES" in normalized
    has_no = "NO" in normalized
    result: bool | None = None
    if has_yes and not has_no:
        result = True
    elif has_no and not has_yes:
        result = False
    return result


def _http_status_code(exc: Exception) -> int | None:
    """Return the HTTP status code from a DemistoException, if present."""
    if isinstance(exc, DemistoException) and exc.res is not None:
        return exc.res.status_code
    return None


def _is_retryable_http_error(exc: Exception) -> bool:
    """Return True when an HTTP or network failure is likely transient and safe to retry."""
    status_code = _http_status_code(exc)
    if status_code in _RETRYABLE_HTTP_STATUS_CODES:
        return True
    message = str(exc).lower()
    return any(marker in message for marker in _CONNECTION_ERROR_MARKERS)


def _is_graphql_rate_limited(errors: Any) -> bool:
    """Return True when GraphQL errors indicate rate limiting."""
    if not isinstance(errors, list):
        return False

    for err in errors:
        if not isinstance(err, dict):
            continue
        extensions = err.get("extensions") or {}
        error_code_name = extensions.get("error_code_name")
        code = extensions.get("code")
        if error_code_name == "REQUEST_RATE_LIMITED" or code == "TooManyRequests":
            return True

    return False


def _is_connection_or_url_error(exc: Exception) -> bool:
    """Return True when the failure is likely caused by an invalid or unreachable Base URL."""
    message = str(exc).lower()
    if any(marker in message for marker in _CONNECTION_ERROR_MARKERS):
        return True
    status_code = _http_status_code(exc)
    return status_code in _URL_UNREACHABLE_STATUS_CODES if status_code is not None else False


def _test_connection_error_message(exc: Exception, key_error_msg: str) -> str:
    """Map API failures to a user-facing test-connection message."""
    if _is_connection_or_url_error(exc):
        return TEST_CONNECTION_BASE_URL_ERROR if _http_status_code(exc) == 404 else TEST_CONNECTION_URL_ERROR
    return key_error_msg


def _build_alerts_query_variables(
    *,
    severities: list[str] | None = None,
    statuses: list[str] | None = None,
    verdicts: list[str] | None = None,
    has_related_incidents: bool | None = None,
    from_time: str | None = None,
    updated_from: str | None = None,
    updated_to: str | None = None,
    alert_ids: list[str] | None = None,
    limit: int | None = None,
    offset: int = 0,
) -> dict[str, Any]:
    """Build GraphQL variables for the getAlerts query."""
    variables: dict[str, Any] = {"offset": offset}
    if limit is not None:
        variables["limit"] = limit
    if severities:
        variables["alertSeverities"] = severities
    if statuses:
        variables["statuses"] = statuses
    if verdicts:
        variables["alertVerdicts"] = verdicts
    if has_related_incidents is not None:
        variables["hasRelatedIncidents"] = has_related_incidents
    if from_time:
        variables["from"] = from_time
    if updated_from:
        variables["updatedFrom"] = updated_from
    if updated_to:
        variables["updatedTo"] = updated_to
    if alert_ids:
        variables["alertIds"] = alert_ids
    return variables


def _build_incidents_query_variables(
    *,
    severities: list[str] | None = None,
    statuses: list[str] | None = None,
    verdicts: list[str] | None = None,
    from_time: str | None = None,
    updated_from: str | None = None,
    updated_to: str | None = None,
    incident_ids: list[str] | None = None,
    limit: int | None = None,
    offset: int = 0,
) -> dict[str, Any]:
    """Build GraphQL variables for the getIncidents query."""
    variables: dict[str, Any] = {"offset": offset}
    if limit is not None:
        variables["limit"] = limit
    if severities:
        variables["severities"] = severities
    if statuses:
        variables["statuses"] = statuses
    if verdicts:
        variables["verdicts"] = verdicts
    if from_time:
        variables["from"] = from_time
    if updated_from:
        variables["updatedFrom"] = updated_from
    if updated_to:
        variables["updatedTo"] = updated_to
    if incident_ids:
        variables["incidentIds"] = incident_ids
    return variables


def _validate_test_connection_roles(get_access_key: dict[str, Any]) -> None:
    """Raise when the access key lacks editor or admin roles."""
    roles = get_access_key.get("roles") or []
    if not any(re.search(r"(?i)editor|admin", role) for role in roles):
        raise ValueError("You do not have required access to fetch incidents.")


# ? ---------------------------- CLIENT CLASS --------------------------------------


class Client(BaseClient):
    """
    Client Class For Vega API Integration
    """

    def __init__(
        self,
        base_url: str,
        verify: bool,
        proxy: bool,
        access_key: str,
        access_key_id: str = "",
    ):
        base_url = base_url.strip() if base_url else ""
        if base_url:
            base_url = base_url.rstrip("/")
            if not base_url.lower().endswith("/api/v1"):
                base_url = f"{base_url}/api/v1"
            base_url = f"{base_url}/"

        super().__init__(base_url=base_url, verify=verify, proxy=proxy)
        _suppress_noisy_http_integration_logs()
        self.access_key = access_key
        self.access_key_id = access_key_id
        self._session_jwt: str | None = None
        self._rate_limit_wait_seconds = RATE_LIMIT_INITIAL_WAIT_SECONDS

    def _reset_rate_limit_wait(self) -> None:
        """Reset the rate-limit backoff interval after a successful API call."""
        self._rate_limit_wait_seconds = RATE_LIMIT_INITIAL_WAIT_SECONDS

    def _sleep_before_rate_limit_retry(self, context: str, attempt: int) -> None:
        """Sleep using incremental backoff before retrying a transient Vega API request."""
        demisto.debug(
            f"Vega API transient error ({context}). Waiting {self._rate_limit_wait_seconds}s before retry "
            f"{attempt + 1}/{RATE_LIMIT_MAX_RETRIES}."
        )
        time.sleep(self._rate_limit_wait_seconds)  # pylint: disable=E9003
        self._rate_limit_wait_seconds += RATE_LIMIT_WAIT_INCREMENT_SECONDS

    def _http_request(self, *args, **kwargs):  # type: ignore[no-untyped-def]
        """Execute an HTTP request with retry handling for rate limits and transient gateway errors."""
        reset_backoff_on_success = kwargs.pop("reset_backoff_on_success", True)
        last_exc: Exception | None = None

        for attempt in range(RATE_LIMIT_MAX_RETRIES):
            try:
                response = super()._http_request(*args, **kwargs)
                if reset_backoff_on_success:
                    self._reset_rate_limit_wait()
                return response
            except Exception as exc:
                if not _is_retryable_http_error(exc):
                    raise
                last_exc = exc
                if attempt < RATE_LIMIT_MAX_RETRIES - 1:
                    status_code = _http_status_code(exc)
                    context = f"HTTP {status_code}" if status_code is not None else "network"
                    self._sleep_before_rate_limit_retry(context, attempt)

        if last_exc is not None:
            raise last_exc
        raise DemistoException("Vega API request failed after maximum retries.")

    def _authenticate(self) -> str:
        """Authenticate with the Vega API and return a session JWT token."""
        if self._session_jwt:
            return self._session_jwt

        login_res: dict = self._http_request(
            method="POST",
            url_suffix="login_machine",
            json_data={"access_key": self.access_key},
            resp_type="json",
            ok_codes=(200,),
        )

        session_jwt: str = login_res.get("session_jwt", "") if login_res else ""
        if not session_jwt:
            raise ValueError("Authentication failed: no session JWT received.")

        self._session_jwt = session_jwt
        return session_jwt

    def _auth_headers(self, session_jwt: str) -> dict[str, str]:
        """Build authentication headers for authenticated Vega API requests."""
        return {
            "JWTSessionToken": session_jwt,
            "X-Vega-Key-Id": self.access_key_id,
        }

    def _graphql_request(self, query: str, variables: dict | None = None) -> dict:
        """Execute a GraphQL query against the Vega API."""
        last_rate_limit_errors: list[Any] | None = None

        for attempt in range(RATE_LIMIT_MAX_RETRIES):
            response = self._post_graphql_query(query, variables)
            errors = response.get("errors")
            if not errors:
                self._reset_rate_limit_wait()
                return response

            if not _is_graphql_rate_limited(errors):
                raise DemistoException(f"GraphQL error: {errors}")

            last_rate_limit_errors = errors
            if attempt < RATE_LIMIT_MAX_RETRIES - 1:
                self._sleep_before_rate_limit_retry("GraphQL REQUEST_RATE_LIMITED", attempt)

        raise DemistoException(
            f"API rate limit exceeded after maximum retries. GraphQL error: {last_rate_limit_errors}. "
            f"Next wait interval would be {self._rate_limit_wait_seconds}s."
        )

    def _post_graphql_query(self, query: str, variables: dict | None) -> dict:
        """Authenticate and POST a single GraphQL query."""
        session_jwt = self._authenticate()
        json_data: dict[str, Any] = {"query": query}
        if variables:
            json_data["variables"] = variables

        response = self._http_request(
            method="POST",
            url_suffix="query",
            headers=self._auth_headers(session_jwt),
            json_data=json_data,
            resp_type="json",
            ok_codes=(200,),
            reset_backoff_on_success=False,
        )
        return response if isinstance(response, dict) else {}

    def _login_for_test_connection(self) -> str:
        """Authenticate during test-module and return the session JWT."""
        if not self._base_url or not str(self._base_url).strip():
            raise ValueError(TEST_CONNECTION_BASE_URL_ERROR)

        try:
            login_res: dict = self._http_request(
                method="POST",
                url_suffix="login_machine",
                json_data={"access_key": self.access_key},
                resp_type="json",
                ok_codes=(200,),
            )
        except Exception as exc:
            raise ValueError(_test_connection_error_message(exc, TEST_CONNECTION_ACCESS_KEY_ERROR)) from exc

        session_jwt: str = login_res.get("session_jwt", "") if login_res else ""
        if not session_jwt:
            raise ValueError("Authentication failed: no session token received. " "Please verify the Access Key and Base URL.")
        return session_jwt

    def _query_access_key_for_test_connection(self, session_jwt: str) -> dict:
        """Validate the configured access key ID during test-module."""
        query_data: dict = {
            "query": (
                "query GetAccessKey($id: String!) {  getAccessKey(id: $id) {    id    name    description    "
                "status    createdBy    createdAt    expireTime    roles    bindings {      role      "
                "scopeId      scopeName    }    secretValue  }}"
            ),
            "variables": {"id": self.access_key_id},
        }

        try:
            response = self._http_request(
                method="POST",
                url_suffix="query",
                headers=self._auth_headers(session_jwt),
                json_data=query_data,
                resp_type="response",
                ok_codes=(200,),
            )
            query_res = response.json()
        except Exception as exc:
            raise ValueError(_test_connection_error_message(exc, TEST_CONNECTION_ACCESS_KEY_ID_ERROR)) from exc

        errors = query_res.get("errors")
        get_access_key = (query_res.get("data") or {}).get("getAccessKey")
        if errors or get_access_key is None:
            raise ValueError(TEST_CONNECTION_ACCESS_KEY_ID_ERROR)

        _validate_test_connection_roles(get_access_key)
        return query_res

    def test_connection(self, backfill_days: str | int | None = None) -> dict:
        validate_backfill_days(backfill_days)
        session_jwt = self._login_for_test_connection()
        return self._query_access_key_for_test_connection(session_jwt)

    def get_alerts(
        self,
        severities: list[str] | None = None,
        statuses: list[str] | None = None,
        verdicts: list[str] | None = None,
        has_related_incidents: bool | None = None,
        from_time: str | None = None,
        updated_from: str | None = None,
        updated_to: str | None = None,
        alert_ids: list[str] | None = None,
        limit: int | None = None,
        offset: int = 0,
    ) -> dict:
        """Fetch alerts from the Vega API."""
        variables = _build_alerts_query_variables(
            severities=severities,
            statuses=statuses,
            verdicts=verdicts,
            has_related_incidents=has_related_incidents,
            from_time=from_time,
            updated_from=updated_from,
            updated_to=updated_to,
            alert_ids=alert_ids,
            limit=limit,
            offset=offset,
        )
        response = self._graphql_request(GET_ALERTS_QUERY, variables)
        raw_data = response.get("data")
        data: dict[str, Any] = raw_data if isinstance(raw_data, dict) else {}
        return data.get("getAlerts") or {}

    def get_alert_by_id(self, alert_id: str, *, from_time: str | None = None) -> dict:
        """Fetch a single Vega alert by ID."""
        response = self.get_alerts(alert_ids=[alert_id], from_time=from_time, limit=1) or {}
        alerts = response.get("alerts") or []
        if alerts:
            return _normalize_alert_api_entity(alerts[0])
        return {}

    def get_alert_for_mirror(self, alert_id: str, *, from_time: str | None = None) -> dict:
        """Fetch mirror-sync alert fields using a lightweight GraphQL query."""
        variables: dict[str, Any] = {"alertIds": [alert_id], "limit": 1, "offset": 0}
        if from_time:
            variables["from"] = from_time
        response = self._graphql_request(GET_ALERT_MIRROR_QUERY, variables)
        get_alerts = (response.get("data") or {}).get("getAlerts") or {}
        alerts = get_alerts.get("alerts") or []
        return alerts[0] if alerts else {}

    def get_incidents(
        self,
        severities: list[str] | None = None,
        statuses: list[str] | None = None,
        verdicts: list[str] | None = None,
        from_time: str | None = None,
        updated_from: str | None = None,
        updated_to: str | None = None,
        incident_ids: list[str] | None = None,
        limit: int | None = None,
        offset: int = 0,
    ) -> dict:
        """Fetch incidents from the Vega API."""
        variables = _build_incidents_query_variables(
            severities=severities,
            statuses=statuses,
            verdicts=verdicts,
            from_time=from_time,
            updated_from=updated_from,
            updated_to=updated_to,
            incident_ids=incident_ids,
            limit=limit,
            offset=offset,
        )
        response = self._graphql_request(GET_INCIDENTS_QUERY, variables)
        raw_data = response.get("data")
        data: dict[str, Any] = raw_data if isinstance(raw_data, dict) else {}
        return data.get("getIncidents") or {}

    def get_incident_by_id(
        self,
        incident_id: str,
        *,
        from_time: str | None = None,
    ) -> dict:
        """Fetch a single Vega incident by ID."""
        response = (
            self.get_incidents(
                incident_ids=[incident_id],
                from_time=from_time,
                limit=1,
            )
            or {}
        )
        incidents = response.get("incidents") or []
        if incidents:
            return _normalize_incident_api_entity(incidents[0])

        return {}

    def get_incident_for_mirror(
        self,
        incident_id: str,
        *,
        from_time: str | None = None,
    ) -> dict:
        """Fetch mirror-sync incident fields using a lightweight GraphQL query."""
        variables: dict[str, Any] = {"incidentIds": [incident_id], "limit": 1, "offset": 0}
        if from_time:
            variables["from"] = from_time
        response = self._graphql_request(GET_INCIDENT_MIRROR_QUERY, variables)
        get_incidents = (response.get("data") or {}).get("getIncidents") or {}
        incidents = get_incidents.get("incidents") or []
        return incidents[0] if incidents else {}

    def update_alerts(self, update_input: dict[str, Any]) -> dict:
        """Update one or more Vega alerts."""
        raw_response = self._graphql_request(UPDATE_ALERTS_MUTATION, {"input": update_input})
        response = raw_response if isinstance(raw_response, dict) else {}
        raw_data = response.get("data")
        data: dict[str, Any] = raw_data if isinstance(raw_data, dict) else {}
        result = data.get("updateAlerts") or {}
        api_error = result.get("error")
        if isinstance(api_error, dict) and api_error.get("message"):
            raise DemistoException(f"Vega API error updating alerts: {api_error.get('message')}")
        if not result:
            errors = response.get("errors")
            if errors:
                raise DemistoException(f"Vega API error updating alerts: {errors}")
        return result

    def update_incidents(self, update_input: dict[str, Any]) -> dict:
        """Update one or more Vega incidents."""
        raw_response = self._graphql_request(UPDATE_INCIDENTS_MUTATION, {"input": update_input})
        response = raw_response if isinstance(raw_response, dict) else {}
        raw_data = response.get("data")
        data: dict[str, Any] = raw_data if isinstance(raw_data, dict) else {}
        result = data.get("updateIncidents") or {}
        errors = result.get("errors") or []
        if errors:
            messages = [err.get("message", "") for err in errors if isinstance(err, dict)]
            raise DemistoException(f"Vega API error updating incidents: {', '.join(filter(None, messages))}")
        if not result:
            response_errors = response.get("errors")
            if response_errors:
                raise DemistoException(f"Vega API error updating incidents: {response_errors}")
        return result

    def get_incident_timeline(self, incident_id: str, limit: int = 100, offset: int = 0) -> dict:
        """Fetch timeline events for a Vega incident.

        Args:
            incident_id: Vega incident ID.
            limit: Maximum number of timeline events to return.
            offset: Pagination offset.

        Returns:
            The getIncidentTimeline response data.
        """
        response = self._graphql_request(
            GET_INCIDENT_TIMELINE_QUERY,
            {"incidentId": incident_id, "limit": limit, "offset": offset},
        )
        data = response.get("data") or {}
        result = data.get("getIncidentTimeline") or {}
        return result if isinstance(result, dict) else {}

    def get_alert_events(self, alert_id: str, limit: int | None = None, offset: int = 0) -> dict:
        """Fetch aggregated alert events for a Vega alert.

        Args:
            alert_id: Vega alert ID.
            limit: Maximum number of events per request.
            offset: Pagination offset.

        Returns:
            The getAlertsEvents response data.
        """
        variables: dict[str, Any] = {"alertId": alert_id, "offset": offset}
        if limit is not None:
            variables["limit"] = limit

        response = self._graphql_request(GET_ALERTS_EVENTS_QUERY, variables)
        data = response.get("data") or {}
        return data.get("getAlertsEvents") or {}

    def set_detections_state(self, detection_ids: list[str], state: str) -> dict:
        """Set the state for one or more Vega detections."""
        response = self._graphql_request(
            SET_DETECTIONS_STATE_MUTATION,
            {"input": {"ids": detection_ids, "state": state}},
        )
        data = response.get("data") or {}
        result = data.get("setDetectionsState") or {}
        return result if isinstance(result, dict) else {}

    def update_detections(self, detections: list[dict[str, Any]]) -> dict:
        """Update one or more Vega detections."""
        response = self._graphql_request(
            UPDATE_DETECTIONS_MUTATION,
            {"input": {"detections": detections}},
        )
        data = response.get("data") or {}
        result = data.get("updateDetections") or {}
        return result if isinstance(result, dict) else {}


# ? ---------------------------- CLIENT CLASS --------------------------------------


# ? ---------------------------- HELPER FUNCTIONS --------------------------------------
def _event_has_bad_alert_events_shape(event: dict) -> bool:
    """Return True when a getAlertsEvents row is vendor raw data identified by cid/eid fields."""
    if not event:
        return False
    return "cid" in event or "eid" in event


def _events_have_bad_alert_events_shape(events: list[dict]) -> bool:
    """Return True when getAlertsEvents results contain vendor raw rows instead of alert events."""
    return any(_event_has_bad_alert_events_shape(event) for event in events)


def _parse_alert_events_results(results: Any) -> list[dict]:
    """Normalize getAlertsEvents results into a list of event dicts."""
    if results is None:
        return []
    if isinstance(results, str):
        text = results.strip()
        if not text:
            return []
        try:
            parsed = json.loads(text)
        except json.JSONDecodeError:
            demisto.debug(f"Could not parse alert events results payload: {text[:200]!r}")
            return []
        if isinstance(parsed, list):
            return [item for item in parsed if isinstance(item, dict)]
        if isinstance(parsed, dict):
            return [parsed]
        return []
    if isinstance(results, list):
        return [item for item in results if isinstance(item, dict)]
    if isinstance(results, dict):
        return [results]
    return []


def _try_parse_json_value(value: Any) -> Any:
    """Parse JSON-encoded alert-event field values when Vega returns them as strings."""
    if not isinstance(value, str):
        return value
    text = value.strip()
    if not text or text[0] not in "{[":
        return value
    try:
        return json.loads(text)
    except (json.JSONDecodeError, TypeError, ValueError):
        return value


def _format_alert_events_cell_value(value: Any) -> str:
    """Format a single alert-event table cell for markdown display."""
    if value is None:
        return "—"
    if isinstance(value, list | dict):
        text = json.dumps(value, ensure_ascii=False)
    else:
        text = str(value).strip()
    if not text:
        return "—"
    if len(text) > ALERT_EVENT_MAX_CELL_LENGTH:
        return f"{text[: ALERT_EVENT_MAX_CELL_LENGTH - 3]}..."
    return text


def _flatten_alert_event_value(
    prefix: str,
    value: Any,
    flattened: dict[str, Any],
    *,
    depth: int = 0,
) -> None:
    """Flatten nested alert-event values into dot-notation keys for dynamic table columns."""
    if depth > ALERT_EVENT_MAX_FLATTEN_DEPTH:
        if prefix:
            flattened[prefix] = value
        return

    if isinstance(value, dict):
        if not value:
            if prefix:
                flattened[prefix] = value
            return
        for key, nested_value in value.items():
            nested_key = f"{prefix}.{key}" if prefix else str(key)
            _flatten_alert_event_value(nested_key, nested_value, flattened, depth=depth + 1)
        return

    if isinstance(value, list):
        if prefix:
            flattened[prefix] = value
        return

    if prefix:
        flattened[prefix] = value


def _normalize_alert_event_for_display(event: dict) -> dict[str, Any]:
    """Normalize a Vega alert event into flat, display-ready key/value pairs."""
    flattened: dict[str, Any] = {}
    for key, value in event.items():
        key_name = str(key)
        parsed_value = _try_parse_json_value(value)

        if key_name in ALERT_EVENT_JSON_TRUNCATE_KEYS:
            flattened[key_name] = parsed_value
            continue

        if key_name in ALERT_EVENT_JSON_MERGE_KEYS and isinstance(parsed_value, dict):
            _flatten_alert_event_value("", parsed_value, flattened, depth=0)
            continue

        _flatten_alert_event_value(key_name, parsed_value, flattened, depth=0)

    return flattened


def _alert_event_column_sort_key(column: str) -> tuple[int, int, str]:
    """Sort discovered columns with known fields first, then remaining keys alphabetically."""
    try:
        preferred_index = ALERT_EVENT_PREFERRED_COLUMNS.index(column)
        return (0, preferred_index, column)
    except ValueError:
        return (1, 0, column)


def _collect_alert_event_columns(normalized_events: list[dict[str, Any]]) -> list[str]:
    """Discover table columns from the alert events present in the current page."""
    discovered: set[str] = set()
    for event in normalized_events:
        for key, value in event.items():
            if _format_alert_events_cell_value(value) != "—":
                discovered.add(key)

    if not discovered:
        return []

    ordered = sorted(discovered, key=_alert_event_column_sort_key)
    return ordered[:ALERT_EVENT_MAX_COLUMNS]


def _alert_events_table_rows(events: list[dict]) -> tuple[list[str], list[dict[str, str]]]:
    """Convert Vega alert events to dynamic markdown table rows based on response shape."""
    normalized_events = [_normalize_alert_event_for_display(event) for event in events]
    headers = _collect_alert_event_columns(normalized_events)
    if not headers:
        return [], []

    rows: list[dict[str, str]] = []
    for normalized_event in normalized_events:
        row = {header: _format_alert_events_cell_value(normalized_event.get(header)) for header in headers}
        rows.append(row)
    return headers, rows


def _format_alert_events_markdown(
    events: list[dict],
    total: int,
    offset: int = 0,
    page_size: int | None = None,
) -> str:
    """Render Vega alert events as a markdown table for War Room and layout widgets."""
    if not events:
        return f"### Alert Events ({total})\n\nNo alert events are available for this alert."

    headers, rows = _alert_events_table_rows(events)
    if not headers:
        return f"### Alert Events ({total})\n\nNo displayable alert event fields were found in the Vega response."

    table_md = tableToMarkdown(
        f"Alert Events ({total})",
        rows,
        headers=headers,
        removeNull=False,
    )
    if page_size and total > page_size:
        current_page = (offset // page_size) + 1
        total_pages = max(1, math.ceil(total / page_size))
        table_md += f"\n\nPage {current_page} of {total_pages} " f"(showing {len(events)} of {total} events)"
    return table_md


def _alert_events_command_results(events_markdown: str, outputs: dict[str, Any]) -> CommandResults:
    """Return alert events as a rendered markdown table war-room entry."""
    return CommandResults(
        readable_output=events_markdown,
        outputs_prefix="Vega.AlertEvents",
        outputs_key_field="AlertId",
        outputs=outputs,
    )


def build_alert_events_custom_fields(
    alert_id: str,
    events_markdown: str,
    total: Any,
    offset: int = 0,
) -> dict[str, Any]:
    """Build incident CustomFields for the alert-events layout section."""
    custom_fields: dict[str, Any] = {
        "vegaalerteventsloadedfor": alert_id,
        "vegaalertevents": events_markdown,
        "vegaalerteventsoffset": offset,
    }
    if total is not None and str(total).strip() != "":
        try:
            custom_fields["vegaalerteventstotal"] = int(total)
        except (TypeError, ValueError):
            custom_fields["vegaalerteventstotal"] = total
    return custom_fields


def fetch_alert_events_page(
    client: Client,
    alert_id: str,
    limit: int = DEFAULT_ALERT_EVENTS_PAGE_SIZE,
    offset: int = 0,
) -> tuple[list[dict], int]:
    """Fetch a single page of alert events from the Vega API."""
    response = client.get_alert_events(alert_id, limit=limit, offset=offset)
    api_error = response.get("error")
    if isinstance(api_error, dict) and api_error.get("message"):
        raise DemistoException(f"Vega API error: {api_error.get('message')}")

    total_raw = response.get("total")
    try:
        total = int(total_raw) if total_raw is not None else 0
    except (TypeError, ValueError):
        total = 0

    events = _parse_alert_events_results(response.get("results"))
    if total == 0 and events:
        total = len(events)
    return events, total


def fetch_all_alert_events(
    client: Client,
    alert_id: str,
    page_limit: int = DEFAULT_ALERT_EVENTS_PAGE_SIZE,
) -> tuple[list[dict], int]:
    """Fetch all alert events using offset-based API pagination."""
    events: list[dict] = []
    offset = 0
    total = 0

    while True:
        page_events, page_total = fetch_alert_events_page(client, alert_id, limit=page_limit, offset=offset)
        if page_events and _events_have_bad_alert_events_shape(page_events):
            return [], 0
        if page_total > 0:
            total = page_total
        if not page_events:
            break

        events.extend(page_events)
        if total and offset + len(page_events) >= total:
            break
        if len(page_events) < page_limit:
            break
        offset += len(page_events)

    if total == 0:
        total = len(events)
    return events, total


def _fetch_alert_events_for_ingest(client: Client, alert_id: str) -> tuple[list[dict], dict[str, Any]]:
    """Fetch alert events for a Vega alert during incident ingest."""
    alert_id = str(alert_id).strip()
    try:
        all_events, total = fetch_all_alert_events(client, alert_id, page_limit=DEFAULT_ALERT_EVENTS_PAGE_SIZE)
        events_markdown, offset, _, has_alert_events = _resolve_alert_events_page(
            all_events,
            total,
            offset=0,
            page_limit=DEFAULT_ALERT_EVENTS_PAGE_SIZE,
        )
        custom_fields = build_alert_events_custom_fields(alert_id, events_markdown, total, offset)
        return (all_events if has_alert_events else []), custom_fields
    except Exception as exc:
        demisto.debug(f"Vega: skipped alert events fetch for {alert_id}: {exc}")
        return [], build_alert_events_custom_fields(alert_id, ALERT_EVENTS_NOT_AVAILABLE_MARKDOWN, 0, 0)


def _collect_incident_custom_fields(incident: dict[str, Any]) -> dict[str, Any]:
    """Merge incident CustomFields with flattened custom-field keys."""
    custom_fields: dict[str, Any] = dict(incident.get("CustomFields") or incident.get("customFields") or {})
    for field_name in (
        "alertid",
        "vegaalertid",
        "vegaincidentid",
        "vegaalerteventsloadedfor",
        "vegaalertevents",
        "vegaalerteventsoffset",
        "vegaalerteventstotal",
        VEGA_ALERT_STATUS_FIELD,
        VEGA_ALERT_SEVERITY_FIELD,
        VEGA_INCIDENT_STATUS_FIELD,
        "vegaverdict",
        "vegaverdictreasoning",
        VEGA_SEVERITY_FIELD,
    ):
        if field_name not in custom_fields and incident.get(field_name) is not None:
            custom_fields[field_name] = incident.get(field_name)
    return custom_fields


def load_current_incident() -> dict[str, Any]:
    """Load the current investigation incident from the integration runtime context."""
    incident: dict[str, Any] = {}
    try:
        incident = demisto.incident() or {}
    except (TypeError, AttributeError, KeyError) as exc:
        demisto.debug(f"Vega: demisto.incident() unavailable: {exc}")
    if not incident.get("id"):
        try:
            incidents = demisto.incidents()
            if incidents:
                incident = incidents[0] or {}
        except Exception as exc:
            demisto.debug(f"Vega: demisto.incidents() failed: {exc}")
    return incident


def resolve_alert_id_from_incident(args: dict[str, Any], incident: dict[str, Any]) -> str | None:
    """Resolve the Vega alert API id (UUID) used for API calls such as getAlertsEvents."""
    alert_ids = _collect_alert_ids_from_args(args)
    if alert_ids:
        return alert_ids[0]

    custom_fields = _collect_incident_custom_fields(incident)

    mapped_alert_id = custom_fields.get("alertid")
    if mapped_alert_id is not None and str(mapped_alert_id).strip():
        return str(mapped_alert_id).strip()

    loaded_for = custom_fields.get("vegaalerteventsloadedfor")
    if loaded_for is not None and str(loaded_for).strip():
        return str(loaded_for).strip()

    incident_type = str(incident.get("type") or incident.get("Type") or "").strip()
    raw_json = incident.get("rawJSON") or incident.get("rawJson")
    if raw_json:
        try:
            raw = json.loads(raw_json) if isinstance(raw_json, str) else raw_json
            if isinstance(raw, dict):
                if incident_type and incident_type != "Vega Alert":
                    return None
                if not incident_type and raw.get("vegaEntityType") not in (None, "Vega Alert"):
                    return None
                raw_id = raw.get("id")
                if raw_id is not None and str(raw_id).strip():
                    return str(raw_id).strip()
        except (json.JSONDecodeError, TypeError, ValueError):
            pass

    return None


def _resolve_alert_events_page(
    all_events: list[dict],
    total: int,
    offset: int,
    page_limit: int,
) -> tuple[str, int, list[dict], bool]:
    """Resolve pagination state and markdown for alert events."""
    has_alert_events = bool(all_events) and not _events_have_bad_alert_events_shape(all_events)
    if not has_alert_events:
        return ALERT_EVENTS_NOT_AVAILABLE_MARKDOWN, 0, [], False

    if offset >= total and total > 0:
        offset = max(0, total - page_limit)
        offset = (offset // page_limit) * page_limit
    page_events = all_events[offset : offset + page_limit]
    events_markdown = _format_alert_events_markdown(page_events, total, offset=offset, page_size=page_limit)
    return events_markdown, offset, page_events, True


def fetch_alert_events_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Fetch alert events for a Vega alert and return a markdown table for the layout section."""
    incident = load_current_incident()
    custom_fields = _collect_incident_custom_fields(incident)

    alert_id = resolve_alert_id_from_incident(args, incident)
    if not alert_id:
        incident_type = str(incident.get("type") or incident.get("Type") or "unknown")
        incident_id = incident.get("id") or "none"
        raise DemistoException(
            "alert_id is required when the command is not run from a Vega Alert incident. "
            f"Could not resolve alert ID from incident id={incident_id}, type={incident_type}. "
            "Open a Vega Alert investigation or pass alert_id explicitly."
        )

    alert_id = str(alert_id).strip()
    offset = arg_to_number(args.get("offset"))
    if offset is None:
        offset = arg_to_number(custom_fields.get("vegaalerteventsoffset")) or 0
    offset = max(0, int(offset))

    page_limit = arg_to_number(args.get("limit")) or DEFAULT_ALERT_EVENTS_PAGE_SIZE
    page_limit = max(1, int(page_limit))

    all_events, total = fetch_all_alert_events(client, alert_id, page_limit=page_limit)
    events_markdown, offset, page_events, has_alert_events = _resolve_alert_events_page(all_events, total, offset, page_limit)

    persisted_fields = build_alert_events_custom_fields(alert_id, events_markdown, total, offset)
    return _alert_events_command_results(
        events_markdown,
        {
            "AlertId": alert_id,
            "Total": total,
            "Offset": offset,
            "Limit": page_limit,
            "Count": len(page_events),
            "HasAlertEvents": has_alert_events,
            "Cached": False,
            "CustomFields": persisted_fields,
        },
    )


def set_detections_state_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Set the state for one or more Vega detections."""
    detection_ids = [item.strip() for item in argToList(args.get("ids")) if str(item).strip()]
    if not detection_ids:
        raise DemistoException("ids is required and must contain at least one detection ID.")

    state = str(args.get("state", "")).strip().upper()
    if not state:
        raise DemistoException("state is required.")
    if state not in VALID_DETECTION_STATES:
        raise DemistoException(f"state must be one of: {', '.join(sorted(VALID_DETECTION_STATES))}")

    result = client.set_detections_state(detection_ids, state)
    updated_ids = result.get("ids") or []
    if not isinstance(updated_ids, list):
        updated_ids = []

    readable_output = tableToMarkdown(
        f"Updated detection state to {state}",
        [{"ID": detection_id} for detection_id in updated_ids],
        headers=["ID"],
    )

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix="Vega.DetectionsState",
        outputs={
            "State": state,
            "IDs": updated_ids,
            "Count": len(updated_ids),
        },
    )


def _build_detection_update_payload(
    detection_id: str,
    severity: str | None = None,
    status: str | None = None,
    state: str | None = None,
    tags: list[str] | None = None,
) -> dict[str, Any]:
    """Build a single detection update payload for updateDetections."""
    payload: dict[str, Any] = {"detectionId": detection_id}
    if severity is not None:
        payload["severity"] = severity
    if status is not None:
        payload["status"] = status
    if state is not None:
        payload["state"] = state
    if tags is not None:
        payload["tags"] = tags
    return payload


def _raise_update_detections_errors(result: dict[str, Any]) -> None:
    """Raise when updateDetections returns per-detection validation errors."""
    error_messages: list[str] = []
    for item in result.get("results") or []:
        if not isinstance(item, dict):
            continue
        if item.get("status") == "VALID":
            continue
        detection_name = str(item.get("name") or "").strip()
        for error in item.get("errors") or []:
            if not isinstance(error, dict):
                continue
            message = str(error.get("message") or error.get("code") or "").strip()
            if not message:
                continue
            field = str(error.get("field") or "").strip()
            prefix = f"{detection_name}: " if detection_name else ""
            error_messages.append(f"{prefix}{field}: {message}" if field else f"{prefix}{message}")

    if error_messages:
        raise DemistoException(f"Vega API error updating detections: {', '.join(error_messages)}")

    summary = result.get("summary") or {}
    if isinstance(summary, dict) and summary.get("committed") is False:
        raise DemistoException("Vega API did not commit detection updates.")


def _format_update_detection_output(result_item: dict[str, Any]) -> dict[str, Any]:
    """Format a single updateDetections result item for command outputs."""
    detection_raw = result_item.get("detection")
    detection: dict[str, Any] = detection_raw if isinstance(detection_raw, dict) else {}
    return {
        "ID": detection.get("id"),
        "Name": detection.get("name") or result_item.get("name"),
        "Severity": detection.get("severity"),
        "Status": detection.get("status"),
        "State": detection.get("state"),
        "Tags": detection.get("tags"),
        "ValidationStatus": result_item.get("status"),
    }


def _parse_detection_update_args(
    args: dict[str, Any],
) -> tuple[list[str], str | None, str | None, str | None, list[str] | None]:
    """Parse and normalize detection update command arguments."""
    detection_ids = [item.strip() for item in argToList(args.get("detection_id")) if str(item).strip()]
    severity_arg = args.get("severity")
    status_arg = args.get("status")
    state_arg = args.get("state")
    tags_arg = args.get("tags")
    severity = str(severity_arg or "").strip().upper() if severity_arg not in (None, "") else None
    status = str(status_arg or "").strip().upper() if status_arg not in (None, "") else None
    state = str(state_arg).strip().upper() if state_arg not in (None, "") else None
    tags = [item.strip() for item in argToList(tags_arg) if str(item).strip()] or None
    return detection_ids, severity, status, state, tags


def _validate_detection_update_args(
    detection_ids: list[str],
    severity: str | None,
    status: str | None,
    state: str | None,
    tags: list[str] | None,
) -> None:
    """Validate detection update command arguments."""
    if not detection_ids:
        raise DemistoException(
            "detection_id is required and must contain at least one detection ID. "
            "Example: !vega-update-detections detection_id=det-1 severity=HIGH state=ENABLED"
        )
    if severity is None and status is None and state is None and tags is None:
        raise DemistoException("At least one of severity, status, state, or tags must be provided.")
    if severity is not None and severity not in VALID_DETECTION_SEVERITIES:
        raise DemistoException(f"severity must be one of: {', '.join(sorted(VALID_DETECTION_SEVERITIES))}")
    if state is not None and state not in VALID_DETECTION_STATES:
        raise DemistoException(f"state must be one of: {', '.join(sorted(VALID_DETECTION_STATES))}")


def _format_detection_update_readable(outputs: list[dict[str, Any]], summary: dict[str, Any]) -> str:
    """Build human-readable output for detection update results."""
    readable = tableToMarkdown(
        "Updated Vega Detections",
        outputs,
        headers=["ID", "Name", "Severity", "Status", "State", "Tags", "ValidationStatus"],
        removeNull=True,
    )
    if not summary:
        return readable
    return (
        readable
        + "\n\n"
        + tableToMarkdown(
            "Update Summary",
            [
                {
                    "Requested": summary.get("requested"),
                    "Valid": summary.get("valid"),
                    "Invalid": summary.get("invalid"),
                    "Committed": summary.get("committed"),
                }
            ],
            headers=["Requested", "Valid", "Invalid", "Committed"],
            removeNull=True,
        )
    )


def update_detections_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Update severity, status, state, and/or tags for one or more Vega detections."""
    detection_ids, severity, status, state, tags = _parse_detection_update_args(args)
    _validate_detection_update_args(detection_ids, severity, status, state, tags)

    detections = [_build_detection_update_payload(detection_id, severity, status, state, tags) for detection_id in detection_ids]
    result = client.update_detections(detections)
    _raise_update_detections_errors(result)

    outputs = [_format_update_detection_output(item) for item in result.get("results") or [] if isinstance(item, dict)]
    raw_summary = result.get("summary")
    summary: dict[str, Any] = raw_summary if isinstance(raw_summary, dict) else {}

    return CommandResults(
        readable_output=_format_detection_update_readable(outputs, summary),
        outputs_prefix="Vega.Detection",
        outputs_key_field="ID",
        outputs=outputs[0] if len(outputs) == 1 else outputs,
    )


def _normalize_list_items(value: Any) -> list[str]:
    """Extract string items from a list or scalar field value."""
    if isinstance(value, str):
        text = value.strip()
        return [text] if text else []
    if not isinstance(value, list):
        return []
    items: list[str] = []
    for item in value:
        if item is None:
            continue
        if isinstance(item, dict):
            label = _mitre_item_label(item)
            if label:
                items.append(label)
            else:
                items.append(json.dumps(item))
        else:
            text = str(item).strip()
            if text:
                items.append(text)
    return items


def _format_bullet_list(value: Any, empty_display: str | None = None) -> Any:
    """Format a list field as newline-separated bullet points."""
    if value is None or not isinstance(value, list) or not value:
        return empty_display if empty_display is not None else value
    items = _normalize_list_items(value)
    if not items:
        return empty_display if empty_display is not None else value
    return "\n".join(f"• {item}" for item in items)


VEGA_EMPTY_FIELD_DISPLAY = "N/A"
VEGA_NO_ASSETS_DISPLAY = "No assets present."
VEGA_NO_OBSERVABLES_DISPLAY = "No observables present."


def _empty_to_na(value: Any) -> str:
    """Return a display placeholder when a Vega text field is missing or blank."""
    if value is None:
        return VEGA_EMPTY_FIELD_DISPLAY
    text = str(value).strip()
    return text if text else VEGA_EMPTY_FIELD_DISPLAY


def _extract_verdict_reasoning_from_entity(raw: dict[str, Any]) -> Any:
    """Extract analyst verdict reasoning from the Vega ``verdictReasoning`` API field only."""
    reasoning = raw.get("verdictReasoning")
    if reasoning is None:
        return None
    text = str(reasoning).strip()
    return None if not text or text.upper() == VEGA_EMPTY_FIELD_DISPLAY.upper() else reasoning


def _normalize_verdict_reasoning_for_display(raw: dict) -> str:
    """Normalize Vega verdict reasoning for XSOAR display."""
    reasoning = _extract_verdict_reasoning_from_entity(raw)
    return _empty_to_na(reasoning)


def _format_vega_detection_query_for_display(value: Any) -> str:
    """Format a detection SQL query for markdown display, or N/A when empty."""
    query = _empty_to_na(value)
    if query == VEGA_EMPTY_FIELD_DISPLAY:
        return query
    return f"```sql\n{query}\n```"


def _mitre_item_label(item: dict) -> str:
    """Extract a display label from a MITRE tactic/technique object."""
    for key in ("name", "displayName", "techniqueName", "tacticName", "id", "techniqueId", "tacticId"):
        value = item.get(key)
        if value is not None and str(value).strip():
            return str(value).strip()
    return ""


def _get_first_mitre_value(mitre: dict, keys: tuple[str, ...]) -> Any:
    """Return the first present MITRE tactic/technique value from supported API key names."""
    for key in keys:
        if key in mitre and mitre.get(key) is not None:
            return mitre.get(key)
    return None


def _format_mitre_attack(mitre: Any) -> str | None:
    """Merge MITRE tactics and techniques into a newline-separated bullet list."""
    if not isinstance(mitre, dict):
        return None
    tactics = _get_first_mitre_value(mitre, MITRE_TACTIC_KEYS)
    techniques = _get_first_mitre_value(mitre, MITRE_TECHNIQUE_KEYS)
    items = _normalize_list_items(tactics) + _normalize_list_items(techniques)
    if not items:
        return None
    return "\n".join(f"• {item}" for item in items)


def _apply_vega_mitre_attack_format(raw: dict) -> None:
    """Populate vegaMitreAttack in raw JSON for visibility in the incident context."""
    mitre = raw.get("mitre")
    if isinstance(mitre, dict):
        mitre_payload: dict[str, Any] = mitre
    elif raw.get("mitreTactics") is not None or raw.get("mitreTechniques") is not None:
        mitre_payload = {
            "mitreTactics": raw.get("mitreTactics"),
            "mitreTechniques": raw.get("mitreTechniques"),
        }
    else:
        return

    mitre_attack = _format_mitre_attack(mitre_payload)
    if mitre_attack:
        raw["vegaMitreAttack"] = mitre_attack


def _build_vega_alert_custom_fields(raw: dict) -> dict[str, Any]:
    """Build CustomFields for Vega alerts (set directly on ingest, not via mapper)."""
    custom_fields: dict[str, Any] = {}
    alert_uuid = raw.get("id")
    if alert_uuid is not None and str(alert_uuid).strip():
        custom_fields["alertid"] = str(alert_uuid).strip()
    mitre_attack = raw.get("vegaMitreAttack")
    if mitre_attack:
        custom_fields["vegamitreattack"] = str(mitre_attack)
    created_at = raw.get("createdAt")
    if created_at:
        custom_fields["vegacreatedat"] = str(created_at)
    alert_event_fields = raw.get("_alertEventsCustomFields")
    if isinstance(alert_event_fields, dict):
        custom_fields.update(alert_event_fields)
    custom_fields[VEGA_NEW_COMMENT_FIELD] = VEGA_NEW_COMMENT_LAYOUT_DEFAULT
    return custom_fields


def _timeline_alert_severity_label(severity: Any) -> str:
    """Map Vega numeric alert severity to a human-readable label."""
    if severity is None:
        return "N/A"
    try:
        return VEGA_TIMELINE_ALERT_SEVERITY_LABELS.get(int(severity), str(severity))
    except (TypeError, ValueError):
        return str(severity)


def _escape_html(text: str) -> str:
    """Escape text for safe inclusion in timeline HTML."""
    return html_module.escape(str(text))


def _format_timeline_display_timestamp(timestamp: Any) -> str:
    """Convert an ISO timestamp to the timeline display format (YYYY-MM-DD HH:MM:SS)."""
    text = str(timestamp or "").strip()
    if not text:
        return "—"
    text = text.replace("T", " ").replace("Z", "").strip()
    if "." in text:
        text = text.split(".", maxsplit=1)[0]
    return text


def _format_comment_display_timestamp(timestamp: Any) -> str:
    """Convert an ISO timestamp to the comment display format (YYYY-MM-DDTHH:MM:SSZ)."""
    text = str(timestamp or "").strip()
    if not text:
        return "—"
    if "." in text:
        text = text.split(".", maxsplit=1)[0]
    if "T" not in text and " " in text:
        text = text.replace(" ", "T", 1)
    if not text.endswith("Z") and "+" not in text:
        text = f"{text}Z"
    return text


def _is_empty_vega_comment_text(text: Any) -> bool:
    """Return True when a Vega comment body is empty or a placeholder such as '[{}]'."""
    if text is None:
        return True
    normalized = str(text).strip()
    return not normalized or normalized in ("[{}]", "[]", "{}")


def _format_comment_author(added_by: Any) -> str:
    """Return a display name for a Vega comment author."""
    author = str(added_by or "").strip()
    if not author:
        return "Unknown"
    if len(author) > 24 and " " not in author:
        return "Unknown"
    return _escape_html(author)


def _format_vega_comment_item_html(comment: dict[str, Any]) -> str:
    """Render one Vega incident comment in the dark UI card layout."""
    comment_text = str(comment.get("text") or "").strip()
    author = _format_comment_author(comment.get("addedBy"))
    timestamp = _escape_html(_format_comment_display_timestamp(comment.get("addedAt")))
    body = _escape_html(comment_text)
    return (
        "<div style='margin-bottom:20px;'>"
        "<div style='display:flex;align-items:center;gap:8px;margin-bottom:10px;color:#ffffff;'>"
        f"<span style='font-size:14px;line-height:1.4;'>"
        f"<span style='font-weight:600;color:#ffffff;'>{author}</span> "
        f"<span style='color:#d1d5db;'>added a comment</span></span></div>"
        f"<div style='border:1px solid #404040;border-radius:10px;padding:12px 14px;"
        f"background:#141414;color:#e5e5e5;font-size:13px;line-height:1.6;'>{body}</div>"
        f"<div style='color:#9ca3af;font-size:12px;margin-top:8px;'>{timestamp}</div>"
        "</div>"
    )


def _format_vega_comments_html(comments: Any) -> str:
    """Render Vega incident comments as HTML, skipping empty placeholder entries."""
    container_style = f"background:#000000;color:#ffffff;padding:16px;font-family:{_VEGA_DARK_UI_FONT};"
    if not isinstance(comments, list):
        return (
            f"<div style='{container_style}'>"
            "<p style='margin:0;color:#9ca3af;font-size:13px;'>No comments are available for this incident.</p>"
            "</div>"
        )

    visible_comments = [
        comment for comment in comments if isinstance(comment, dict) and not _is_empty_vega_comment_text(comment.get("text"))
    ]
    visible_comments.sort(key=lambda item: str(item.get("addedAt") or ""), reverse=True)

    if not visible_comments:
        return (
            f"<div style='{container_style}'>"
            "<p style='margin:0;color:#9ca3af;font-size:13px;'>No comments are available for this incident.</p>"
            "</div>"
        )

    rows = "".join(_format_vega_comment_item_html(comment) for comment in visible_comments)
    return f"<div style='{container_style}'>{rows}</div>"


def _timeline_severity_bars_html(severity: Any) -> str:
    """Render alert severity as vertical bars (Vega UI style)."""
    try:
        level = max(1, min(4, int(severity)))
    except (TypeError, ValueError):
        level = 2
    bar_heights = (8, 11, 14, 16)
    bars: list[str] = []
    for index, height in enumerate(bar_heights, start=1):
        color = "#f97316" if index <= level else "#404040"
        bars.append(f"<div style='width:4px;height:{height}px;background:{color};border-radius:1px;'></div>")
    return f"<div style='display:flex;gap:2px;align-items:flex-end;'>{''.join(bars)}</div>"


_TIMELINE_PILL_STYLE = (
    "display:inline-block;padding:4px 10px;border-radius:999px;"
    "background:#2a2a2a;border:1px solid #404040;color:#f5f5f5;"
    "font-size:11px;line-height:1.4;white-space:normal;max-width:100%;"
)

_VEGA_DARK_UI_FONT = "-apple-system,BlinkMacSystemFont,Segoe UI,Roboto,Helvetica,Arial,sans-serif"

_KEY_FINDINGS_NUMBER_STYLE = (
    "display:flex;align-items:center;justify-content:center;flex-shrink:0;"
    "width:28px;height:28px;background:#141414;border:1px solid #333333;"
    "border-radius:8px;color:#9ca3af;font-size:12px;font-weight:600;"
)


def _timeline_data_source_label(source: dict) -> str:
    """Build the full display name for a timeline data source."""
    vendor = str(source.get("vendor", "")).strip()
    display_name = str(source.get("displayName", "")).strip()
    if vendor and display_name:
        return f"{vendor} · {display_name}"
    if display_name:
        return display_name
    if vendor:
        return vendor
    return ""


def _timeline_string_pill_html(value: str) -> str:
    """Render a timeline footer pill for a plain string value."""
    label = str(value).strip()
    if not label:
        return ""
    return f"<span style='{_TIMELINE_PILL_STYLE}'>{_escape_html(label)}</span>"


def _timeline_footer_data_source_pills(event: dict) -> list[str]:
    """Build timeline footer pills for data source values."""
    parts: list[str] = []
    data_sources = event.get("dataSources")
    if not isinstance(data_sources, list):
        return parts

    for source in data_sources:
        if isinstance(source, dict):
            label = _timeline_data_source_label(source)
            if label:
                parts.append(_timeline_string_pill_html(label))
        elif isinstance(source, str):
            pill = _timeline_string_pill_html(source)
            if pill:
                parts.append(pill)
    return parts


def _timeline_footer_alert_severity_pill(alert: dict) -> str | None:
    """Build a timeline footer pill for alert severity."""
    if alert.get("displayName") or alert.get("severity") is not None:
        severity_label = _timeline_alert_severity_label(alert.get("severity"))
        return f"<span style='{_TIMELINE_PILL_STYLE}'>Severity: {_escape_html(severity_label)}</span>"
    return None


def _timeline_footer_list_pills(event: dict, key: str) -> list[str]:
    """Build timeline footer pills from a list of string values on an event."""
    parts: list[str] = []
    values = event.get(key)
    if not isinstance(values, list):
        return parts
    for value in values:
        if isinstance(value, str):
            pill = _timeline_string_pill_html(value)
            if pill:
                parts.append(pill)
    return parts


def _timeline_footer_entity_pills(event: dict) -> list[str]:
    """Build timeline footer pills for entity metadata."""
    parts: list[str] = []
    entities = event.get("entities")
    if not isinstance(entities, list):
        return parts

    for entity in entities:
        if not isinstance(entity, dict):
            continue
        entity_type = str(entity.get("type", "")).strip()
        category = str(entity.get("category", "")).strip()
        value = str(entity.get("value", "")).strip()
        if not value:
            continue
        meta_parts = [part for part in (entity_type, category) if part]
        pill_text = f"{value} ({', '.join(meta_parts)})" if meta_parts else value
        parts.append(_timeline_string_pill_html(pill_text))
    return parts


def _timeline_footer_html(event: dict) -> str:
    """Build footer badges (data sources, severity, assets, observables) for a timeline event."""
    parts = _timeline_footer_data_source_pills(event)

    alert = event.get("alert")
    if isinstance(alert, dict):
        severity_pill = _timeline_footer_alert_severity_pill(alert)
        if severity_pill:
            parts.append(severity_pill)

    parts.extend(_timeline_footer_list_pills(event, "assets"))
    parts.extend(_timeline_footer_list_pills(event, "observables"))
    parts.extend(_timeline_footer_entity_pills(event))

    if not parts:
        return ""

    return f"<div style='display:flex;flex-wrap:wrap;gap:8px;align-items:center;margin-top:12px;'>" f"{''.join(parts)}</div>"


def _timeline_axis_html(is_last: bool) -> str:
    """Render the vertical timeline axis (line only; Vega API has no timeline event type field)."""
    line_bottom = "bottom:0;" if is_last else "bottom:-28px;"
    return (
        f"<div style='width:20px;flex-shrink:0;position:relative;align-self:stretch;min-height:20px;'>"
        f"<div style='position:absolute;left:50%;top:0;width:2px;{line_bottom}"
        f"background:#404040;transform:translateX(-50%);'></div></div>"
    )


def _timeline_event_row_html(event: dict, is_last: bool) -> str:
    """Render a single timeline row (timestamp, axis line, content)."""
    timestamp = _escape_html(_format_timeline_display_timestamp(event.get("timestamp")))
    summary = _escape_html(str(event.get("summary", "")).strip() or "No summary provided.")
    alert_data = event.get("alert")
    content_parts: list[str] = []
    if isinstance(alert_data, dict):
        alert_name_value = str(alert_data.get("name") or alert_data.get("displayName") or "").strip()
        if alert_name_value:
            alert_name = _escape_html(alert_name_value)
            severity_bars = _timeline_severity_bars_html(alert_data.get("severity"))
            content_parts.append(
                f"<div style='display:inline-flex;align-items:center;gap:10px;"
                f"background:#141414;border:1px solid #333333;border-radius:10px;"
                f"padding:10px 14px;margin-bottom:12px;max-width:100%;'>"
                f"{severity_bars}"
                f"<span style='color:#ffffff;font-size:14px;font-weight:600;line-height:1.4;'>"
                f"{alert_name}</span></div>"
            )

    content_parts.append(f"<p style='margin:0;color:#e5e5e5;font-size:13px;line-height:1.65;'>{summary}</p>")
    footer = _timeline_footer_html(event)
    if footer:
        content_parts.append(footer)

    return (
        f"<div style='display:flex;align-items:stretch;margin-bottom:28px;position:relative;'>"
        f"<div style='width:148px;flex-shrink:0;text-align:right;padding-right:14px;"
        f"padding-top:2px;color:#9ca3af;font-size:12px;font-family:monospace;'>{timestamp}</div>"
        f"{_timeline_axis_html(is_last)}"
        f"<div style='flex:1;min-width:0;padding-left:12px;padding-top:0;'>"
        f"{''.join(content_parts)}</div></div>"
    )


def _format_timeline_events_html(timeline_events: list[dict]) -> str:
    """Render Vega incident timeline as HTML (dark theme, three-column layout)."""
    if not timeline_events:
        return (
            "<div style='background:#000000;color:#ffffff;padding:16px;font-family:"
            "-apple-system,BlinkMacSystemFont,Segoe UI,Roboto,Helvetica,Arial,sans-serif;'>"
            "<div style='font-size:15px;font-weight:600;margin-bottom:8px;'>Timeline</div>"
            "<p style='margin:0;color:#9ca3af;font-size:13px;'>"
            "No timeline events are available for this incident.</p></div>"
        )

    sorted_events = sorted(
        timeline_events,
        key=lambda event: str(event.get("timestamp", "")),
    )
    rows = [_timeline_event_row_html(event, is_last=index == len(sorted_events) - 1) for index, event in enumerate(sorted_events)]

    return (
        "<div style='background:#000000;color:#ffffff;padding:16px 16px 8px 16px;"
        "font-family:-apple-system,BlinkMacSystemFont,Segoe UI,Roboto,Helvetica,Arial,sans-serif;'>"
        "<div style='font-size:15px;font-weight:600;margin-bottom:20px;color:#ffffff;'>"
        "Timeline</div>"
        f"<div style='position:relative;'>{''.join(rows)}</div></div>"
    )


def _build_vega_incident_custom_fields(raw: dict) -> dict[str, str]:
    """Build CustomFields for Vega incidents (set directly on ingest, not via mapper)."""
    custom_fields: dict[str, str] = {}
    # Populate vegaincidentid so outgoing mirroring and vega-update-incident can reliably
    # resolve the Vega entity without falling back to fragile rawJSON parsing.
    incident_id = _normalize_entity_id(raw)
    if incident_id:
        custom_fields["vegaincidentid"] = incident_id
    created_at = raw.get("createdAt")
    if created_at:
        custom_fields["vegacreatedat"] = str(created_at)
    timeline_html = raw.get("vegaTimelineEvents")
    if timeline_html:
        custom_fields["vegatimelineevents"] = str(timeline_html)
    findings_html = raw.get("vegaIncidentFindings")
    if findings_html:
        custom_fields["vegaincidentfindings"] = str(findings_html)
    custom_fields[VEGA_NEW_COMMENT_FIELD] = VEGA_NEW_COMMENT_LAYOUT_DEFAULT
    return custom_fields


def _normalize_findings_list(findings: Any) -> list[str]:
    """Extract non-empty finding strings from API data."""
    if findings is None or not isinstance(findings, list):
        return []
    texts: list[str] = []
    for finding in findings:
        text = json.dumps(finding) if isinstance(finding, dict) else str(finding).strip()
        if text:
            texts.append(text)
    return texts


def _highlight_values_in_html(text: str, values: set[str]) -> str:
    """Wrap occurrences of known asset/observable values in timeline-style pills."""
    escaped = _escape_html(text)
    if not values:
        return escaped
    result = escaped
    for value in sorted(values, key=len, reverse=True):
        if not value:
            continue
        escaped_value = _escape_html(value)
        if escaped_value not in result:
            continue
        pill = f"<span style='{_TIMELINE_PILL_STYLE}'>{escaped_value}</span>"
        result = result.replace(escaped_value, pill)
    return result


def _key_finding_item_html(number: int, text: str, highlight_values: set[str], is_last: bool) -> str:
    """Render one numbered key finding row (screenshot-style layout, dark theme)."""
    body = _highlight_values_in_html(text, highlight_values)
    border = "" if is_last else "border-bottom:1px solid #333333;"
    return (
        f"<div style='display:flex;gap:14px;padding:16px 0;{border}align-items:flex-start;'>"
        f"<div style='{_KEY_FINDINGS_NUMBER_STYLE}'>{number}</div>"
        f"<p style='margin:0;flex:1;color:#e5e5e5;font-size:13px;line-height:1.65;'>{body}</p>"
        f"</div>"
    )


def _format_key_findings_html(findings: Any, assets: Any, observables: Any) -> str:
    """Render Vega key findings as HTML (black background, numbered list, entity pills)."""
    finding_texts = _normalize_findings_list(findings)
    highlight_values = set(_normalize_list_items(assets) + _normalize_list_items(observables))
    header = "<div style='font-size:15px;font-weight:600;margin-bottom:4px;color:#ffffff;'>" "Key findings</div>"
    container_style = f"background:#000000;color:#ffffff;padding:16px;" f"font-family:{_VEGA_DARK_UI_FONT};"

    if not finding_texts:
        return (
            f"<div style='{container_style}'>"
            f"{header}"
            f"<p style='margin:8px 0 0;color:#9ca3af;font-size:13px;'>"
            f"No key findings are available for this incident.</p></div>"
        )

    rows = [
        _key_finding_item_html(
            index,
            text,
            highlight_values,
            is_last=index == len(finding_texts),
        )
        for index, text in enumerate(finding_texts, start=1)
    ]
    return f"<div style='{container_style}'>{header}{''.join(rows)}</div>"


def _api_to_app_url(url: str) -> str:
    """Replace the api host subdomain with app in a Vega platform URL."""
    return url.strip().replace("://api.", "://app.")


def _platform_ui_base_url(integration_url: str) -> str:
    """Derive the Vega app UI base URL from the configured integration URL."""
    base = integration_url.rstrip("/")
    if base.lower().endswith("/api/v1"):
        base = base[: -len("/api/v1")]
    return _api_to_app_url(base)


def _apply_vega_entity_link(raw: dict, integration_url: str | None = None) -> None:
    """Normalize or build Vega platform UI links before XSOAR ingestion."""
    api_link = raw.get("link")
    if api_link:
        raw["link"] = _api_to_app_url(str(api_link))
        return

    entity_type = raw.get("vegaEntityType")
    entity_id = raw.get("id", "")
    if entity_type == "Vega Alert" and entity_id and integration_url:
        platform_base = _platform_ui_base_url(integration_url)
        raw["link"] = f"{platform_base.rstrip('/')}/incidents/alerts/investigation/{entity_id}"


def _format_raw_entity_for_xsoar(raw: dict) -> None:
    """Format display-oriented list fields in raw entity data before XSOAR ingestion."""
    entity_type = raw.get("vegaEntityType")
    if entity_type == "Vega Alert" and raw.get("status") is not None:
        raw["status"] = _normalize_vega_status_for_display(str(raw["status"]), MIRROR_ENTITY_SUFFIX_ALERT)
    elif entity_type == "Vega Incident" and raw.get("status") is not None:
        raw["status"] = _normalize_vega_status_for_display(str(raw["status"]), MIRROR_ENTITY_SUFFIX_INCIDENT)

    if raw.get("verdict") is not None or raw.get("userVerdict") is not None:
        raw["verdict"] = _normalize_vega_verdict_for_display(_extract_vega_verdict_from_entity(raw))

    raw["verdictReasoning"] = _normalize_verdict_reasoning_for_display(raw)

    if raw.get("severity") is not None:
        raw["severity"] = _normalize_vega_severity_for_display(raw.get("severity"))

    if entity_type == "Vega Alert":
        vega_display_id = raw.get("vegaAlertId")
        if vega_display_id is not None and str(vega_display_id).strip():
            raw["vegaAlertId"] = str(vega_display_id).strip()
        raw["detectionDescription"] = _empty_to_na(raw.get("detectionDescription"))
        raw["detectionQuery"] = _format_vega_detection_query_for_display(raw.get("detectionQuery"))

    if "dataSources" in raw:
        raw["dataSources"] = _format_bullet_list(raw.get("dataSources"))

    assets = raw.get("assets")
    observables = raw.get("observables")

    if "assets" in raw:
        raw["assets"] = _format_bullet_list(assets, VEGA_NO_ASSETS_DISPLAY)
    if "observables" in raw:
        raw["observables"] = _format_bullet_list(observables, VEGA_NO_OBSERVABLES_DISPLAY)
    findings_source = raw.get("keyFindings") or raw.get("incidentFindings")
    if findings_source is not None:
        raw["vegaIncidentFindings"] = _format_key_findings_html(findings_source, assets, observables)
    if entity_type in ("Vega Incident", "Vega Alert") and "comments" in raw:
        raw["vegaComments"] = _format_vega_comments_html(raw.get("comments"))
    _apply_vega_mitre_attack_format(raw)


def _normalize_incident_verdict_value(verdict: Any) -> str:
    """Normalize a Vega incident verdict to a string for XSOAR mapping."""
    if isinstance(verdict, dict):
        return str(verdict.get("value") or verdict.get("verdict") or "")
    return str(verdict or "")


def _extract_vega_verdict_from_entity(entity: dict[str, Any]) -> Any:
    """Extract the analyst-facing verdict, preferring userVerdict over automated state verdict."""
    user_verdict = entity.get("userVerdict")
    if user_verdict is not None:
        if isinstance(user_verdict, dict):
            value = user_verdict.get("value") or user_verdict.get("verdict")
            if value is not None and str(value).strip():
                return value
        elif str(user_verdict).strip():
            return user_verdict
    return entity.get("verdict")


def _normalize_vega_verdict_for_display(verdict: Any) -> str:
    """Normalize a Vega verdict to a value accepted by the XSOAR single-select field."""
    normalized = _normalize_incident_verdict_value(verdict).strip().upper()
    return VERDICT_DISPLAY_TO_API.get(normalized, normalized)


def _normalize_vega_severity_for_display(severity: Any) -> str:
    """Normalize a Vega severity to a value accepted by the XSOAR single-select field."""
    if severity is None or severity == "":
        return ""
    if isinstance(severity, int | float) or (isinstance(severity, str) and str(severity).strip().isdigit()):
        mapped = VEGA_NUMERIC_SEVERITY_TO_API.get(int(float(str(severity).strip())))
        if mapped:
            return mapped
    normalized = str(severity or "").strip().upper()
    return normalized if normalized in VALID_SEVERITIES else normalized


def _normalize_vega_status_for_api(status: str, entity_type: str) -> str:
    """Map a Vega status value to the GraphQL API enum format."""
    normalized = str(status or "").strip().upper()
    if entity_type == MIRROR_ENTITY_SUFFIX_ALERT:
        return ALERT_STATUS_DISPLAY_TO_API.get(normalized, normalized.replace(" ", "_"))
    return INCIDENT_STATUS_DISPLAY_TO_API.get(normalized, normalized.replace(" ", "_"))


def _normalize_vega_status_for_display(status: str, entity_type: str) -> str:
    """Map a Vega API status value to the human-readable dropdown format."""
    normalized = str(status or "").strip().upper()
    if entity_type == MIRROR_ENTITY_SUFFIX_ALERT:
        api_to_display = {api: display for display, api in ALERT_STATUS_DISPLAY_TO_API.items()}
    else:
        api_to_display = {api: display for display, api in INCIDENT_STATUS_DISPLAY_TO_API.items()}
    return api_to_display.get(normalized, normalized.replace("_", " "))


def _normalize_vega_verdict_for_api(verdict: str) -> str:
    """Map a Vega verdict value to the GraphQL API enum format."""
    normalized = str(verdict or "").strip().upper()
    return VERDICT_DISPLAY_TO_API.get(normalized, normalized)


def _build_close_reopen_sync_entries(status: str, entity_type_suffix: str) -> list[dict]:
    """Build close or reopen entries when syncing XSOAR investigation status."""
    entries: list[dict] = []
    api_status = _normalize_vega_status_for_api(status, entity_type_suffix)
    if api_status in VEGA_CLOSE_STATUSES:
        entries.append(
            {
                "Type": EntryType.NOTE,
                "Contents": {
                    "dbotIncidentClose": True,
                    "closeReason": "Resolved",
                    "closeNotes": f"Vega {entity_type_suffix} status changed to {api_status}.",
                },
                "ContentsFormat": EntryFormat.JSON,
                "Note": True,
            }
        )
    elif api_status in {"REOPENED", "OPEN", "NEW", "INVESTIGATING", "IN_PROGRESS"}:
        entries.append(
            {
                "Type": EntryType.NOTE,
                "Contents": {"dbotIncidentReopen": True},
                "ContentsFormat": EntryFormat.JSON,
            }
        )
    return entries


def _build_comment_war_room_entry(comment_text: str, tags: list[str] | None = None) -> dict[str, Any]:
    """Build a plain-text War Room comment entry matching native XSOAR comment styling."""
    entry: dict[str, Any] = {
        "Type": EntryType.NOTE,
        "Contents": comment_text,
        "ContentsFormat": EntryFormat.TEXT,
        "Note": True,
    }
    if tags:
        entry["Tags"] = tags
    return entry


def _collect_alert_ids_from_args(args: dict[str, Any]) -> list[str]:
    """Collect unique Vega alert IDs from command arguments."""
    entity_ids: list[str] = []
    for key in ("alert_ids", "alert_id"):
        entity_ids.extend(str(item).strip() for item in argToList(args.get(key)) if str(item).strip())
    return list(dict.fromkeys(entity_ids))


def _collect_incident_ids_from_args(args: dict[str, Any]) -> list[str]:
    """Collect unique Vega incident IDs from command arguments."""
    entity_ids: list[str] = []
    for key in ("incident_ids", "incident_id"):
        entity_ids.extend(str(item).strip() for item in argToList(args.get(key)) if str(item).strip())
    return list(dict.fromkeys(entity_ids))


def _collect_string_list_from_args(args: dict[str, Any], key: str) -> list[str]:
    """Collect unique non-empty string values from a command argument list."""
    return list(dict.fromkeys(str(item).strip() for item in argToList(args.get(key)) if str(item).strip()))


def _validate_alert_status_value(status: str) -> str:
    """Validate and normalize an alert status for the Vega API."""
    api_status = _normalize_vega_status_for_api(status, MIRROR_ENTITY_SUFFIX_ALERT)
    if api_status not in VALID_ALERT_STATUSES:
        valid_values = ", ".join(sorted(ALERT_STATUS_DISPLAY_TO_API.keys()))
        raise DemistoException(f"Invalid alert status '{status}'. Valid values: {valid_values}.")
    return api_status


def _validate_incident_status_value(status: str) -> str:
    """Validate and normalize an incident status for the Vega API."""
    api_status = _normalize_vega_status_for_api(status, MIRROR_ENTITY_SUFFIX_INCIDENT)
    if api_status not in VALID_INCIDENT_STATUSES:
        valid_values = ", ".join(sorted(INCIDENT_STATUS_DISPLAY_TO_API.keys()))
        raise DemistoException(f"Invalid incident status '{status}'. Valid values: {valid_values}.")
    return api_status


def _validate_verdict_value(verdict: str) -> str:
    """Validate and normalize a verdict for the Vega API."""
    api_verdict = _normalize_vega_verdict_for_api(verdict)
    if api_verdict not in VALID_VERDICTS:
        raise DemistoException("Invalid verdict. Valid values: MALICIOUS, SUSPICIOUS, BENIGN, INCONCLUSIVE, NA.")
    return api_verdict


def _validate_severity_value(severity: str) -> str:
    """Validate and normalize a severity for the Vega API."""
    normalized = _normalize_vega_severity_for_display(severity)
    if normalized not in VALID_SEVERITIES:
        raise DemistoException(f"Invalid severity. Valid values: {', '.join(sorted(VALID_SEVERITIES))}.")
    return normalized


def _build_direct_alert_update_payload(args: dict[str, Any]) -> dict[str, Any]:
    """Build an UpdateAlertsInput payload from explicit command arguments."""
    update_input: dict[str, Any] = {}
    status = args.get("status") or args.get("alert_status")
    if status is not None and str(status).strip():
        update_input["status"] = _validate_alert_status_value(str(status))
    verdict = args.get("verdict")
    if verdict is not None and str(verdict).strip():
        update_input["verdict"] = _validate_verdict_value(str(verdict))
    verdict_reasoning = args.get("verdict_reasoning")
    if verdict_reasoning is not None and str(verdict_reasoning).strip():
        update_input["verdictReasoning"] = str(verdict_reasoning).strip()
    severity = args.get("severity") or args.get("alert_severity")
    if severity is not None and str(severity).strip():
        update_input["severity"] = _validate_severity_value(str(severity))
    comment = args.get("comment")
    if comment is not None and str(comment).strip():
        update_input["comment"] = str(comment).strip()
    assignees = _collect_string_list_from_args(args, "assignees")
    if assignees:
        update_input["assignees"] = assignees
    return update_input


def _build_direct_incident_update_payload(args: dict[str, Any]) -> dict[str, Any]:
    """Build an UpdateIncidentsInput payload from explicit command arguments."""
    update_input: dict[str, Any] = {}
    status = args.get("status") or args.get("incident_status")
    if status is not None and str(status).strip():
        update_input["status"] = _validate_incident_status_value(str(status))
    verdict = args.get("verdict")
    verdict_reasoning = args.get("verdict_reasoning")
    if verdict is not None and str(verdict).strip():
        update_input["verdict"] = {
            "value": _validate_verdict_value(str(verdict)),
            "reasoning": str(verdict_reasoning or ""),
        }
    elif verdict_reasoning is not None and str(verdict_reasoning).strip():
        update_input["verdict"] = {
            "value": _validate_verdict_value("NA"),
            "reasoning": str(verdict_reasoning).strip(),
        }
    severity = args.get("severity")
    if severity is not None and str(severity).strip():
        update_input["severity"] = _validate_severity_value(str(severity))
    comment = args.get("comment")
    if comment is not None and str(comment).strip():
        update_input["comment"] = str(comment).strip()
    assignee_emails = _collect_string_list_from_args(args, "assignee_emails")
    if assignee_emails:
        update_input["assigneeEmails"] = assignee_emails
    return update_input


def _format_assignee_output(assignee: Any) -> str | None:
    """Format a Vega assignee object for command context output."""
    if not isinstance(assignee, dict):
        return None
    email = str(assignee.get("email") or "").strip()
    if email:
        return email
    display_name = str(assignee.get("displayName") or "").strip()
    if display_name:
        return display_name
    user_id = str(assignee.get("userId") or "").strip()
    return user_id or None


def _format_push_alert_output(alert: dict[str, Any]) -> dict[str, str]:
    """Format a Vega alert update response for context output."""
    output: dict[str, str] = {
        "id": str(alert.get("id") or ""),
        "status": _normalize_vega_status_for_display(str(alert.get("status") or ""), MIRROR_ENTITY_SUFFIX_ALERT),
        "verdict": _normalize_vega_verdict_for_display(alert.get("verdict")),
    }
    if alert.get("severity") is not None:
        output["severity"] = _normalize_vega_severity_for_display(alert.get("severity"))
    assignee = _format_assignee_output(alert.get("assignee"))
    if assignee:
        output["assignee"] = assignee
    return output


def _format_push_incident_output(
    incident: dict[str, Any],
    requested_severity: str | None = None,
) -> dict[str, str]:
    """Format a Vega incident update response for context output."""
    severity_value = incident.get("severity")
    if severity_value is None and requested_severity is not None:
        severity_value = requested_severity
    output: dict[str, str] = {
        "id": str(incident.get("incidentId") or incident.get("id") or ""),
        "status": _normalize_vega_status_for_display(str(incident.get("status") or ""), MIRROR_ENTITY_SUFFIX_INCIDENT),
        "verdict": _normalize_vega_verdict_for_display(incident.get("verdict")),
    }
    if severity_value is not None:
        output["severity"] = _normalize_vega_severity_for_display(severity_value)
    assignee = _format_assignee_output(incident.get("assignee"))
    if assignee:
        output["assignee"] = assignee
    return output


def resolve_incident_id_from_incident(args: dict[str, Any], incident: dict[str, Any]) -> str | None:
    """Resolve Vega incident ID from command args or the current Vega Incident investigation."""
    incident_ids = _collect_incident_ids_from_args(args)
    if incident_ids:
        return incident_ids[0]

    custom_fields = _collect_incident_custom_fields(incident)
    vega_incident_id = custom_fields.get("vegaincidentid")
    if vega_incident_id is not None and str(vega_incident_id).strip():
        return str(vega_incident_id).strip()

    incident_type = str(incident.get("type") or incident.get("Type") or "").strip()
    raw_json = incident.get("rawJSON") or incident.get("rawJson")
    if raw_json:
        try:
            raw = json.loads(raw_json) if isinstance(raw_json, str) else raw_json
            if isinstance(raw, dict):
                if incident_type and incident_type != "Vega Incident":
                    return None
                if not incident_type and raw.get("vegaEntityType") not in (None, "Vega Incident"):
                    return None
                raw_id = raw.get("id") or raw.get("incidentId")
                if raw_id is not None and str(raw_id).strip():
                    return str(raw_id).strip()
        except (json.JSONDecodeError, TypeError, ValueError):
            pass

    return None


def _is_field_change_trigger(args: dict[str, Any]) -> bool:
    """Return True when the command was triggered by a layout field change."""
    return "old" in args or "new" in args


def _resolve_field_change_update_args(args: dict[str, Any], entity_type_suffix: str) -> dict[str, str]:
    """Map a layout field-change ``new`` value to the status, verdict, severity, or reasoning arg to update."""
    new_value = str(args.get("new") or "").strip()
    if not new_value:
        return {}

    normalized_upper = new_value.strip().upper()
    api_status = _normalize_vega_status_for_api(new_value, entity_type_suffix)
    valid_statuses = VALID_ALERT_STATUSES if entity_type_suffix == MIRROR_ENTITY_SUFFIX_ALERT else VALID_INCIDENT_STATUSES
    if api_status in valid_statuses:
        return {"status": new_value}
    if _normalize_vega_verdict_for_api(normalized_upper) in VALID_VERDICTS:
        return {"verdict": new_value}
    if _normalize_vega_severity_for_display(normalized_upper) in VALID_SEVERITIES:
        return {"severity": new_value}
    return {"verdict_reasoning": new_value}


def _args_explicitly_set(args: dict[str, Any], *keys: str) -> bool:
    """Return True when at least one of the provided args was explicitly set."""
    for key in keys:
        value = args.get(key)
        if value is not None and str(value).strip() != "":
            return True
    return False


def _alert_update_fields_explicitly_set(args: dict[str, Any]) -> bool:
    """Return True when the caller provided alert update command arguments."""
    return _args_explicitly_set(
        args,
        "status",
        "alert_status",
        "verdict",
        "verdict_reasoning",
        "severity",
        "alert_severity",
        "comment",
        "assignees",
    )


def _incident_update_fields_explicitly_set(args: dict[str, Any]) -> bool:
    """Return True when the caller provided incident status, verdict, severity, reasoning, and/or comment command arguments."""
    return _args_explicitly_set(
        args,
        "status",
        "incident_status",
        "verdict",
        "verdict_reasoning",
        "severity",
        "comment",
        "assignee_emails",
    )


def _xsoar_incident_is_closed(incident: dict[str, Any]) -> bool:
    """Return True when the current XSOAR investigation is closed."""
    status = incident.get("status") or incident.get("Status")
    return status == IncidentStatus.DONE or (isinstance(status, str) and status.strip().lower() in {"closed", "done"})


def _resolve_entity_ids_for_update(
    args: dict[str, Any],
    incident: dict[str, Any],
    collect_fn: Callable[[dict[str, Any]], list[str]],
    resolve_fn: Callable[[dict[str, Any], dict[str, Any]], str | None],
) -> list[str]:
    """Resolve Vega entity IDs from args or the current investigation."""
    entity_ids = collect_fn(args)
    if entity_ids:
        return entity_ids
    resolved_id = resolve_fn(args, incident)
    return [resolved_id] if resolved_id else []


def _resolve_alert_ids_for_update(args: dict[str, Any], incident: dict[str, Any]) -> list[str]:
    """Resolve Vega alert IDs from args or the current investigation."""
    return _resolve_entity_ids_for_update(args, incident, _collect_alert_ids_from_args, resolve_alert_id_from_incident)


def _resolve_incident_ids_for_update(args: dict[str, Any], incident: dict[str, Any]) -> list[str]:
    """Resolve Vega incident IDs from args or the current investigation."""
    return _resolve_entity_ids_for_update(args, incident, _collect_incident_ids_from_args, resolve_incident_id_from_incident)


def _resolve_alert_status_for_update(args: dict[str, Any], incident: dict[str, Any]) -> str | None:
    """Resolve alert status from args or the current investigation custom fields."""
    status = args.get("alert_status")
    if status is None or str(status).strip() == "":
        status = args.get("status")
    if status is None or str(status).strip() == "":
        custom_fields = _collect_incident_custom_fields(incident)
        status = custom_fields.get(VEGA_ALERT_STATUS_FIELD)
    if status is None or str(status).strip() == "":
        return None
    return str(status)


def _resolve_incident_status_for_update(args: dict[str, Any], incident: dict[str, Any]) -> str | None:
    """Resolve incident status from args or the current investigation custom fields."""
    status = args.get("incident_status")
    if status is None or str(status).strip() == "":
        status = args.get("status")
    if status is None or str(status).strip() == "":
        custom_fields = _collect_incident_custom_fields(incident)
        status = custom_fields.get(VEGA_INCIDENT_STATUS_FIELD) or custom_fields.get(VEGA_ALERT_STATUS_FIELD)
    if status is None or str(status).strip() == "":
        return None
    return str(status)


def _resolve_verdict_for_update(args: dict[str, Any], incident: dict[str, Any]) -> str | None:
    """Resolve verdict from args or the current investigation custom fields."""
    verdict = args.get("verdict")
    if verdict is None or str(verdict).strip() == "":
        custom_fields = _collect_incident_custom_fields(incident)
        verdict = custom_fields.get("vegaverdict")
    if verdict is None or str(verdict).strip() == "":
        return None
    return str(verdict)


def _resolve_alert_severity_for_update(args: dict[str, Any], incident: dict[str, Any]) -> str | None:
    """Resolve alert severity from args or the current investigation custom fields."""
    severity = args.get("alert_severity")
    if severity is None or str(severity).strip() == "":
        severity = args.get("severity")
    if severity is None or str(severity).strip() == "":
        custom_fields = _collect_incident_custom_fields(incident)
        severity = custom_fields.get(VEGA_ALERT_SEVERITY_FIELD)
    if severity is None or str(severity).strip() == "":
        return None
    return str(severity)


def _resolve_severity_for_update(args: dict[str, Any], incident: dict[str, Any]) -> str | None:
    """Resolve severity from args or the current investigation custom fields."""
    severity = args.get("severity")
    if severity is None or str(severity).strip() == "":
        custom_fields = _collect_incident_custom_fields(incident)
        severity = custom_fields.get(VEGA_SEVERITY_FIELD)
    if severity is None or str(severity).strip() == "":
        return None
    return str(severity)


def _resolve_comment_for_update(args: dict[str, Any]) -> str | None:
    """Resolve an optional Vega incident comment from command args."""
    comment = args.get("comment")
    if comment is None or str(comment).strip() == "":
        return None
    return str(comment).strip()


def _build_effective_alert_update_args(args: dict[str, Any], incident: dict[str, Any]) -> dict[str, Any]:
    """Build alert update args from explicit args, field changes, or current investigation fields."""
    if _is_field_change_trigger(args):
        return {**args, **_resolve_field_change_update_args(args, MIRROR_ENTITY_SUFFIX_ALERT)}

    effective_args = dict(args)
    if not _alert_update_fields_explicitly_set(args):
        status = _resolve_alert_status_for_update(args, incident)
        if status is not None:
            effective_args["status"] = status
        verdict = _resolve_verdict_for_update(args, incident)
        if verdict is not None:
            effective_args["verdict"] = verdict
        severity = _resolve_alert_severity_for_update(args, incident)
        if severity is not None:
            effective_args["severity"] = severity
        return effective_args

    if _args_explicitly_set(args, "status", "alert_status"):
        status = _resolve_alert_status_for_update(args, incident)
        if status is not None:
            effective_args["status"] = status
    if _args_explicitly_set(args, "verdict"):
        verdict = _resolve_verdict_for_update(args, incident)
        if verdict is not None:
            effective_args["verdict"] = verdict
    if _args_explicitly_set(args, "severity", "alert_severity"):
        severity = _resolve_alert_severity_for_update(args, incident)
        if severity is not None:
            effective_args["severity"] = severity
    if _args_explicitly_set(args, "assignees"):
        effective_args["assignees"] = _collect_string_list_from_args(args, "assignees")
    return effective_args


def _build_effective_incident_update_args(args: dict[str, Any], incident: dict[str, Any]) -> dict[str, Any]:
    """Build incident update args from explicit args, field changes, or current investigation fields."""
    if _is_field_change_trigger(args):
        resolved_args = _resolve_field_change_update_args(args, MIRROR_ENTITY_SUFFIX_INCIDENT)
        effective_args = {**args, **resolved_args}
        if resolved_args.get("verdict_reasoning") and not resolved_args.get("verdict"):
            verdict = _resolve_verdict_for_update(args, incident)
            if verdict is not None:
                effective_args["verdict"] = verdict
        return effective_args

    effective_args = dict(args)
    if not _incident_update_fields_explicitly_set(args):
        status = _resolve_incident_status_for_update(args, incident)
        if status is not None:
            effective_args["status"] = status
        verdict = _resolve_verdict_for_update(args, incident)
        if verdict is not None:
            effective_args["verdict"] = verdict
        comment = _resolve_comment_for_update(args)
        if comment is not None:
            effective_args["comment"] = comment
        return effective_args

    if _args_explicitly_set(args, "status", "incident_status"):
        status = _resolve_incident_status_for_update(args, incident)
        if status is not None:
            effective_args["status"] = status
    if _args_explicitly_set(args, "verdict"):
        verdict = _resolve_verdict_for_update(args, incident)
        if verdict is not None:
            effective_args["verdict"] = verdict
    comment = _resolve_comment_for_update(args)
    if comment is not None:
        effective_args["comment"] = comment
    if _args_explicitly_set(args, "assignee_emails"):
        effective_args["assignee_emails"] = _collect_string_list_from_args(args, "assignee_emails")
    return effective_args


def _should_sync_xsoar_entity(
    args: dict[str, Any],
    incident: dict[str, Any],
    entity_ids: list[str],
    id_arg_keys: tuple[str, ...],
    resolve_fn: Callable[[dict[str, Any], dict[str, Any]], str | None],
) -> bool:
    """Return True when the open XSOAR investigation should be synced after an entity update."""
    if not incident.get("id"):
        return False
    if len(entity_ids) > 1 and _args_explicitly_set(args, *id_arg_keys):
        current_id = resolve_fn(args, incident)
        return bool(current_id and current_id in entity_ids)
    return True


def _should_sync_xsoar_alert(args: dict[str, Any], incident: dict[str, Any], alert_ids: list[str]) -> bool:
    """Return True when the open XSOAR investigation should be synced after an alert update."""
    return _should_sync_xsoar_entity(args, incident, alert_ids, ("alert_ids", "alert_id"), resolve_alert_id_from_incident)


def _should_sync_xsoar_incident(args: dict[str, Any], incident: dict[str, Any], incident_ids: list[str]) -> bool:
    """Return True when the open XSOAR investigation should be synced after an incident update."""
    return _should_sync_xsoar_entity(
        args, incident, incident_ids, ("incident_ids", "incident_id"), resolve_incident_id_from_incident
    )


def _build_xsoar_alert_sync_entries(args: dict[str, Any], incident: dict[str, Any]) -> list[dict]:
    """Build war room entries that sync the open Vega Alert investigation without executeCommand."""
    if not incident.get("id"):
        return []

    entries: list[dict] = []
    field_change = _is_field_change_trigger(args)
    if not field_change and _args_explicitly_set(args, "status", "alert_status", "verdict", "severity", "alert_severity"):
        custom_fields: dict[str, str] = {}
        status = _resolve_alert_status_for_update(args, incident)
        if status is not None:
            custom_fields[VEGA_ALERT_STATUS_FIELD] = _normalize_vega_status_for_display(status, MIRROR_ENTITY_SUFFIX_ALERT)
        verdict = _resolve_verdict_for_update(args, incident)
        if verdict is not None:
            custom_fields["vegaverdict"] = _normalize_vega_verdict_for_display(verdict)
        severity = _resolve_alert_severity_for_update(args, incident)
        if severity is not None:
            custom_fields[VEGA_ALERT_SEVERITY_FIELD] = _normalize_vega_severity_for_display(severity)
        if custom_fields:
            entries.append(
                {
                    "Type": EntryType.NOTE,
                    "ContentsFormat": EntryFormat.JSON,
                    "Contents": {"CustomFields": custom_fields},
                    "Note": True,
                }
            )

    status = _resolve_alert_status_for_update(args, incident)
    if status is None:
        return entries

    api_status = _normalize_vega_status_for_api(status, MIRROR_ENTITY_SUFFIX_ALERT)
    if api_status in VEGA_CLOSE_STATUSES and not _xsoar_incident_is_closed(incident):
        entries.extend(_build_close_reopen_sync_entries(status, MIRROR_ENTITY_SUFFIX_ALERT))
    elif api_status in VEGA_ALERT_OPEN_STATUSES and _xsoar_incident_is_closed(incident):
        entries.extend(_build_close_reopen_sync_entries(status, MIRROR_ENTITY_SUFFIX_ALERT))

    return entries


# ? ---------------------------- HELPER FUNCTIONS --------------------------------------


def _build_xsoar_incident_sync_entries(args: dict[str, Any], incident: dict[str, Any]) -> list[dict]:
    """Build war room entries that sync the open Vega Incident investigation without executeCommand."""
    if not incident.get("id"):
        return []

    entries: list[dict] = []
    field_change = _is_field_change_trigger(args)
    if not field_change and _args_explicitly_set(args, "status", "incident_status", "verdict", "severity"):
        custom_fields: dict[str, str] = {}
        status = _resolve_incident_status_for_update(args, incident)
        if status is not None:
            custom_fields[VEGA_INCIDENT_STATUS_FIELD] = _normalize_vega_status_for_display(status, MIRROR_ENTITY_SUFFIX_INCIDENT)
        verdict = _resolve_verdict_for_update(args, incident)
        if verdict is not None:
            custom_fields["vegaverdict"] = _normalize_vega_verdict_for_display(verdict)
        severity = _resolve_severity_for_update(args, incident)
        if severity is not None:
            custom_fields[VEGA_SEVERITY_FIELD] = _normalize_vega_severity_for_display(severity)
        if custom_fields:
            entries.append(
                {
                    "Type": EntryType.NOTE,
                    "ContentsFormat": EntryFormat.JSON,
                    "Contents": {"CustomFields": custom_fields},
                    "Note": True,
                }
            )

    status = _resolve_incident_status_for_update(args, incident)
    if status is None:
        return entries

    api_status = _normalize_vega_status_for_api(status, MIRROR_ENTITY_SUFFIX_INCIDENT)
    if api_status in VEGA_CLOSE_STATUSES and not _xsoar_incident_is_closed(incident):
        entries.extend(_build_close_reopen_sync_entries(status, MIRROR_ENTITY_SUFFIX_INCIDENT))
    elif api_status in VEGA_INCIDENT_OPEN_STATUSES and _xsoar_incident_is_closed(incident):
        entries.extend(_build_close_reopen_sync_entries(status, MIRROR_ENTITY_SUFFIX_INCIDENT))

    comment = _resolve_comment_for_update(args)
    if (
        comment is not None
        and not field_change
        and _args_explicitly_set(args, "comment")
        and set(_build_direct_incident_update_payload(args).keys()) != {"comment"}
    ):
        entries.append(_build_comment_war_room_entry(comment))

    return entries


def update_alert_command(client: Client, args: dict[str, Any]) -> CommandResults | list[Any]:
    """Update Vega alert status and/or verdict and sync the open XSOAR investigation."""
    incident = load_current_incident()
    alert_ids = _resolve_alert_ids_for_update(args, incident)
    if not alert_ids:
        incident_type = str(incident.get("type") or incident.get("Type") or "unknown")
        xsoar_incident_id = incident.get("id") or "none"
        raise DemistoException(
            "At least one alert id is required when the command is not run from a Vega Alert incident. "
            f"Could not resolve alert ID from incident id={xsoar_incident_id}, type={incident_type}. "
            "Pass alert_ids explicitly, for example: "
            "!vega-update-alert alert_ids=alert-1,alert-2 status=RESOLVED verdict=MALICIOUS"
        )

    effective_args = _build_effective_alert_update_args(args, incident)
    update_fields = _build_direct_alert_update_payload(effective_args)
    if not update_fields:
        raise DemistoException(
            "At least one of status, severity, verdict, verdict reasoning, comment, or assignees must be provided."
        )

    result = client.update_alerts({**update_fields, "alertIds": alert_ids})
    updated_alerts = result.get("alerts") or []

    outputs = [_format_push_alert_output(alert) for alert in updated_alerts]
    readable = tableToMarkdown(
        "Updated Vega Alerts",
        outputs,
        headers=["id", "status", "severity", "verdict", "assignee"],
        removeNull=True,
    )
    command_result = CommandResults(
        readable_output=readable,
        outputs_prefix="Vega.Alert",
        outputs_key_field="id",
        outputs=outputs[0] if len(outputs) == 1 else outputs,
    )
    if not _should_sync_xsoar_alert(args, incident, alert_ids):
        return command_result

    sync_entries = _build_xsoar_alert_sync_entries(effective_args, incident)
    if sync_entries:
        return [command_result, *sync_entries]
    return command_result


def _build_incident_update_command_result(
    incident_ids: list[str],
    outputs: list[dict[str, Any]],
    update_fields: dict[str, Any],
    comment_text: str | None,
) -> CommandResults:
    """Build the command result for a Vega incident update."""
    comment_only_update = set(update_fields.keys()) == {"comment"} and bool(comment_text)
    if comment_only_update:
        return CommandResults(
            readable_output=comment_text,
            entry_type=EntryType.NOTE,
            mark_as_note=True,
            outputs_prefix="Vega.Incident",
            outputs_key_field="id",
            outputs={"id": incident_ids[0], "comment": comment_text},
        )

    readable = tableToMarkdown(
        "Updated Vega Incidents",
        outputs,
        headers=["id", "status", "verdict", "severity", "assignee"],
        removeNull=True,
    )
    return CommandResults(
        readable_output=readable,
        outputs_prefix="Vega.Incident",
        outputs_key_field="id",
        outputs=outputs[0] if len(outputs) == 1 else outputs,
    )


def update_incident_command(client: Client, args: dict[str, Any]) -> CommandResults | list[Any]:
    """Update Vega incident status, verdict, and/or comment and sync the open XSOAR investigation."""
    incident = load_current_incident()
    incident_ids = _resolve_incident_ids_for_update(args, incident)
    if not incident_ids:
        incident_type = str(incident.get("type") or incident.get("Type") or "unknown")
        xsoar_incident_id = incident.get("id") or "none"
        raise DemistoException(
            "At least one incident id is required when the command is not run from a Vega Incident investigation. "
            f"Could not resolve incident ID from incident id={xsoar_incident_id}, type={incident_type}. "
            "Pass incident_ids explicitly, for example: "
            "!vega-update-incident incident_ids=inc-1,inc-2 status=RESOLVED verdict=MALICIOUS comment=Updated"
        )

    effective_args = _build_effective_incident_update_args(args, incident)
    update_fields = _build_direct_incident_update_payload(effective_args)
    if not update_fields:
        raise DemistoException(
            "At least one of status, verdict, verdict reasoning, severity, comment, or assignee_emails must be provided."
        )

    result = client.update_incidents({**update_fields, "incidentIds": incident_ids})
    requested_severity = effective_args.get("severity")
    outputs = [
        _format_push_incident_output(incident_item, requested_severity=str(requested_severity) if requested_severity else None)
        for incident_item in result.get("incidents") or []
    ]
    command_result = _build_incident_update_command_result(
        incident_ids,
        outputs,
        update_fields,
        _resolve_comment_for_update(effective_args),
    )
    if not _should_sync_xsoar_incident(args, incident, incident_ids):
        return command_result

    sync_entries = _build_xsoar_incident_sync_entries(effective_args, incident)
    if sync_entries:
        return [command_result, *sync_entries]
    return command_result


def _build_xsoar_incident_dict(
    raw: dict[str, Any],
    entity_type: str,
    entity_type_suffix: str,
    custom_fields_builder: Callable[[dict], dict[str, str]],
) -> dict[str, Any]:
    """Build a common XSOAR incident dict from prepared raw entity data."""
    severity = VEGA_SEVERITY_TO_XSOAR.get(raw.get("severity", "").upper(), IncidentSeverity.UNKNOWN)
    xsoar_incident: dict[str, Any] = {
        "name": f"{raw.get('name', 'Unknown')}",
        "occurred": raw.get("createdAt", ""),
        "severity": severity,
        "type": entity_type,
        "rawJSON": json.dumps({key: value for key, value in raw.items() if key != "_alertEventsCustomFields"}),
    }
    mirror_id = raw.get("mirror_id")
    if mirror_id:
        xsoar_incident["dbotMirrorId"] = str(mirror_id).strip()
    elif raw.get("id"):
        xsoar_incident["dbotMirrorId"] = _format_dbot_mirror_id(entity_type_suffix, str(raw["id"]).strip())
    _apply_xsoar_mirror_metadata(xsoar_incident)
    custom_fields = custom_fields_builder(raw)
    if custom_fields:
        xsoar_incident["CustomFields"] = custom_fields
    return xsoar_incident


def alert_to_incident(
    alert: dict,
    integration_url: str | None = None,
    client: Client | None = None,
) -> dict:
    """Convert a Vega alert to an XSOAR incident."""
    raw = dict(alert)
    raw["vegaEntityType"] = "Vega Alert"
    raw.update(_get_mirroring_fields())
    _apply_mirror_metadata(raw, MIRROR_ENTITY_SUFFIX_ALERT)
    _apply_vega_entity_link(raw, integration_url=integration_url)
    if client is not None:
        alert_id = _normalize_entity_id(raw)
        if alert_id:
            alert_events, event_custom_fields = _fetch_alert_events_for_ingest(client, alert_id)
            raw["alertEvents"] = alert_events
            raw["_alertEventsCustomFields"] = event_custom_fields
    _format_raw_entity_for_xsoar(raw)
    return _build_xsoar_incident_dict(raw, "Vega Alert", MIRROR_ENTITY_SUFFIX_ALERT, _build_vega_alert_custom_fields)


def incident_to_xsoar_incident(
    incident: dict,
    timeline_events: list[dict] | None = None,
) -> dict:
    """Convert a Vega incident to an XSOAR incident."""
    raw = dict(incident)
    raw["vegaEntityType"] = "Vega Incident"
    raw.update(_get_mirroring_fields())
    _apply_mirror_metadata(raw, MIRROR_ENTITY_SUFFIX_INCIDENT)
    if timeline_events is not None:
        raw["timelineEvents"] = timeline_events
        raw["vegaTimelineEvents"] = _format_timeline_events_html(timeline_events)
    _apply_vega_entity_link(raw)
    _format_raw_entity_for_xsoar(raw)
    return _build_xsoar_incident_dict(raw, "Vega Incident", MIRROR_ENTITY_SUFFIX_INCIDENT, _build_vega_incident_custom_fields)


def _apply_mirror_metadata(raw: dict[str, Any], entity_type_suffix: str) -> None:
    """Attach mirror_id used by incoming mappers and mirroring commands."""
    entity_id = _normalize_entity_id(raw)
    if entity_id:
        raw["mirror_id"] = _format_dbot_mirror_id(entity_type_suffix, str(entity_id).strip())


def _is_xsoar_to_vega_mirroring_enabled(params: dict[str, Any] | None = None) -> bool:
    """Return True when outgoing XSOAR to Vega mirroring is enabled."""
    params = params or demisto.params()
    return argToBoolean(params.get("autoclosure", True))


def _get_mirroring_fields(
    params: dict[str, Any] | None = None,
    mirror_context: dict[str, Any] | None = None,
) -> dict[str, str]:
    """Build mirror metadata embedded in fetched incidents."""
    params = params or demisto.params()
    fields: dict[str, str] = {}

    instance = str(demisto.integrationInstance() or "")
    if not instance and isinstance(mirror_context, dict):
        instance = str(mirror_context.get("dbotMirrorInstance") or mirror_context.get("mirror_instance") or "").strip()
        if not instance:
            custom_fields = mirror_context.get("CustomFields")
            if isinstance(custom_fields, dict):
                instance = str(custom_fields.get("dbotmirrorinstance") or custom_fields.get("mirror_instance") or "").strip()
    if not instance:
        calling_context = getattr(demisto, "callingContext", None)
        if isinstance(calling_context, dict):
            ctx = calling_context.get("context", {})
            if isinstance(ctx, dict) and ctx.get("IntegrationInstance"):
                instance = str(ctx["IntegrationInstance"])
    if instance:
        fields["mirror_instance"] = instance

    fields["mirror_direction"] = "Both" if _is_xsoar_to_vega_mirroring_enabled(params) else "In"
    return fields


def _apply_xsoar_mirror_metadata(
    xsoar_incident: dict[str, Any],
    mirror_context: dict[str, Any] | None = None,
) -> None:
    """Attach top-level mirror metadata required for XSOAR remote sync."""
    mirror_id = xsoar_incident.get("dbotMirrorId") or xsoar_incident.get("mirror_id")
    if not mirror_id:
        return
    _apply_mirror_metadata_fields(xsoar_incident, mirror_context=mirror_context, mirror_id=str(mirror_id).strip())


def _apply_mirror_metadata_fields(
    payload: dict[str, Any],
    mirror_context: dict[str, Any] | None = None,
    *,
    mirror_id: str | None = None,
) -> None:
    """Attach mirror direction and instance to an ingest or get-remote-data payload."""
    effective_mirror_id = mirror_id or payload.get("dbotMirrorId") or payload.get("mirror_id")
    if not effective_mirror_id:
        return

    mirror_id_text = str(effective_mirror_id).strip()
    payload["dbotMirrorId"] = mirror_id_text
    payload["mirror_id"] = mirror_id_text

    mirror_fields = _get_mirroring_fields(mirror_context=mirror_context or payload)
    if mirror_fields.get("mirror_direction"):
        direction = mirror_fields["mirror_direction"]
        payload["dbotMirrorDirection"] = direction
        payload["mirror_direction"] = direction
    if mirror_fields.get("mirror_instance"):
        instance = mirror_fields["mirror_instance"]
        payload["dbotMirrorInstance"] = instance
        payload["mirror_instance"] = instance


def _apply_mirror_sync_metadata(
    sync_object: dict[str, Any],
    mirror_context: dict[str, Any] | None = None,
) -> None:
    """Refresh top-level mirror metadata on every incoming mirror sync cycle."""
    _apply_mirror_metadata_fields(sync_object, mirror_context=mirror_context)


def _normalize_entity_id(entity: dict, id_key: str = "id") -> str:
    """Return a stable string ID for deduplication."""
    entity_id = entity.get(id_key)
    if entity_id is None or entity_id == "":
        for fallback_key in ("incidentId", "alertId", "vegaAlertId"):
            fallback = entity.get(fallback_key)
            if fallback is not None and str(fallback).strip():
                entity_id = fallback
                break
    if entity_id is None or entity_id == "":
        return ""
    return str(entity_id)


def _normalize_incident_api_entity(entity: dict[str, Any]) -> dict[str, Any]:
    """Normalize incident payloads from list or detail APIs to a common shape."""
    if not entity:
        return {}
    normalized = dict(entity)
    entity_id = _normalize_entity_id(normalized)
    if entity_id:
        normalized["id"] = entity_id
    if not normalized.get("lastUpdated") and normalized.get("lastUpdate"):
        normalized["lastUpdated"] = normalized["lastUpdate"]
    if normalized.get("alertCount") is not None and normalized.get("alertsCount") is None:
        normalized["alertsCount"] = normalized["alertCount"]
    return normalized


def _normalize_alert_api_entity(entity: dict[str, Any]) -> dict[str, Any]:
    """Normalize alert payloads from the Vega API to a common shape."""
    if not entity:
        return {}
    normalized = dict(entity)
    entity_id = _normalize_entity_id(normalized)
    if entity_id:
        normalized["id"] = entity_id
    return normalized


def _parse_entity_created_at(created_at: Any) -> datetime | None:
    """Parse a Vega createdAt value to UTC datetime."""
    if not created_at:
        return None
    return arg_to_datetime(str(created_at), is_utc=True)  # type: ignore[return-value]


def _normalize_fetch_datetime(created_at: datetime) -> datetime:
    """Truncate a UTC datetime to whole seconds for cursor comparisons."""
    return created_at.replace(microsecond=0)


def _format_fetch_timestamp(created_at: datetime) -> str:
    """Format a datetime as the canonical ISO 8601 timestamp stored in last_run."""
    return _normalize_fetch_datetime(created_at).strftime("%Y-%m-%dT%H:%M:%SZ")


def _current_fetch_timestamp() -> str:
    """Return the current UTC time formatted for last_run cursors."""
    return _format_fetch_timestamp(datetime.now(UTC))


def _fetch_paginated_entities(
    fetch_func: Callable[..., dict],
    entities_key: str,
    max_entities: int | None = None,
    start_offset: int = 0,
    **fetch_kwargs: Any,
) -> tuple[list[dict], int | None]:
    """Fetch entities from the Vega API.

    Returns the entity list and an optional next offset when max_entities stops
    the fetch before all matching records are retrieved.
    """
    entities: list[dict] = []
    offset = start_offset

    while True:
        request_kwargs = dict(fetch_kwargs)
        page_limit = FETCH_ENTITIES_PAGE_SIZE
        if max_entities is not None:
            remaining = max_entities - len(entities)
            if remaining <= 0:
                break
            page_limit = min(page_limit, remaining)
        request_kwargs["limit"] = page_limit

        response = fetch_func(offset=offset, **request_kwargs)

        page = response.get(entities_key) or []
        if not page:
            break

        entities.extend(page)
        if max_entities is not None and len(entities) >= max_entities:
            entities = entities[:max_entities]
            total = response.get("total")
            if total is not None:
                next_offset = start_offset + len(entities)
                if next_offset < total:
                    return entities, next_offset
            break

        total = response.get("total")
        if total is not None and offset + len(page) >= total:
            break

        offset += len(page)

    return entities, None


def _build_fetch_filter_fingerprint(
    severities: list[str] | None,
    statuses: list[str] | None,
    verdicts: list[str] | None,
    has_related_incidents: bool | None = None,
) -> str:
    """Build a stable fingerprint for fetch filter parameters."""
    payload: dict[str, Any] = {
        "severities": sorted(severities or []),
        "statuses": sorted(statuses or []),
        "verdicts": sorted(verdicts or []),
    }
    if has_related_incidents is not None:
        payload["hasRelatedIncidents"] = has_related_incidents
    return json.dumps(payload, sort_keys=True)


def _fetch_config_key_for_last_fetch(last_fetch_key: str) -> str:
    """Map a last_fetch cursor key to its corresponding fetch filter fingerprint key."""
    return last_fetch_key.replace("_last_fetch", "_fetch_config")


def _resolve_fetch_from_time(
    last_run: dict,
    last_fetch_key: str,
    first_fetch_time: str,
) -> str:
    """Resolve the Vega API `from` timestamp for the current fetch run."""
    stored_fetch = last_run.get(last_fetch_key)
    fetch_config_key = _fetch_config_key_for_last_fetch(last_fetch_key)
    if stored_fetch not in (None, "") and last_run.get(fetch_config_key) is not None:
        return str(stored_fetch)

    if stored_fetch not in (None, ""):
        return first_fetch_time

    return first_fetch_time


def _parse_mirror_last_update(last_update: str | None) -> datetime:
    """Parse a mirroring lastUpdate timestamp to UTC."""
    if not last_update:
        return datetime.fromtimestamp(0, tz=UTC)
    parsed = arg_to_datetime(last_update, is_utc=True)
    if parsed is None:
        return datetime.fromtimestamp(0, tz=UTC)
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def _format_mirror_timestamp(value: datetime) -> str:
    """Format a UTC datetime for Vega updatedFrom/updatedTo filters."""
    normalized = value.astimezone(UTC).replace(microsecond=0)
    return normalized.strftime("%Y-%m-%dT%H:%M:%SZ")


def _resolve_mirror_updated_from(last_update: str | None) -> str:
    """Resolve updatedFrom for incident mirror polling."""
    cursor_start = _parse_mirror_last_update(last_update) - MIRROR_LAST_UPDATE_SAFETY_MARGIN
    minimum_lookback = datetime.now(UTC) - MIRROR_POLL_LOOKBACK
    resolved = _format_mirror_timestamp(min(cursor_start, minimum_lookback))
    return resolved


def _resolve_mirror_updated_to() -> str:
    """Resolve updatedTo as current time plus a small buffer."""
    resolved = _format_mirror_timestamp(datetime.now(UTC) + MIRROR_UPDATED_TO_BUFFER)
    return resolved


def _poll_entity_is_alert(entity: dict[str, Any]) -> bool:
    """Return True when a polled Vega entity is an alert (has vegaAlertId)."""
    vega_alert_id = entity.get("vegaAlertId")
    return vega_alert_id is not None and str(vega_alert_id).strip() != ""


def _mirror_entity_suffix_from_poll_entity(entity: dict[str, Any], *, poll_source: str | None = None) -> str:
    """Classify a polled entity as alert or incident using vegaAlertId when present."""
    if _poll_entity_is_alert(entity):
        return MIRROR_ENTITY_SUFFIX_ALERT
    if poll_source == MIRROR_ENTITY_SUFFIX_ALERT:
        return MIRROR_ENTITY_SUFFIX_ALERT
    if poll_source == MIRROR_ENTITY_SUFFIX_INCIDENT:
        return MIRROR_ENTITY_SUFFIX_INCIDENT
    return MIRROR_ENTITY_SUFFIX_INCIDENT


def _append_modified_remote_entity_id(
    modified_ids: list[str],
    entity: dict[str, Any],
    *,
    poll_source: str,
) -> str | None:
    """Append prefixed (and legacy bare) mirror IDs for a polled alert or incident entity."""
    normalized = (
        _normalize_alert_api_entity(entity)
        if poll_source == MIRROR_ENTITY_SUFFIX_ALERT
        else _normalize_incident_api_entity(entity)
    )
    entity_id = _normalize_entity_id(normalized)
    if not entity_id:
        return None

    entity_suffix = _mirror_entity_suffix_from_poll_entity(normalized, poll_source=poll_source)
    prefixed_id = _format_dbot_mirror_id(entity_suffix, entity_id)
    if prefixed_id and prefixed_id not in modified_ids:
        modified_ids.append(prefixed_id)
    return entity_id


def _resolve_mirror_entity_lookup_filters() -> dict[str, str]:
    """Build a wide ``from`` filter for direct mirror entity ID lookups during get-remote-data."""
    return {"from_time": parse_backfill_days(demisto.params().get("backfill_days"))}


def _resolve_mirror_incident_lookup_filters(last_update: str | None) -> dict[str, str]:
    """Build getIncidents `from` filter for incident ID lookups during mirroring."""
    return {"from_time": _resolve_mirror_updated_from(last_update)}


def _normalize_mirror_field_value(value: Any) -> Any:
    """Return the effective value from a mirror delta field (supports old/new change dicts)."""
    if isinstance(value, dict):
        if "new" in value:
            new_value = value.get("new")
            if new_value is not None and str(new_value).strip() != "":
                return new_value
        if "old" in value:
            return value.get("old")
    return value


def _outgoing_mirror_comment_value(value: Any) -> str | None:
    """Return a Vega comment to push, skipping empty values and the layout display default."""
    if value is None:
        return None
    text = str(value).strip()
    if not text or text.casefold() == VEGA_NEW_COMMENT_LAYOUT_DEFAULT.casefold():
        return None
    return text


def _mirror_delta_raw_field_value(delta: dict[str, Any], field_name: str) -> Any:
    """Return the raw delta value for a field without falling back to investigation data."""
    if not delta:
        return None
    custom_fields = _mirror_custom_fields(delta)
    if field_name in custom_fields:
        return custom_fields[field_name]
    if field_name in delta:
        return delta[field_name]
    return None


def _normalize_outgoing_mirror_compare_value(field_name: str, value: Any, entity_type_suffix: str) -> str:
    """Normalize a mirror field value for outgoing change comparison."""
    if value is None:
        return ""
    if isinstance(value, dict):
        value = value.get("value") or value.get("new") or value.get("old")
    text = str(value or "").strip()
    if not text or text in ("-", VEGA_EMPTY_FIELD_DISPLAY):
        if field_name == VEGA_VERDICT_FIELD:
            return "NA"
        return ""
    if field_name in (VEGA_ALERT_STATUS_FIELD, VEGA_INCIDENT_STATUS_FIELD):
        return _normalize_vega_status_for_api(text, entity_type_suffix)
    if field_name in (VEGA_ALERT_SEVERITY_FIELD, VEGA_SEVERITY_FIELD):
        return _normalize_vega_severity_for_display(text)
    if field_name == VEGA_VERDICT_FIELD:
        normalized = text.upper()
        return VERDICT_DISPLAY_TO_API.get(normalized, normalized)
    return text


def _mirror_field_changed_in_delta(field_name: str, delta: dict[str, Any], entity_type_suffix: str) -> bool:
    """Return True when delta records a meaningful outgoing change for the field."""
    raw = _mirror_delta_raw_field_value(delta, field_name)
    if raw is None:
        return False
    if isinstance(raw, dict) and ("old" in raw or "new" in raw):
        old_normalized = _normalize_outgoing_mirror_compare_value(field_name, raw.get("old"), entity_type_suffix)
        new_normalized = _normalize_outgoing_mirror_compare_value(field_name, raw.get("new"), entity_type_suffix)
        return old_normalized != new_normalized
    normalized = _normalize_outgoing_mirror_compare_value(field_name, raw, entity_type_suffix)
    return bool(normalized)


def _mirror_delta_changed_value(field_name: str, delta: dict[str, Any], entity_type_suffix: str) -> Any:
    """Return the new value for a field that changed in delta, or None when unchanged."""
    if not _mirror_field_changed_in_delta(field_name, delta, entity_type_suffix):
        return None
    raw = _mirror_delta_raw_field_value(delta, field_name)
    if raw is None:
        return None
    return _normalize_mirror_field_value(raw)


def _mirror_field_value(field_name: str, delta: dict[str, Any], data: dict[str, Any] | None = None) -> Any:
    """Read a mirrored field from delta and fall back to the investigation data payload."""
    data = data or {}
    for source in (delta, data):
        custom_fields = _mirror_custom_fields(source)
        if field_name in custom_fields:
            value = _normalize_mirror_field_value(custom_fields.get(field_name))
            if value is not None and str(value).strip() != "":
                return value
        if field_name in source:
            value = _normalize_mirror_field_value(source.get(field_name))
            if value is not None and str(value).strip() != "":
                return value
    return None


def _entity_updated_after(entity: dict[str, Any], entity_type_suffix: str, last_update: datetime) -> bool:
    """Return True when the remote entity was updated after the mirroring cursor."""
    if entity_type_suffix == MIRROR_ENTITY_SUFFIX_INCIDENT:
        updated_at = _parse_entity_created_at(entity.get("lastUpdated") or entity.get("updatedAt"))
    else:
        updated_at = _parse_entity_created_at(entity.get("updatedAt"))
    if updated_at is None:
        return False
    return _normalize_fetch_datetime(updated_at) > _normalize_fetch_datetime(last_update)


def _format_dbot_mirror_id(entity_type_suffix: str, entity_id: str) -> str:
    """Format dbotMirrorId with an entity-type prefix for reliable mirror routing."""
    normalized_id = str(entity_id).strip()
    if not normalized_id:
        return ""
    if entity_type_suffix == MIRROR_ENTITY_SUFFIX_ALERT:
        return f"alert:{normalized_id}"
    if entity_type_suffix == MIRROR_ENTITY_SUFFIX_INCIDENT:
        return f"incident:{normalized_id}"
    return normalized_id


def _parse_mirror_id(remote_id: str) -> tuple[str, str | None]:
    """Split legacy prefixed mirror IDs into Vega entity ID and type hint."""
    remote_id = str(remote_id).strip()
    if remote_id.startswith("alert:"):
        return remote_id[6:], MIRROR_ENTITY_SUFFIX_ALERT
    if remote_id.startswith("incident:"):
        return remote_id[9:], MIRROR_ENTITY_SUFFIX_INCIDENT
    return remote_id, None


def _entity_matches_remote_id(entity: dict[str, Any], remote_id: str) -> bool:
    """Return True when the Vega entity ID matches the mirrored remote ID."""
    remote_id = str(remote_id).strip()
    if not remote_id or not entity:
        return False
    candidate_ids = {_normalize_entity_id(entity)}
    for key in ("id", "incidentId", "alertId", "vegaAlertId"):
        value = entity.get(key)
        if value is not None and str(value).strip():
            candidate_ids.add(str(value).strip())
    candidate_ids.discard("")
    return remote_id in candidate_ids


def _mirror_dict(value: Any) -> dict[str, Any]:
    """Parse mirror command JSON payloads into dictionaries."""
    if isinstance(value, str) and value.strip():
        try:
            parsed = json.loads(value)
        except (json.JSONDecodeError, TypeError, ValueError):
            return {}
        return parsed if isinstance(parsed, dict) else {}
    return dict(value) if isinstance(value, dict) else {}


def _entity_type_from_field_keys(data: dict[str, Any]) -> str | None:
    """Infer Vega Alert vs Vega Incident from mirrored custom-field keys present in a payload."""
    incident_type = str(
        data.get("type") or data.get("Type") or data.get("incident_type") or data.get("incidentType") or ""
    ).strip()
    if incident_type == "Vega Alert":
        return "Vega Alert"
    if incident_type == "Vega Incident":
        return "Vega Incident"

    custom_fields = _mirror_custom_fields(data)
    incident_keys = ("vegaincidentid", "vegaincidentstatus", "vegaseverity")
    alert_keys = ("alertid", "vegaalertid", "vegastatus", "vegaalertseverity")

    if any(custom_fields.get(key) for key in incident_keys) or any(data.get(key) for key in incident_keys):
        return "Vega Incident"
    if any(custom_fields.get(key) for key in alert_keys) or any(data.get(key) for key in alert_keys):
        return "Vega Alert"
    return None


def _entity_type_from_raw_json(data: dict[str, Any]) -> str | None:
    """Resolve Vega entity type from a rawJSON field on a mirror payload."""
    raw_json = data.get("rawJSON") or data.get("rawJson")
    if not raw_json:
        return None
    try:
        raw = json.loads(raw_json) if isinstance(raw_json, str) else raw_json
    except (json.JSONDecodeError, TypeError, ValueError):
        return None
    if not isinstance(raw, dict):
        return None
    raw_type = str(raw.get("vegaEntityType") or raw.get("type") or raw.get("Type") or "").strip()
    if raw_type in ("Vega Alert", "Vega Incident"):
        return raw_type
    return None


def _entity_type_from_mirror_payload(data: dict[str, Any]) -> str | None:
    """Resolve Vega Alert vs Vega Incident from a mirror payload or investigation dict."""
    if not data:
        return None

    custom_fields = _mirror_custom_fields(data)
    vega_incident_id = str(custom_fields.get("vegaincidentid") or "").strip()
    alert_id = str(custom_fields.get("alertid") or "").strip()
    if vega_incident_id and not alert_id:
        return "Vega Incident"
    if alert_id and not vega_incident_id:
        return "Vega Alert"

    entity_type_from_fields = _entity_type_from_field_keys(data)
    if entity_type_from_fields:
        return entity_type_from_fields

    incident_type = str(
        data.get("type") or data.get("Type") or data.get("incident_type") or data.get("incidentType") or ""
    ).strip()
    if incident_type in ("Vega Alert", "Vega Incident"):
        return incident_type

    vega_entity_type = str(data.get("vegaEntityType") or "").strip()
    if vega_entity_type in ("Vega Alert", "Vega Incident"):
        return vega_entity_type

    entity_type_from_raw = _entity_type_from_raw_json(data)
    if entity_type_from_raw:
        return entity_type_from_raw

    if custom_fields.get("vegaincidentid"):
        return "Vega Incident"
    if custom_fields.get("alertid"):
        return "Vega Alert"

    return None


def _mirror_entity_type_from_args(
    args: dict[str, Any],
    remote_id: str,
    *,
    use_investigation_context: bool = True,
) -> str | None:
    """Resolve Vega Alert vs Vega Incident from mirror command args and investigation context."""
    _, hinted_suffix = _parse_mirror_id(remote_id)
    if hinted_suffix == MIRROR_ENTITY_SUFFIX_ALERT:
        return "Vega Alert"
    if hinted_suffix == MIRROR_ENTITY_SUFFIX_INCIDENT:
        return "Vega Incident"

    for raw_payload in (args.get("data"), args.get("remoteIncidentData"), args.get("incident"), args.get("delta")):
        entity_type = _entity_type_from_mirror_payload(_mirror_dict(raw_payload))
        if entity_type:
            return entity_type

    if use_investigation_context:
        incident = load_current_incident()
        entity_type = _entity_type_from_mirror_payload(incident)
        if entity_type:
            return entity_type

    entity_type = _entity_type_from_mirror_payload(
        {
            "type": args.get("incidentType") or args.get("type") or args.get("Type") or args.get("incident_type"),
        }
    )
    if entity_type:
        return entity_type

    return None


def _fetch_alert_for_mirror_lookup(
    client: Client,
    vega_id: str,
    *,
    lookup_filters: dict[str, str],
    require_vega_alert_id: bool = False,
) -> dict[str, Any]:
    """Fetch and normalize an alert for mirror resolution."""
    alert = client.get_alert_for_mirror(vega_id, **lookup_filters)
    if not alert:
        alert = client.get_alert_by_id(vega_id, **lookup_filters)
    normalized = _normalize_alert_api_entity(alert) if alert else {}
    if not normalized or not _entity_matches_remote_id(normalized, vega_id):
        return {}
    if require_vega_alert_id and not _poll_entity_is_alert(normalized):
        return {}
    return normalized


def _fetch_incident_for_mirror_lookup(
    client: Client,
    vega_id: str,
    *,
    lookup_filters: dict[str, str],
) -> dict[str, Any]:
    """Fetch and normalize an incident for mirror resolution."""
    incident = client.get_incident_for_mirror(vega_id, **lookup_filters)
    if not incident:
        incident = client.get_incident_by_id(vega_id, **lookup_filters)
    normalized = _normalize_incident_api_entity(incident) if incident else {}
    if normalized and _entity_matches_remote_id(normalized, vega_id):
        return normalized
    return {}


def _resolve_preferred_alert_entity(
    client: Client,
    vega_id: str,
    remote_id: str,
    lookup_filters: dict[str, str],
) -> tuple[dict[str, Any], str]:
    """Resolve a remote ID when the preferred entity type is Vega Alert."""
    normalized = _fetch_alert_for_mirror_lookup(client, vega_id, lookup_filters=lookup_filters)
    if normalized:
        return normalized, MIRROR_ENTITY_SUFFIX_ALERT
    demisto.info(f"Alert not found: remote_id={remote_id}")
    return {}, ""


def _resolve_preferred_incident_entity(
    client: Client,
    vega_id: str,
    remote_id: str,
    lookup_filters: dict[str, str],
) -> tuple[dict[str, Any], str]:
    """Resolve a remote ID when the preferred entity type is Vega Incident."""
    normalized = _fetch_incident_for_mirror_lookup(client, vega_id, lookup_filters=lookup_filters)
    if normalized:
        return normalized, MIRROR_ENTITY_SUFFIX_INCIDENT
    demisto.info(f"Incident not found: remote_id={remote_id}")
    return {}, ""


def _resolve_ambiguous_remote_entity(
    client: Client,
    vega_id: str,
    remote_id: str,
    lookup_filters: dict[str, str],
) -> tuple[dict[str, Any], str]:
    """Resolve a remote ID when the entity type is unknown."""
    normalized_alert = _fetch_alert_for_mirror_lookup(
        client,
        vega_id,
        lookup_filters=lookup_filters,
        require_vega_alert_id=True,
    )
    if normalized_alert:
        return normalized_alert, MIRROR_ENTITY_SUFFIX_ALERT

    demisto.info(f"Alert not found or missing vegaAlertId; trying incident lookup: remote_id={remote_id}, vega_id={vega_id}")
    normalized_incident = _fetch_incident_for_mirror_lookup(client, vega_id, lookup_filters=lookup_filters)
    if normalized_incident:
        return normalized_incident, MIRROR_ENTITY_SUFFIX_INCIDENT

    return {}, ""


def _resolve_remote_entity(
    client: Client,
    remote_id: str,
    preferred_entity_type: str | None = None,
    *,
    mirror_last_update: str | None = None,
) -> tuple[dict[str, Any], str]:
    """Resolve a mirrored remote ID to a Vega alert or incident."""
    del mirror_last_update
    vega_id, hinted_suffix = _parse_mirror_id(str(remote_id).strip())
    entity_lookup_filters = _resolve_mirror_entity_lookup_filters()
    if hinted_suffix == MIRROR_ENTITY_SUFFIX_ALERT:
        preferred_entity_type = "Vega Alert"
    elif hinted_suffix == MIRROR_ENTITY_SUFFIX_INCIDENT:
        preferred_entity_type = "Vega Incident"

    if preferred_entity_type == "Vega Alert":
        return _resolve_preferred_alert_entity(client, vega_id, remote_id, entity_lookup_filters)
    if preferred_entity_type == "Vega Incident":
        return _resolve_preferred_incident_entity(client, vega_id, remote_id, entity_lookup_filters)
    return _resolve_ambiguous_remote_entity(client, vega_id, remote_id, entity_lookup_filters)


def _resolve_mirror_entity_type_suffix(
    entity_type_suffix: str,
    preferred_entity_type: str | None,
) -> str:
    """Apply preferred entity type to the mirror entity suffix."""
    if preferred_entity_type == "Vega Incident":
        return MIRROR_ENTITY_SUFFIX_INCIDENT
    if preferred_entity_type == "Vega Alert":
        return MIRROR_ENTITY_SUFFIX_ALERT
    return entity_type_suffix


def _normalize_mirror_entity(entity: dict[str, Any], entity_type_suffix: str) -> dict[str, Any]:
    """Normalize a mirror entity based on its suffix."""
    if entity_type_suffix == MIRROR_ENTITY_SUFFIX_INCIDENT:
        return _normalize_incident_api_entity(entity)
    return _normalize_alert_api_entity(entity)


#! ---------------------------- MIRROR VEGA TO XSOAR--------------------------------------
def _build_mirror_entity_custom_fields(entity: dict[str, Any], entity_type_suffix: str) -> dict[str, str]:
    """Build custom fields for a mirrored Vega entity."""
    custom_fields: dict[str, str] = {}
    entity_id = _normalize_entity_id(entity)
    if entity_id:
        if entity_type_suffix == MIRROR_ENTITY_SUFFIX_INCIDENT:
            custom_fields["vegaincidentid"] = entity_id
        else:
            custom_fields["alertid"] = entity_id
            vega_alert_id = entity.get("vegaAlertId")
            if vega_alert_id and str(vega_alert_id).strip():
                custom_fields["vegaalertid"] = str(vega_alert_id).strip()

    status = entity.get("status")
    if status is not None and str(status).strip():
        status_field = VEGA_ALERT_STATUS_FIELD if entity_type_suffix == MIRROR_ENTITY_SUFFIX_ALERT else VEGA_INCIDENT_STATUS_FIELD
        custom_fields[status_field] = _normalize_vega_status_for_display(str(status), entity_type_suffix)

    if entity.get("severity") is not None:
        severity_field = VEGA_ALERT_SEVERITY_FIELD if entity_type_suffix == MIRROR_ENTITY_SUFFIX_ALERT else VEGA_SEVERITY_FIELD
        custom_fields[severity_field] = _normalize_vega_severity_for_display(entity.get("severity"))

    verdict = _extract_vega_verdict_from_entity(entity)
    if verdict is not None and str(_normalize_incident_verdict_value(verdict)).strip():
        custom_fields[VEGA_VERDICT_FIELD] = _normalize_vega_verdict_for_display(verdict)

    reasoning = _normalize_verdict_reasoning_for_display(entity)
    if reasoning and reasoning != VEGA_EMPTY_FIELD_DISPLAY:
        custom_fields[VEGA_VERDICT_REASONING_FIELD] = reasoning

    if "comments" in entity:
        custom_fields["vegacomments"] = _format_vega_comments_html(entity.get("comments"))
    return custom_fields


def _build_mirror_sync_object(
    entity: dict[str, Any],
    entity_type_suffix: str,
    remote_id: str | None = None,
    mirror_context: dict[str, Any] | None = None,
    preferred_entity_type: str | None = None,
) -> dict[str, Any]:
    """Build the mirrored object used by XSOAR incoming remote sync."""
    entity_type_suffix = _resolve_mirror_entity_type_suffix(entity_type_suffix, preferred_entity_type)
    entity = _normalize_mirror_entity(entity, entity_type_suffix)

    entity_id = _normalize_entity_id(entity)
    vega_entity_type = "Vega Alert" if entity_type_suffix == MIRROR_ENTITY_SUFFIX_ALERT else "Vega Incident"
    bare_entity_id = str(entity_id).strip() if entity_id else ""
    parsed_remote_id = str(remote_id).strip() if remote_id else ""
    vega_id, _ = _parse_mirror_id(parsed_remote_id) if parsed_remote_id else ("", None)
    effective_remote_id = vega_id or bare_entity_id

    raw = dict(entity)
    raw["vegaEntityType"] = vega_entity_type
    raw.update(_get_mirroring_fields(mirror_context=mirror_context))
    _apply_mirror_metadata(raw, entity_type_suffix)
    _format_raw_entity_for_xsoar(raw)

    custom_fields = _build_mirror_entity_custom_fields(entity, entity_type_suffix)
    prefixed_mirror_id = _format_dbot_mirror_id(entity_type_suffix, bare_entity_id) if bare_entity_id else ""
    sync_object: dict[str, Any] = {
        "id": bare_entity_id or effective_remote_id,
        "mirror_id": prefixed_mirror_id or bare_entity_id,
        "vegaEntityType": vega_entity_type,
        "CustomFields": custom_fields,
    }
    for key in ("status", "severity", "verdict", "verdictReasoning"):
        value = raw.get(key)
        if value is not None and str(value).strip() != "":
            sync_object[key] = value

    if "vegaComments" in raw:
        sync_object["vegaComments"] = raw["vegaComments"]

    _apply_mirror_sync_metadata(sync_object, mirror_context=mirror_context)

    return sync_object


def _build_incoming_status_sync_entries(
    entity: dict[str, Any],
    entity_type_suffix: str,
    last_update: datetime,
) -> list[dict[str, Any]]:
    """Build close or reopen entries when Vega status changed during incoming mirroring."""
    if not _entity_updated_after(entity, entity_type_suffix, last_update):
        return []

    api_status = _normalize_vega_status_for_api(str(entity.get("status") or ""), entity_type_suffix)
    if api_status in VEGA_CLOSE_STATUSES:
        return [
            {
                "Type": EntryType.NOTE,
                "Contents": {
                    "dbotIncidentClose": True,
                    "closeReason": "Resolved",
                    "closeNotes": f"Vega {entity_type_suffix} status changed to {api_status}.",
                },
                "ContentsFormat": EntryFormat.JSON,
                "Note": True,
            }
        ]
    if api_status == "REOPENED":
        return [
            {
                "Type": EntryType.NOTE,
                "Contents": {"dbotIncidentReopen": True},
                "ContentsFormat": EntryFormat.JSON,
            }
        ]
    return []


#! ---------------------------- MIRROR VEGA TO XSOAR--------------------------------------


def _normalize_mirror_entries(entries: Any) -> list[dict[str, Any]]:
    """Parse mirror War Room entries from XSOAR update-remote-system args."""
    if entries is None:
        return []
    if isinstance(entries, str):
        if not entries.strip():
            return []
        try:
            entries = json.loads(entries)
        except (json.JSONDecodeError, TypeError, ValueError):
            demisto.info("Failed to parse entries JSON")
            return []
    if isinstance(entries, dict):
        return [entries]
    if not isinstance(entries, list):
        return []
    return [entry for entry in entries if isinstance(entry, dict)]


def _collect_outgoing_entry_comments(entries: list[dict[str, Any]]) -> list[str]:
    """Collect War Room note texts that should be mirrored to Vega."""
    comments: list[str] = []
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        entry_type = entry.get("type") if entry.get("type") is not None else entry.get("Type")
        if entry_type != EntryType.NOTE:
            continue
        tags = entry.get("tags") or entry.get("Tags") or []
        if VEGA_MIRROR_TAG_FROM_VEGA in tags or VEGA_MIRROR_TAG_TO_VEGA in tags:
            continue
        contents = entry.get("contents")
        if contents is None:
            contents = entry.get("Contents")
        if contents is None:
            continue
        text = str(contents).strip()
        if text:
            comments.append(text)
    return comments


def _poll_modified_mirror_page(
    response: dict[str, Any],
    entities_key: str,
    modified_ids: list[str],
    bare_ids: set[str],
    poll_source: str,
    offset: int,
) -> tuple[int, bool]:
    """Process one modified-remote-data poll page and return whether pagination should continue."""
    entities = response.get(entities_key) or []
    for entity in entities:
        bare_id = _append_modified_remote_entity_id(modified_ids, entity, poll_source=poll_source)
        if bare_id:
            bare_ids.add(bare_id)

    if not entities:
        return 0, False

    total = response.get("total")
    if total is not None and offset + len(entities) >= int(total):
        return len(entities), False
    if len(entities) < GET_MODIFIED_REMOTE_DATA_LIMIT:
        return len(entities), False
    return len(entities), True


def _poll_modified_alerts_for_mirror(
    client: Client,
    updated_from: str,
    modified_ids: list[str],
    alert_bare_ids: set[str],
) -> None:
    """Poll updated alerts and collect modified mirror IDs."""
    offset = 0
    try:
        while True:
            response = (
                client.get_alerts(
                    updated_from=updated_from,
                    limit=GET_MODIFIED_REMOTE_DATA_LIMIT,
                    offset=offset,
                )
                or {}
            )
            api_error = response.get("error")
            if isinstance(api_error, dict) and api_error.get("message"):
                demisto.info(f"Alert poll API error: error={str(api_error.get('message'))}")

            page_count, should_continue = _poll_modified_mirror_page(
                response,
                "alerts",
                modified_ids,
                alert_bare_ids,
                MIRROR_ENTITY_SUFFIX_ALERT,
                offset,
            )
            if not should_continue:
                break
            offset += page_count

    except Exception as exc:
        demisto.info(f"Alert poll failed: error={str(exc)}")


def _poll_modified_incidents_for_mirror(
    client: Client,
    updated_from: str,
    updated_to: str,
    modified_ids: list[str],
    incident_bare_ids: set[str],
) -> None:
    """Poll updated incidents and collect modified mirror IDs."""
    offset = 0
    try:
        while True:
            response = (
                client.get_incidents(
                    updated_from=updated_from,
                    updated_to=updated_to,
                    limit=GET_MODIFIED_REMOTE_DATA_LIMIT,
                    offset=offset,
                )
                or {}
            )
            page_count, should_continue = _poll_modified_mirror_page(
                response,
                "incidents",
                modified_ids,
                incident_bare_ids,
                MIRROR_ENTITY_SUFFIX_INCIDENT,
                offset,
            )
            if not should_continue:
                break
            offset += page_count

    except Exception as exc:
        demisto.info(f"Incident poll failed: error={str(exc)}")


def _finalize_modified_mirror_ids(
    modified_ids: list[str],
    alert_bare_ids: set[str],
    incident_bare_ids: set[str],
) -> list[str]:
    """Drop ambiguous bare IDs shared by alerts and incidents."""
    shared_bare_ids = alert_bare_ids & incident_bare_ids
    finalized_ids = list(modified_ids)
    for bare_id in sorted(alert_bare_ids | incident_bare_ids):
        if bare_id in shared_bare_ids:
            demisto.info(f"Skipping ambiguous bare mirror id shared by alert and incident: remote_id={bare_id}")
            continue
        if bare_id not in finalized_ids:
            finalized_ids.append(bare_id)
    return finalized_ids


def get_modified_remote_data_command(client: Client, args: dict[str, Any]) -> GetModifiedRemoteDataResponse:
    """Return Vega alert and incident IDs updated since the last mirroring run."""
    remote_args = GetModifiedRemoteDataArgs(args)
    vega_entities = argToList(demisto.params().get("vega_entities") or ["Alerts", "Incidents"])
    fetch_alerts = "Alerts" in vega_entities
    fetch_incidents = "Incidents" in vega_entities

    demisto.info(
        f"Command started: fetch_alerts={fetch_alerts}, fetch_incidents={fetch_incidents}, "
        f"last_update={remote_args.last_update}"
    )

    modified_ids: list[str] = []
    alert_bare_ids: set[str] = set()
    incident_bare_ids: set[str] = set()

    if fetch_alerts:
        _poll_modified_alerts_for_mirror(
            client,
            _resolve_mirror_updated_from(remote_args.last_update),
            modified_ids,
            alert_bare_ids,
        )

    if fetch_incidents:
        _poll_modified_incidents_for_mirror(
            client,
            _resolve_mirror_updated_from(remote_args.last_update),
            _resolve_mirror_updated_to(),
            modified_ids,
            incident_bare_ids,
        )

    finalized_ids = _finalize_modified_mirror_ids(modified_ids, alert_bare_ids, incident_bare_ids)
    demisto.info(f"Command finished: total_ids={len(finalized_ids)}, ")
    return GetModifiedRemoteDataResponse(finalized_ids)


def _resolve_remote_entity_for_mirror(
    client: Client,
    remote_id: str,
    args: dict[str, Any],
    last_update: str | None,
) -> tuple[dict[str, Any], str, str | None, str | None]:
    """Resolve a remote entity for get-remote-data, enforcing investigation context when needed."""
    preferred_entity_type = _mirror_entity_type_from_args(args, remote_id)
    entity, entity_type_suffix = _resolve_remote_entity(
        client,
        remote_id,
        preferred_entity_type,
        mirror_last_update=last_update,
    )

    investigation_context = load_current_incident()
    context_entity_type = _entity_type_from_mirror_payload(investigation_context)
    if context_entity_type:
        context_suffix = MIRROR_ENTITY_SUFFIX_INCIDENT if context_entity_type == "Vega Incident" else MIRROR_ENTITY_SUFFIX_ALERT
        if entity_type_suffix != context_suffix:
            preferred_entity_type = context_entity_type
            entity, entity_type_suffix = _resolve_remote_entity(
                client,
                remote_id,
                preferred_entity_type,
                mirror_last_update=last_update,
            )

    if (preferred_entity_type == "Vega Incident" and entity_type_suffix == MIRROR_ENTITY_SUFFIX_ALERT) or (
        preferred_entity_type == "Vega Alert" and entity_type_suffix == MIRROR_ENTITY_SUFFIX_INCIDENT
    ):
        entity, entity_type_suffix = _resolve_remote_entity(
            client,
            remote_id,
            preferred_entity_type,
            mirror_last_update=last_update,
        )

    return entity, entity_type_suffix, preferred_entity_type, context_entity_type


def _build_not_found_mirror_response(
    remote_id: str,
    preferred_entity_type: str | None,
    context_entity_type: str | None,
) -> GetRemoteDataResponse:
    """Build a get-remote-data response when the remote entity was not found."""
    vega_id, hinted_suffix = _parse_mirror_id(remote_id)
    mirror_key = vega_id or remote_id
    effective_entity_type = preferred_entity_type or context_entity_type
    prefixed_mirror_id = mirror_key
    if effective_entity_type and mirror_key:
        mirror_suffix = MIRROR_ENTITY_SUFFIX_INCIDENT if effective_entity_type == "Vega Incident" else MIRROR_ENTITY_SUFFIX_ALERT
        prefixed_mirror_id = _format_dbot_mirror_id(mirror_suffix, mirror_key)
    elif hinted_suffix and mirror_key:
        prefixed_mirror_id = _format_dbot_mirror_id(hinted_suffix, mirror_key)

    not_found: dict[str, Any] = {
        "id": mirror_key,
        "mirror_id": prefixed_mirror_id,
    }
    if effective_entity_type:
        not_found["vegaEntityType"] = effective_entity_type
    _apply_mirror_sync_metadata(not_found)
    return GetRemoteDataResponse(mirrored_object=not_found, entries=[])


def _enrich_mirror_incident_entity(client: Client, entity: dict[str, Any], last_update: str | None) -> dict[str, Any]:
    """Fetch additional incident details needed for incoming mirror sync."""
    entity_id = _normalize_entity_id(entity)
    if not entity_id:
        return entity

    incident_lookup_filters = _resolve_mirror_incident_lookup_filters(last_update)
    details = client.get_incident_by_id(entity_id, **incident_lookup_filters)
    if not isinstance(details, dict) or not details:
        return entity

    for key in ("verdictReasoning", "verdict", "comments", "status", "severity", "lastUpdated", "userVerdict"):
        if key in details and details[key] is not None:
            entity[key] = details[key]
    return _normalize_incident_api_entity(entity)


def _build_incoming_mirror_comment_entries(entity: dict[str, Any], last_update_dt: datetime) -> list[dict[str, Any]]:
    """Build incoming mirror war room entries for new Vega comments."""
    entries: list[dict[str, Any]] = []
    comments = entity.get("comments")
    if not isinstance(comments, list):
        return entries

    for comment in comments:
        if not isinstance(comment, dict) or _is_empty_vega_comment_text(comment.get("text")):
            continue
        added_at = _parse_entity_created_at(comment.get("addedAt"))
        if added_at is None or _normalize_fetch_datetime(added_at) <= _normalize_fetch_datetime(last_update_dt):
            continue
        author = _format_comment_author(comment.get("addedBy"))
        timestamp = _format_comment_display_timestamp(comment.get("addedAt"))
        comment_text = str(comment.get("text") or "").strip()
        entries.append(
            _build_comment_war_room_entry(
                f"{author} ({timestamp}): {comment_text}",
                tags=[VEGA_MIRROR_TAG_FROM_VEGA],
            )
        )
    return entries


def _build_get_remote_data_error_response(remote_id: str, args: dict[str, Any], exc: Exception) -> GetRemoteDataResponse:
    """Build a get-remote-data error response that preserves mirror metadata."""
    vega_id, _ = _parse_mirror_id(remote_id)
    mirror_key = vega_id or remote_id
    preferred_entity_type = _mirror_entity_type_from_args(args, remote_id)
    error_object: dict[str, Any] = {
        "id": mirror_key,
        "in_mirror_error": str(exc),
    }
    if preferred_entity_type:
        error_object["vegaEntityType"] = preferred_entity_type
    error_object["mirror_id"] = mirror_key
    _apply_mirror_sync_metadata(error_object)
    return GetRemoteDataResponse(mirrored_object=error_object, entries=[])


def get_remote_data_command(
    client: Client,
    args: dict[str, Any],
    integration_url: str | None = None,
) -> GetRemoteDataResponse:
    """Fetch updated Vega alert or incident data and incoming mirror entries."""
    del integration_url
    remote_args = GetRemoteDataArgs(args)
    remote_id = remote_args.remote_incident_id
    last_update_dt = _parse_mirror_last_update(remote_args.last_update)

    demisto.info(f"Command started: remote_id={remote_id}, last_update={remote_args.last_update}")

    try:
        entity, entity_type_suffix, preferred_entity_type, context_entity_type = _resolve_remote_entity_for_mirror(
            client,
            remote_id,
            args,
            remote_args.last_update,
        )
        if not entity:
            demisto.info(f"Remote entity not found: remote_id={remote_id}")
            return _build_not_found_mirror_response(remote_id, preferred_entity_type, context_entity_type)

        if entity_type_suffix == MIRROR_ENTITY_SUFFIX_INCIDENT:
            entity = _enrich_mirror_incident_entity(client, entity, remote_args.last_update)

        mirror_context = (
            _mirror_dict(args.get("data")) or _mirror_dict(args.get("remoteIncidentData")) or _mirror_dict(args.get("incident"))
        )
        mirrored_object = _build_mirror_sync_object(
            entity,
            entity_type_suffix,
            remote_id=remote_id,
            mirror_context=mirror_context or None,
            preferred_entity_type=preferred_entity_type,
        )

        entries = _build_incoming_mirror_comment_entries(entity, last_update_dt)
        entries.extend(_build_incoming_status_sync_entries(entity, entity_type_suffix, last_update_dt))

        return GetRemoteDataResponse(mirrored_object=mirrored_object, entries=entries)
    except Exception as exc:
        demisto.info(f"Command failed: remote_id={remote_id}, error={str(exc)}")
        return _build_get_remote_data_error_response(remote_id, args, exc)


def _parse_outgoing_mirror_inc_status(parsed_args: UpdateRemoteSystemArgs) -> int | None:
    """Parse the XSOAR investigation status from outgoing mirror args."""
    if parsed_args.inc_status is None or parsed_args.inc_status == "":
        return None
    try:
        return int(parsed_args.inc_status)
    except (TypeError, ValueError):
        return None


def _build_outgoing_alert_mirror_update(
    delta: dict[str, Any],
    data: dict[str, Any],
    inc_status: int | None,
    enabled_fields: set[str] | None = None,
) -> dict[str, Any]:
    """Build the outgoing mirror update payload for a Vega alert."""
    del data
    update_input: dict[str, Any] = {}
    entity_type_suffix = MIRROR_ENTITY_SUFFIX_ALERT
    active_fields = enabled_fields if enabled_fields is not None else _resolve_outgoing_mirror_fields()

    if OUTGOING_MIRROR_FIELD_STATUS in active_fields:
        if inc_status == IncidentStatus.DONE:
            update_input["status"] = "RESOLVED"
        else:
            status = _mirror_delta_changed_value(VEGA_ALERT_STATUS_FIELD, delta, entity_type_suffix)
            if status is not None and str(status).strip():
                update_input["status"] = _validate_alert_status_value(str(status))

    if OUTGOING_MIRROR_FIELD_VERDICT in active_fields:
        verdict = _mirror_delta_changed_value(VEGA_VERDICT_FIELD, delta, entity_type_suffix)
        if verdict is not None and str(verdict).strip():
            update_input["verdict"] = _validate_verdict_value(str(verdict))

    if OUTGOING_MIRROR_FIELD_SEVERITY in active_fields:
        severity = _mirror_delta_changed_value(VEGA_ALERT_SEVERITY_FIELD, delta, entity_type_suffix)
        if severity is not None and str(severity).strip():
            update_input["severity"] = _validate_severity_value(str(severity))

    if OUTGOING_MIRROR_FIELD_VERDICT_REASONING in active_fields:
        verdict_reasoning = _mirror_delta_changed_value(VEGA_VERDICT_REASONING_FIELD, delta, entity_type_suffix)
        if verdict_reasoning is not None and str(verdict_reasoning).strip():
            update_input["verdictReasoning"] = str(verdict_reasoning).strip()

    if OUTGOING_MIRROR_FIELD_COMMENTS in active_fields:
        comment = _outgoing_mirror_comment_value(_mirror_delta_changed_value(VEGA_NEW_COMMENT_FIELD, delta, entity_type_suffix))
        if comment is not None:
            update_input["comment"] = comment
    return update_input


def _build_outgoing_incident_mirror_update(
    delta: dict[str, Any],
    data: dict[str, Any],
    inc_status: int | None,
    enabled_fields: set[str] | None = None,
) -> dict[str, Any]:
    """Build the outgoing mirror update payload for a Vega incident."""
    update_input: dict[str, Any] = {}
    entity_type_suffix = MIRROR_ENTITY_SUFFIX_INCIDENT
    active_fields = enabled_fields if enabled_fields is not None else _resolve_outgoing_mirror_fields()
    mirror_verdict = OUTGOING_MIRROR_FIELD_VERDICT in active_fields
    mirror_verdict_reasoning = OUTGOING_MIRROR_FIELD_VERDICT_REASONING in active_fields

    if OUTGOING_MIRROR_FIELD_STATUS in active_fields:
        if inc_status == IncidentStatus.DONE:
            update_input["status"] = "RESOLVED"
        else:
            status = _mirror_delta_changed_value(VEGA_INCIDENT_STATUS_FIELD, delta, entity_type_suffix)
            if status is None or not str(status).strip():
                status = _mirror_delta_changed_value(VEGA_ALERT_STATUS_FIELD, delta, entity_type_suffix)
            if status is not None and str(status).strip():
                update_input["status"] = _validate_incident_status_value(str(status))

    if OUTGOING_MIRROR_FIELD_SEVERITY in active_fields:
        severity = _mirror_delta_changed_value(VEGA_SEVERITY_FIELD, delta, entity_type_suffix)
        if severity is not None and str(severity).strip():
            update_input["severity"] = _validate_severity_value(str(severity))

    if mirror_verdict or mirror_verdict_reasoning:
        verdict = _mirror_delta_changed_value(VEGA_VERDICT_FIELD, delta, entity_type_suffix)
        verdict_reasoning = _mirror_delta_changed_value(VEGA_VERDICT_REASONING_FIELD, delta, entity_type_suffix)
        if mirror_verdict and verdict is not None and str(verdict).strip():
            update_input["verdict"] = {
                "value": _validate_verdict_value(str(verdict)),
                "reasoning": str(verdict_reasoning or "") if mirror_verdict_reasoning else "",
            }
        elif mirror_verdict_reasoning and verdict_reasoning is not None and str(verdict_reasoning).strip():
            current_verdict = _mirror_field_value(VEGA_VERDICT_FIELD, {}, data)
            update_input["verdict"] = {
                "value": _validate_verdict_value(str(current_verdict or "NA")),
                "reasoning": str(verdict_reasoning).strip(),
            }

    if OUTGOING_MIRROR_FIELD_COMMENTS in active_fields:
        comment = _outgoing_mirror_comment_value(_mirror_delta_changed_value(VEGA_NEW_COMMENT_FIELD, delta, entity_type_suffix))
        if comment is not None:
            update_input["comment"] = comment
    return update_input


def _push_outgoing_mirror_entity_update(
    client: Client,
    entity_type_suffix: str,
    vega_id: str,
    remote_id: str,
    update_input: dict[str, Any],
) -> None:
    """Push outgoing mirror field updates to Vega."""
    if not update_input:
        entity_label = "alert" if entity_type_suffix == MIRROR_ENTITY_SUFFIX_ALERT else "incident"
        demisto.info(f"No {entity_label} fields to push: remote_id={remote_id}")
        return

    if entity_type_suffix == MIRROR_ENTITY_SUFFIX_ALERT:
        client.update_alerts({**update_input, "alertIds": [vega_id]})
    else:
        client.update_incidents({**update_input, "incidentIds": [vega_id]})


def _mirror_outgoing_war_room_comments(
    client: Client,
    mirror_entries: list[dict[str, Any]],
    entity_type_suffix: str,
    vega_id: str,
    remote_id: str,
    enabled_fields: set[str] | None = None,
) -> None:
    """Mirror eligible War Room comments to Vega."""
    active_fields = enabled_fields if enabled_fields is not None else _resolve_outgoing_mirror_fields()
    if OUTGOING_MIRROR_FIELD_COMMENTS not in active_fields:
        demisto.info(f"War Room comments filtered by outgoing mirror field config: remote_id={remote_id}")
        return

    for comment in _collect_outgoing_entry_comments(mirror_entries):
        demisto.info(f"Mirroring War Room comment to Vega: remote_id={remote_id}")
        if entity_type_suffix == MIRROR_ENTITY_SUFFIX_ALERT:
            client.update_alerts({"alertIds": [vega_id], "comment": comment})
        else:
            client.update_incidents({"incidentIds": [vega_id], "comment": comment})


def _resolve_outgoing_mirror_entity(
    client: Client,
    args: dict[str, Any],
    remote_id: str,
    delta: dict[str, Any],
    data: dict[str, Any],
) -> tuple[dict[str, Any], str, str | None]:
    """Resolve the Vega entity targeted by an outgoing mirror update."""
    mirror_args = dict(args)
    if data:
        mirror_args["data"] = data
    if delta:
        mirror_args["delta"] = delta
    preferred_entity_type = _mirror_entity_type_from_args(mirror_args, remote_id, use_investigation_context=True)
    demisto.info(
        f"Resolved mirror context: remote_id={remote_id}, entity_type={preferred_entity_type}, "
        f"delta_keys={','.join(sorted(delta.keys())) or 'none'}"
    )

    mirror_last_update = str(args.get("lastUpdate") or args.get("last_update") or "").strip() or None
    entity, entity_type_suffix = _resolve_remote_entity(
        client,
        remote_id,
        preferred_entity_type,
        mirror_last_update=mirror_last_update,
    )
    if (preferred_entity_type == "Vega Alert" and entity_type_suffix == MIRROR_ENTITY_SUFFIX_INCIDENT) or (
        preferred_entity_type == "Vega Incident" and entity_type_suffix == MIRROR_ENTITY_SUFFIX_ALERT
    ):
        demisto.info(
            f"Re-resolving entity with preferred type: remote_id={remote_id}, "
            f"preferred_entity_type={preferred_entity_type}, resolved_as={entity_type_suffix}"
        )
        entity, entity_type_suffix = _resolve_remote_entity(
            client,
            remote_id,
            preferred_entity_type,
            mirror_last_update=mirror_last_update,
        )
    return entity, entity_type_suffix, preferred_entity_type


def update_remote_system_command(client: Client, args: dict[str, Any]) -> str:
    """Push XSOAR investigation changes to Vega when outgoing mirroring is enabled."""
    parsed_args = UpdateRemoteSystemArgs(args)
    remote_id = parsed_args.remote_incident_id or ""
    if not remote_id:
        demisto.info("Command skipped; no remote ID")
        return remote_id

    demisto.info(
        f"Command started: remote_id={remote_id}, incident_changed={parsed_args.incident_changed}, "
        f"entry_count={len(parsed_args.entries or [])}"
    )

    if not _is_xsoar_to_vega_mirroring_enabled():
        demisto.info(f"Outgoing mirroring disabled; skipping: remote_id={remote_id}")
        return remote_id

    if not _mirror_bool(parsed_args.incident_changed) and not parsed_args.entries:
        demisto.info(f"No changes to mirror; skipping: remote_id={remote_id}")
        return remote_id

    delta = _mirror_dict(parsed_args.delta)
    data = _mirror_dict(parsed_args.data)
    mirror_entries = _normalize_mirror_entries(parsed_args.entries)
    vega_id, _ = _parse_mirror_id(remote_id)
    inc_status = _parse_outgoing_mirror_inc_status(parsed_args)
    enabled_fields = _resolve_outgoing_mirror_fields()

    try:
        entity, entity_type_suffix, _ = _resolve_outgoing_mirror_entity(client, args, remote_id, delta, data)
        if not entity:
            demisto.info(f"Remote entity not found: remote_id={remote_id}")
            return remote_id

        if _mirror_bool(parsed_args.incident_changed):
            if entity_type_suffix == MIRROR_ENTITY_SUFFIX_ALERT:
                update_input = _build_outgoing_alert_mirror_update(delta, data, inc_status, enabled_fields)
            else:
                update_input = _build_outgoing_incident_mirror_update(delta, data, inc_status, enabled_fields)
            _push_outgoing_mirror_entity_update(client, entity_type_suffix, vega_id, remote_id, update_input)

        _mirror_outgoing_war_room_comments(
            client,
            mirror_entries,
            entity_type_suffix,
            vega_id,
            remote_id,
            enabled_fields,
        )
        demisto.info(f"Command finished: remote_id={remote_id}")
    except Exception as exc:
        demisto.info(f"Command failed: remote_id={remote_id}, error={str(exc)}, error_type={type(exc).__name__}")

    return remote_id


def get_mapping_fields_command() -> GetMappingFieldsResponse:
    """Return outgoing mirroring fields for Vega Alert and Vega Incident investigations."""
    mapping_response = GetMappingFieldsResponse()

    alert_scheme = SchemeTypeMapping(type_name="Vega Alert")
    for field_name, descriptions in VEGA_OUTGOING_MIRROR_FIELDS["Vega Alert"].items():
        alert_scheme.add_field(name=field_name, description=descriptions[0])
    mapping_response.add_scheme_type(alert_scheme)

    incident_scheme = SchemeTypeMapping(type_name="Vega Incident")
    for field_name, descriptions in VEGA_OUTGOING_MIRROR_FIELDS["Vega Incident"].items():
        incident_scheme.add_field(name=field_name, description=descriptions[0])
    mapping_response.add_scheme_type(incident_scheme)

    return mapping_response


def _handle_fetch_entity_error(entity_label: str, exc: Exception) -> None:
    """Log transient fetch failures without advancing cursor; re-raise permanent errors."""
    if _is_retryable_http_error(exc):
        demisto.error(
            f"Vega {entity_label} fetch skipped due to a transient API error after retries: {exc}. "
            f"The {entity_label} cursor was not advanced and will retry on the next fetch cycle."
        )
        return
    raise exc


def _fetch_filters_changed(last_run: dict, fetch_config_key: str, fetch_config: str) -> bool:
    """Return True when fetch filters changed since the previous run."""
    previous_config = last_run.get(fetch_config_key)
    return previous_config is not None and previous_config != fetch_config


def _clear_fetch_pagination_state(next_run: dict, offset_key: str, pagination_from_key: str) -> None:
    """Drop saved offset pagination for an entity type."""
    next_run.pop(offset_key, None)
    next_run.pop(pagination_from_key, None)


def _batch_fetch_last_run(
    last_run: dict,
    next_run: dict,
    *,
    offset_key: str,
    pagination_from_key: str,
    fetch_config_key: str,
    fetch_config: str,
) -> dict:
    """Build the last_run view used for API pagination.

    When fetch filters change, discard stale offset state so the next query uses the
    stored cursor timestamp instead of an old backfill window.
    """
    if not _fetch_filters_changed(last_run, fetch_config_key, fetch_config):
        return last_run

    _clear_fetch_pagination_state(next_run, offset_key, pagination_from_key)
    batch_run = dict(last_run)
    batch_run.pop(offset_key, None)
    batch_run.pop(pagination_from_key, None)
    return batch_run


def _is_resuming_fetch_pagination(
    last_run: dict,
    offset_key: str,
    fetch_config_key: str,
    fetch_config: str,
) -> bool:
    """Return True only when continuing offset pagination for the same filter set."""
    return last_run.get(offset_key) is not None and not _fetch_filters_changed(last_run, fetch_config_key, fetch_config)


def validate_max_fetch(max_fetch: int | str | None) -> None:
    """Validate that max_fetch is an integer between 1 and 50 inclusive."""
    parsed = arg_to_number(max_fetch, arg_name="max_fetch", required=False)
    if parsed is None or parsed < MAX_FETCH_MIN or parsed > MAX_FETCH_CAP:
        raise ValueError(MAX_FETCH_ERROR)


def _resolve_max_fetch(max_fetch: int | str | None) -> int:
    """Return the combined per-fetch limit, defaulting to 50 when the value is invalid."""
    try:
        validate_max_fetch(max_fetch)
    except ValueError:
        return DEFAULT_MAX_FETCH
    return int(arg_to_number(max_fetch, arg_name="max_fetch", required=False))  # type: ignore[arg-type]


def _fetch_vega_entity_batch(
    last_run: dict,
    next_run: dict,
    *,
    offset_key: str,
    pagination_from_key: str,
    default_from_time: str,
    limit: int,
    fetch_func: Callable[..., dict],
    entities_key: str,
    **fetch_kwargs: Any,
) -> list[dict]:
    """Fetch up to `limit` Vega entities and store offset state when more remain."""
    saved_offset = last_run.get(offset_key)
    offset = int(saved_offset) if saved_offset is not None else 0
    from_time = str(last_run.get(pagination_from_key) or default_from_time) if offset > 0 else default_from_time

    entities, next_offset = _fetch_paginated_entities(
        fetch_func,
        entities_key=entities_key,
        max_entities=limit,
        start_offset=offset,
        from_time=from_time,
        **fetch_kwargs,
    )

    if next_offset is not None:
        next_run[offset_key] = next_offset
        next_run[pagination_from_key] = from_time
    else:
        next_run.pop(offset_key, None)
        next_run.pop(pagination_from_key, None)

    return entities


def _fetch_incident_timeline_events(client: Client, incident_id: str) -> list[dict]:
    """Fetch timeline events for a Vega incident."""
    try:
        timeline_result = client.get_incident_timeline(str(incident_id))
        fetched_events = timeline_result.get("events")
        if isinstance(fetched_events, list):
            return [event for event in fetched_events if isinstance(event, dict)]
    except Exception:
        return []
    return []


def _ingest_fetched_incidents(
    client: Client,
    last_run: dict,
    next_run: dict,
    xsoar_incidents: list[dict],
    *,
    incidents_from_time: str,
    incidents_last_fetch: str,
    incidents_last_ids: list[str],
    incidents_fetch_config: str,
    incident_severities: list[str] | None,
    incident_statuses: list[str] | None,
    incident_verdicts: list[str] | None,
    limit: int,
    backfill_days: str | int | None = None,
    lookback_minutes: int = DEFAULT_LOOKBACK_MINUTES,
) -> int:
    try:
        batch_last_run = _batch_fetch_last_run(
            last_run,
            next_run,
            offset_key=INCIDENTS_OFFSET_KEY,
            pagination_from_key=INCIDENTS_PAGINATION_FROM_KEY,
            fetch_config_key="incidents_fetch_config",
            fetch_config=incidents_fetch_config,
        )
        incidents = _fetch_vega_entity_batch(
            batch_last_run,
            next_run,
            offset_key=INCIDENTS_OFFSET_KEY,
            pagination_from_key=INCIDENTS_PAGINATION_FROM_KEY,
            default_from_time=incidents_from_time,
            limit=limit,
            fetch_func=client.get_incidents,
            entities_key="incidents",
            severities=incident_severities,
            statuses=incident_statuses,
            verdicts=incident_verdicts,
        )

        previous_ids = set(incidents_last_ids)
        new_ids: list[str] = []
        duplicate_ids: list[str] = []
        ingested: list[dict] = []
        parsed_last_fetch = _parse_entity_created_at(incidents_last_fetch)
        max_created_at_dt = _normalize_fetch_datetime(parsed_last_fetch) if parsed_last_fetch else None

        current_cycle_ids = list(next_run.get("incidents_last_ids", []))

        for incident in incidents:
            incident_id = _normalize_entity_id(incident)
            if not incident_id:
                continue

            current_cycle_ids.append(incident_id)

            created_at_raw = _parse_entity_created_at(incident.get("createdAt"))
            if created_at_raw:
                dt = _normalize_fetch_datetime(created_at_raw)
                if max_created_at_dt is None or dt > max_created_at_dt:
                    max_created_at_dt = dt

            if incident_id in previous_ids:
                duplicate_ids.append(incident_id)
                continue

            new_ids.append(incident_id)
            timeline_events = _fetch_incident_timeline_events(client, incident_id) if incident_id else []
            xsoar_incidents.append(incident_to_xsoar_incident(incident, timeline_events=timeline_events))
            ingested.append(incident)

        next_run["incidents_last_ids"] = list(set(current_cycle_ids))
        if new_ids and max_created_at_dt:
            next_run["incidents_last_fetch"] = _format_fetch_timestamp(max_created_at_dt)
        elif not new_ids:
            next_run["incidents_last_fetch"] = _current_fetch_timestamp()

        next_run["incidents_fetch_config"] = incidents_fetch_config
        return len(ingested)
    except Exception as exc:
        _handle_fetch_entity_error("incidents", exc)
        return 0


def _ingest_fetched_alerts(
    client: Client,
    last_run: dict,
    next_run: dict,
    xsoar_incidents: list[dict],
    *,
    alerts_from_time: str,
    alerts_last_fetch: str,
    alerts_last_ids: list[str],
    alerts_fetch_config: str,
    alert_severities: list[str] | None,
    alert_statuses: list[str] | None,
    alert_verdicts: list[str] | None,
    has_related_incidents: bool | None,
    integration_url: str | None,
    limit: int,
    backfill_days: str | int | None = None,
    lookback_minutes: int = DEFAULT_LOOKBACK_MINUTES,
) -> int:
    try:
        batch_last_run = _batch_fetch_last_run(
            last_run,
            next_run,
            offset_key=ALERTS_OFFSET_KEY,
            pagination_from_key=ALERTS_PAGINATION_FROM_KEY,
            fetch_config_key="alerts_fetch_config",
            fetch_config=alerts_fetch_config,
        )
        alerts = _fetch_vega_entity_batch(
            batch_last_run,
            next_run,
            offset_key=ALERTS_OFFSET_KEY,
            pagination_from_key=ALERTS_PAGINATION_FROM_KEY,
            default_from_time=alerts_from_time,
            limit=limit,
            fetch_func=client.get_alerts,
            entities_key="alerts",
            severities=alert_severities,
            statuses=alert_statuses,
            verdicts=alert_verdicts,
            has_related_incidents=has_related_incidents,
        )

        previous_ids = set(alerts_last_ids)
        new_ids: list[str] = []
        duplicate_ids: list[str] = []
        ingested: list[dict] = []
        parsed_last_fetch = _parse_entity_created_at(alerts_last_fetch)
        max_created_at_dt = _normalize_fetch_datetime(parsed_last_fetch) if parsed_last_fetch else None

        current_cycle_ids = list(next_run.get("alerts_last_ids", []))

        for alert in alerts:
            alert_id = _normalize_entity_id(alert)
            if not alert_id:
                continue

            current_cycle_ids.append(alert_id)

            created_at_raw = _parse_entity_created_at(alert.get("createdAt"))
            if created_at_raw:
                dt = _normalize_fetch_datetime(created_at_raw)
                if max_created_at_dt is None or dt > max_created_at_dt:
                    max_created_at_dt = dt

            if alert_id in previous_ids:
                duplicate_ids.append(alert_id)
                continue

            new_ids.append(alert_id)
            xsoar_incidents.append(alert_to_incident(alert, integration_url=integration_url, client=client))
            ingested.append(alert)

        next_run["alerts_last_ids"] = list(set(current_cycle_ids))
        if new_ids and max_created_at_dt:
            next_run["alerts_last_fetch"] = _format_fetch_timestamp(max_created_at_dt)
        elif not new_ids:
            next_run["alerts_last_fetch"] = _current_fetch_timestamp()

        next_run["alerts_fetch_config"] = alerts_fetch_config
        return len(ingested)
    except Exception as exc:
        _handle_fetch_entity_error("alerts", exc)
        return 0


def fetch_incidents_command(
    client: Client,
    last_run: dict,
    fetch_alerts: bool,
    fetch_incidents: bool,
    alert_severities: list[str] | None,
    alert_statuses: list[str] | None,
    alert_verdicts: list[str] | None,
    has_related_incidents: bool | None,
    incident_severities: list[str] | None,
    incident_statuses: list[str] | None,
    incident_verdicts: list[str] | None,
    first_fetch_time: str,
    backfill_days: str | int | None = None,
    integration_url: str | None = None,
    max_fetch: int = DEFAULT_MAX_FETCH,
    lookback_minutes: int = DEFAULT_LOOKBACK_MINUTES,
) -> tuple[dict, list[dict]]:
    xsoar_incidents: list[dict] = []
    next_run: dict = dict(last_run)
    next_run.pop("alerts_seen_ids", None)
    next_run.pop("incidents_seen_ids", None)
    next_run.pop("vega_backfill_days", None)

    alerts_fetch_config = _build_fetch_filter_fingerprint(
        alert_severities,
        alert_statuses,
        alert_verdicts,
        has_related_incidents,
    )
    incidents_fetch_config = _build_fetch_filter_fingerprint(incident_severities, incident_statuses, incident_verdicts)

    remaining = max_fetch
    working_run = last_run
    incidents_touched = False
    alerts_touched = False

    def _get_from_time(last_fetch_key: str) -> str:
        last_fetch = working_run.get(last_fetch_key)
        if last_fetch:
            return _apply_lookback_to_from_time(last_fetch, lookback_minutes)
        return first_fetch_time

    incidents_last_fetch = working_run.get("incidents_last_fetch") or first_fetch_time
    alerts_last_fetch = working_run.get("alerts_last_fetch") or first_fetch_time

    if fetch_incidents and remaining > 0 and working_run.get(INCIDENTS_OFFSET_KEY) is not None:
        incidents_from_time = _get_from_time("incidents_last_fetch")
        ingested_incidents = _ingest_fetched_incidents(
            client,
            working_run,
            next_run,
            xsoar_incidents,
            incidents_from_time=incidents_from_time,
            incidents_last_fetch=incidents_last_fetch,
            incidents_last_ids=working_run.get("incidents_last_ids", []),
            incidents_fetch_config=incidents_fetch_config,
            incident_severities=incident_severities,
            incident_statuses=incident_statuses,
            incident_verdicts=incident_verdicts,
            limit=remaining,
            backfill_days=backfill_days,
            lookback_minutes=lookback_minutes,
        )
        remaining -= ingested_incidents
        working_run = next_run
        incidents_touched = True

    if (
        fetch_alerts
        and remaining > 0
        and working_run.get(INCIDENTS_OFFSET_KEY) is None
        and working_run.get(ALERTS_OFFSET_KEY) is not None
    ):
        alerts_from_time = _get_from_time("alerts_last_fetch")
        ingested_alerts = _ingest_fetched_alerts(
            client,
            working_run,
            next_run,
            xsoar_incidents,
            alerts_from_time=alerts_from_time,
            alerts_last_fetch=alerts_last_fetch,
            alerts_last_ids=working_run.get("alerts_last_ids", []),
            alerts_fetch_config=alerts_fetch_config,
            alert_severities=alert_severities,
            alert_statuses=alert_statuses,
            alert_verdicts=alert_verdicts,
            has_related_incidents=has_related_incidents,
            integration_url=integration_url,
            limit=remaining,
            backfill_days=backfill_days,
            lookback_minutes=lookback_minutes,
        )
        remaining -= ingested_alerts
        working_run = next_run
        alerts_touched = True

    if fetch_incidents and remaining > 0 and not incidents_touched and next_run.get(INCIDENTS_OFFSET_KEY) is None:
        incidents_from_time = _get_from_time("incidents_last_fetch")
        ingested_incidents = _ingest_fetched_incidents(
            client,
            working_run,
            next_run,
            xsoar_incidents,
            incidents_from_time=incidents_from_time,
            incidents_last_fetch=incidents_last_fetch,
            incidents_last_ids=working_run.get("incidents_last_ids", []),
            incidents_fetch_config=incidents_fetch_config,
            incident_severities=incident_severities,
            incident_statuses=incident_statuses,
            incident_verdicts=incident_verdicts,
            limit=remaining,
            backfill_days=backfill_days,
            lookback_minutes=lookback_minutes,
        )
        remaining -= ingested_incidents
        working_run = next_run

    if (
        fetch_alerts
        and remaining > 0
        and not alerts_touched
        and next_run.get(INCIDENTS_OFFSET_KEY) is None
        and next_run.get(ALERTS_OFFSET_KEY) is None
    ):
        alerts_from_time = _get_from_time("alerts_last_fetch")
        _ingest_fetched_alerts(
            client,
            working_run,
            next_run,
            xsoar_incidents,
            alerts_from_time=alerts_from_time,
            alerts_last_fetch=alerts_last_fetch,
            alerts_last_ids=working_run.get("alerts_last_ids", []),
            alerts_fetch_config=alerts_fetch_config,
            alert_severities=alert_severities,
            alert_statuses=alert_statuses,
            alert_verdicts=alert_verdicts,
            has_related_incidents=has_related_incidents,
            integration_url=integration_url,
            limit=remaining,
            backfill_days=backfill_days,
            lookback_minutes=lookback_minutes,
        )

    return next_run, xsoar_incidents


def test_module(
    client: Client,
    backfill_days: str | int | None = None,
    max_fetch: int | str | None = None,
    lookback_minutes: int | str | None = None,
):
    try:
        validate_max_fetch(max_fetch)
        validate_lookback_minutes(lookback_minutes)
        client.test_connection(backfill_days)
        return "ok"
    except Exception as e:
        return str(e)


def _parse_vega_integration_params(params: dict[str, Any]) -> dict[str, Any]:
    """Parse Vega integration instance parameters used across commands."""
    vega_entities = argToList(params.get("vega_entities") if params.get("vega_entities") is not None else ["Alerts", "Incidents"])
    backfill_days = params.get("backfill_days")
    return {
        "base_url": params.get("url"),
        "access_key": params.get("access_key", {}).get("password").strip(),
        "access_key_id": params.get("access_key_id", {}).get("password").strip(),
        "verify_certificate": not argToBoolean(params.get("insecure", False)),
        "proxy": argToBoolean(params.get("proxy", False)),
        "fetch_alerts": "Alerts" in vega_entities,
        "fetch_incidents": "Incidents" in vega_entities,
        "alert_severities": filter_alert_severities(argToList(params.get("alert_severities")) or None),
        "alert_statuses": filter_alert_statuses(argToList(params.get("alert_statuses")) or None),
        "alert_verdicts": filter_alert_verdicts(argToList(params.get("alert_verdicts")) or None),
        "has_related_incidents": resolve_has_related_incidents(argToList(params.get("alert_has_related_incidents"))),
        "incident_severities": filter_incident_severities(argToList(params.get("incident_severities")) or None),
        "incident_statuses": filter_incident_statuses(argToList(params.get("incident_statuses")) or None),
        "incident_verdicts": filter_incident_verdicts(argToList(params.get("incident_verdicts")) or None),
        "backfill_days": backfill_days,
        "first_fetch_time": parse_backfill_days(backfill_days),
        "max_fetch": _resolve_max_fetch(params.get("max_fetch")),
        "lookback_minutes": _parse_lookback_minutes(params.get("lookback_minutes")),
    }


def _build_vega_client(config: dict[str, Any]) -> Client:
    """Create a Vega API client from parsed integration parameters."""
    return Client(
        base_url=config["base_url"],
        verify=config["verify_certificate"],
        proxy=config["proxy"],
        access_key=config["access_key"],
        access_key_id=config["access_key_id"],
    )


def _dispatch_vega_command(client: Client, command: str, config: dict[str, Any]) -> None:
    """Route a Vega integration command to its handler."""
    command_handlers: dict[str, Callable[..., None]] = {
        "test-module": lambda: return_results(
            test_module(
                client, config["backfill_days"], demisto.params().get("max_fetch"), demisto.params().get("lookback_minutes")
            )
        ),
        "vega-get-alert-events": lambda: return_results(fetch_alert_events_command(client, demisto.args())),
        "vega-set-detections-state": lambda: return_results(set_detections_state_command(client, demisto.args())),
        "vega-update-detections": lambda: return_results(update_detections_command(client, demisto.args())),
        "vega-update-alert": lambda: return_results(update_alert_command(client, demisto.args())),
        "vega-update-incident": lambda: return_results(update_incident_command(client, demisto.args())),
        "get-remote-data": lambda: return_results(
            get_remote_data_command(client, demisto.args(), integration_url=config["base_url"])
        ),
        "get-modified-remote-data": lambda: return_results(get_modified_remote_data_command(client, demisto.args())),
        "update-remote-system": lambda: return_results(update_remote_system_command(client, demisto.args())),
        "get-mapping-fields": lambda: return_results(get_mapping_fields_command()),
    }

    if command == "fetch-incidents":
        last_run = demisto.getLastRun()
        next_run, xsoar_incidents = fetch_incidents_command(
            client=client,
            last_run=last_run,
            fetch_alerts=config["fetch_alerts"],
            fetch_incidents=config["fetch_incidents"],
            alert_severities=config["alert_severities"],
            alert_statuses=config["alert_statuses"],
            alert_verdicts=config["alert_verdicts"],
            has_related_incidents=config["has_related_incidents"],
            incident_severities=config["incident_severities"],
            incident_statuses=config["incident_statuses"],
            incident_verdicts=config["incident_verdicts"],
            first_fetch_time=config["first_fetch_time"],
            backfill_days=config["backfill_days"],
            integration_url=config["base_url"],
            max_fetch=config["max_fetch"],
            lookback_minutes=config["lookback_minutes"],
        )
        demisto.setLastRun(next_run)
        demisto.incidents(xsoar_incidents)
        return

    handler = command_handlers.get(command)
    if handler is None:
        raise NotImplementedError(f"Command {command} is not implemented")
    handler()


def main() -> None:
    command = demisto.command()
    _suppress_noisy_http_integration_logs()

    try:
        config = _parse_vega_integration_params(demisto.params())
        client = _build_vega_client(config)
        _dispatch_vega_command(client, command, config)
    except Exception as e:
        return_error(f"Failed to execute {command} command.\nError:\n{str(e)}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
