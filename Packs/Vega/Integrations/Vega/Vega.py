import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
import html as html_module
import math
import re
import time
from collections.abc import Callable
from datetime import datetime, timedelta, UTC

# requests.packages.urllib3.disable_warnings() # pylint: disable=no-member

VEGA_SEVERITY_TO_XSOAR = {
    "LOW": IncidentSeverity.LOW,
    "MEDIUM": IncidentSeverity.MEDIUM,
    "HIGH": IncidentSeverity.HIGH,
    "CRITICAL": IncidentSeverity.CRITICAL,
}

GET_ALERTS_QUERY = (
    "query GetAlerts($alertNames: [String!], $alertIds: [ID!], $alertSeverities: [AlertSeverity!], "
    "$statuses: [AlertStatus!], $detectionIds: [ID!], $dataSourceNames: [String!], "
    "$alertVerdicts: [AlertVerdict!], $from: Time, $to: Time, $originType: AlertOriginType, "
    "$limit: Int, $offset: Int) { "
    " getAlerts(alertNames: $alertNames, alertIds: $alertIds, alertSeverities: $alertSeverities, "
    "statuses: $statuses, detectionIds: $detectionIds, dataSourceNames: $dataSourceNames, "
    "alertVerdicts: $alertVerdicts, from: $from, to: $to, originType: $originType, "
    "limit: $limit, offset: $offset) { "
    "  alerts { id detectionId name severity status "
    "   assignee { userId displayName email } "
    "   dataSources createdAt "
    "   mitre { mitreTactics mitreTechniques } "
    "   relatedIncidents { incidentId name } "
    "   detectionSource detectionDescription detectionQuery eventCount isTestMode verdict verdictReasoning dedupCount } "
    "  total limit offset "
    "  error { code message } } }"
)

GET_INCIDENTS_QUERY = (
    "query GetIncidents($incidentNames: [String!], $incidentIds: [ID!], $severities: [IncidentSeverity!], "
    "$statuses: [IncidentStatusPublic!], $verdicts: [IncidentVerdictPublic!], "
    "$from: Time, $to: Time, $limit: Int, $offset: Int) { "
    " getIncidents(incidentNames: $incidentNames, incidentIds: $incidentIds, severities: $severities, "
    "statuses: $statuses, verdicts: $verdicts, from: $from, to: $to, "
    "limit: $limit, offset: $offset) { "
    "  incidents { id name createdBy createdAt lastUpdated severity status dataSources verdict verdictReasoning "
    "   assignee { userId displayName email } "
    "   comments { text addedBy addedAt } "
    "   incidentSummary incidentFindings assets observables alertsCount "
    "   alerts { alertId name createdAt } link } "
    "  total limit offset "
    "  error { code message } } }"
)

GET_INCIDENT_DETAILS_QUERY = (
    "query getIncidentsDetails($id: UUID!) { "
    " incident(id: $id) { "
    "  ...IncidentDetailFields "
    "  timelineEvents { ...IncidentTimelineEventFields } "
    " } "
    "} "
    "fragment UserIdentityFields on User { id email name } "
    "fragment DataSourceListFields on DataSource { id vendor displayName } "
    "fragment IncidentBaseFields on Incident { "
    " id incidentId name description status createdAt "
    " createdBy { ...UserIdentityFields } lastUpdate firstSeen "
    " assignees { ...UserIdentityFields } severity alertCount alertIds "
    " dataSources { ...DataSourceListFields } state verdict "
    "} "
    "fragment FeedbackFields on Feedback { id liked comment } "
    "fragment EntityFields on Entity { id type category value reputationData } "
    "fragment RecommendedActionSummaryFields on RecommendedAction { "
    " id actionName actionDescription actionPriority "
    "} "
    "fragment RecommendedActionFields on RecommendedAction { "
    " ...RecommendedActionSummaryFields feedback { ...FeedbackFields } "
    "} "
    "fragment IncidentDetailFields on Incident { "
    " ...IncidentBaseFields userVerdict keyFindings verdictReasoning "
    " investigationNotebookID userNotebookIDs "
    " keyFindingsFeedback { ...FeedbackFields } entities { ...EntityFields } "
    " recommendedActions { ...RecommendedActionFields } connectorTypes "
    "} "
    "fragment IncidentTimelineEventFields on IncidentTimelineEvent { "
    " id timestamp summary entities { ...EntityFields } dataSourceIds "
    " dataSources { ...DataSourceListFields } "
    " alert { id displayName severity } "
    "}"
)

UPDATE_ALERTS_MUTATION = (
    "mutation UpdateAlerts($input: UpdateAlertsInput!) { "
    " updateAlerts(input: $input) { "
    "  alerts { id status severity verdict verdictReasoning "
    "   assignee { userId displayName email } } "
    "  error { code message } } }"
)

UPDATE_INCIDENTS_MUTATION = (
    "mutation UpdateIncidents($input: UpdateIncidentsInput!) { "
    " updateIncidents(input: $input) { "
    "  incidents { incidentId status verdict verdictReasoning updatedAt "
    "   assignee { userId displayName email } } "
    "  errors { code message } } }"
)

SET_DETECTIONS_STATE_MUTATION = (
    "mutation SetDetectionsState($input: SetDetectionsStateInput!) { " " setDetectionsState(input: $input) { " "  ids } }"
)

VALID_DETECTION_STATES = frozenset({"ENABLED", "DISABLED", "TEST_MODE"})
VALID_DETECTION_SEVERITIES = frozenset({"LOW", "MEDIUM", "HIGH", "CRITICAL"})

UPDATE_DETECTIONS_MUTATION = (
    "mutation UpdateDetections($input: UpdateDetectionsInput!) { "
    " updateDetections(input: $input) { "
    "  results { "
    "   name status "
    "   errors { code message field } "
    "   detection { id name severity status } "
    "  } "
    "  summary { requested valid invalid committed } "
    " } }"
)

MIRROR_ENTITY_SUFFIX_ALERT = "alert"
MIRROR_ENTITY_SUFFIX_INCIDENT = "incident"
VEGA_ALERT_STATUS_FIELD = "vegastatus"
VEGA_INCIDENT_STATUS_FIELD = "vegaincidentstatus"
MAX_MIRRORING_LIMIT = 5000
MIRRORED_FROM_VEGA = "[Mirrored From Vega]"
MIRRORED_FROM_XSOAR = "[Mirrored From XSOAR]"
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
DEFAULT_COMMENT_TAG = "comment"
DEFAULT_AUTO_CLOSURE = True
ALERT_MIRROR_FINGERPRINTS_KEY = "vega_alert_mirror_fingerprints"
INCIDENT_MIRROR_LAST_UPDATED_KEY = "vega_incident_mirror_last_updated"

XSOAR_SEVERITY_TO_VEGA: dict[int, str] = {
    IncidentSeverity.UNKNOWN: "LOW",
    IncidentSeverity.LOW: "LOW",
    IncidentSeverity.MEDIUM: "MEDIUM",
    IncidentSeverity.HIGH: "HIGH",
    IncidentSeverity.CRITICAL: "CRITICAL",
}

GET_ALERTS_EVENTS_QUERY = (
    "query GetAlertsEvents($alertId: ID!, $limit: Int, $offset: Int) { "
    " getAlertsEvents(alertId: $alertId, limit: $limit, offset: $offset) { "
    "  total limit offset results "
    "  error { code message } } }"
)

RATE_LIMIT_MAX_RETRIES = 10
RATE_LIMIT_INITIAL_WAIT_SECONDS = 2
RATE_LIMIT_WAIT_INCREMENT_SECONDS = 2
ALERT_MIRROR_IDS_BATCH_SIZE = 1000
INCIDENT_MIRROR_IDS_BATCH_SIZE = 1000
MIRROR_LAST_UPDATE_FALLBACK_MINUTES = 2
DEFAULT_ALERT_EVENTS_PAGE_SIZE = 200
ALERT_EVENT_JSON_MERGE_KEYS = frozenset({"fields"})
ALERT_EVENT_JSON_TRUNCATE_KEYS = frozenset({"raw", "_raw"})
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
GET_ALERTS_FETCH_LIMIT = None  # Set to None for production (unlimited alert fetch)

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


def _parse_backfill_days(backfill_days: str | int | float | None) -> int | None:
    """Parse a backfill day count from integration params."""
    if backfill_days is None or str(backfill_days).strip() == "":
        return None
    try:
        return int(float(str(backfill_days).strip()))
    except (TypeError, ValueError):
        return None


def _normalize_to_midnight_utc(value: datetime) -> datetime:
    """Return the same calendar date at 00:00:00 UTC."""
    return value.replace(hour=0, minute=0, second=0, microsecond=0)


def parse_backfill_days(
    backfill_days: str | int | None,
    legacy_first_fetch: str | None = None,
) -> str:
    """Convert a backfill day count to an ISO 8601 UTC timestamp for the first fetch.

    Args:
        backfill_days: Days before today (0 = start of today UTC, max 365).
        legacy_first_fetch: Deprecated relative time string from older instances (e.g. "30 days").

    Returns:
        An ISO 8601 UTC timestamp string, e.g. "2026-01-01T00:00:00Z".
    """
    days = _parse_backfill_days(backfill_days)

    if days is None and legacy_first_fetch:
        parsed = arg_to_datetime(legacy_first_fetch, is_utc=True)
        if parsed:
            start = _normalize_to_midnight_utc(parsed)  # type: ignore[arg-type]
            return start.strftime("%Y-%m-%dT%H:%M:%SZ")

    if days is None:
        days = DEFAULT_BACKFILL_DAYS

    days = max(BACKFILL_DAYS_MIN, min(BACKFILL_DAYS_MAX, days))
    today_start = _normalize_to_midnight_utc(datetime.now(UTC))
    start = today_start - timedelta(days=days)
    return start.strftime("%Y-%m-%dT%H:%M:%SZ")


def validate_backfill_days(backfill_days: str | int | None) -> None:
    """Validate that backfill_days is an integer between 0 and 365 inclusive.

    Args:
        backfill_days: Days before today (0 = start of today UTC, max 365).

    Raises:
        ValueError: If the value is not an integer or is outside the allowed range.
    """
    if backfill_days is None or str(backfill_days).strip() == "":
        return

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


def _http_status_code(exc: Exception) -> int | None:
    """Return the HTTP status code from a DemistoException, if present."""
    if isinstance(exc, DemistoException) and exc.res is not None:
        return exc.res.status_code
    return None


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


def _chunked(items: list[str], size: int) -> list[list[str]]:
    """Split a list into fixed-size chunks."""
    return [items[index : index + size] for index in range(0, len(items), size)]


def _is_connection_or_url_error(exc: Exception) -> bool:
    """Return True when the failure is likely caused by an invalid or unreachable Base URL."""
    message = str(exc).lower()
    if any(marker in message for marker in _CONNECTION_ERROR_MARKERS):
        return True
    status_code = _http_status_code(exc)
    return status_code in _URL_UNREACHABLE_STATUS_CODES if status_code is not None else False


def _test_connection_login_error_message(exc: Exception) -> str:
    """Map login_machine failures to a user-facing test-connection message."""
    if _is_connection_or_url_error(exc):
        if _http_status_code(exc) == 404:
            return TEST_CONNECTION_BASE_URL_ERROR
        return TEST_CONNECTION_URL_ERROR
    status_code = _http_status_code(exc)
    if status_code in _AUTH_FAILURE_STATUS_CODES:
        return TEST_CONNECTION_ACCESS_KEY_ERROR
    return TEST_CONNECTION_ACCESS_KEY_ERROR


def _test_connection_query_error_message(exc: Exception) -> str:
    """Map getAccessKey query failures to a user-facing test-connection message."""
    if _is_connection_or_url_error(exc):
        if _http_status_code(exc) == 404:
            return TEST_CONNECTION_BASE_URL_ERROR
        return TEST_CONNECTION_URL_ERROR
    status_code = _http_status_code(exc)
    if status_code in _AUTH_FAILURE_STATUS_CODES:
        return TEST_CONNECTION_ACCESS_KEY_ID_ERROR
    return TEST_CONNECTION_ACCESS_KEY_ID_ERROR


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
        self.access_key = access_key
        self.access_key_id = access_key_id
        self._session_jwt: str | None = None
        self._rate_limit_wait_seconds = RATE_LIMIT_INITIAL_WAIT_SECONDS

    def _reset_rate_limit_wait(self) -> None:
        """Reset the rate-limit backoff interval after a successful API call."""
        self._rate_limit_wait_seconds = RATE_LIMIT_INITIAL_WAIT_SECONDS

    def _sleep_before_rate_limit_retry(self, context: str, attempt: int) -> None:
        """Sleep using incremental backoff (2s, 4s, 6s, ...) before retrying a rate-limited request."""
        demisto.debug(
            f"Vega API rate limited ({context}). Waiting {self._rate_limit_wait_seconds}s before retry "
            f"{attempt + 1}/{RATE_LIMIT_MAX_RETRIES}."
        )
        time.sleep(self._rate_limit_wait_seconds)  # pylint: disable=E9003
        self._rate_limit_wait_seconds += RATE_LIMIT_WAIT_INCREMENT_SECONDS

    def _http_request(self, *args, **kwargs):  # type: ignore[no-untyped-def]
        """Execute an HTTP request with Vega rate-limit retry handling for HTTP 429 responses."""
        reset_backoff_on_success = kwargs.pop("reset_backoff_on_success", True)
        last_exc: Exception | None = None

        for attempt in range(RATE_LIMIT_MAX_RETRIES):
            try:
                response = super()._http_request(*args, **kwargs)
                if reset_backoff_on_success:
                    self._reset_rate_limit_wait()
                return response
            except Exception as exc:
                if _http_status_code(exc) != 429:
                    raise
                last_exc = exc
                if attempt < RATE_LIMIT_MAX_RETRIES - 1:
                    self._sleep_before_rate_limit_retry("HTTP 429", attempt)

        if last_exc is not None:
            raise last_exc
        raise DemistoException("Vega API rate limit exceeded after maximum retries.")

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
        """Execute a GraphQL query against the Vega API.

        Args:
            query: The GraphQL query string.
            variables: Optional variables for the query.

        Returns:
            The full JSON response from the API.
        """
        last_rate_limit_errors: list[Any] | None = None

        for attempt in range(RATE_LIMIT_MAX_RETRIES):
            session_jwt = self._authenticate()
            json_data: dict[str, Any] = {"query": query}
            if variables:
                json_data["variables"] = variables

            response: dict = self._http_request(
                method="POST",
                url_suffix="query",
                headers=self._auth_headers(session_jwt),
                json_data=json_data,
                resp_type="json",
                ok_codes=(200,),
                reset_backoff_on_success=False,
            )

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

    def test_connection(self, backfill_days: str | int | None = None) -> dict:
        validate_backfill_days(backfill_days)

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
            raise ValueError(_test_connection_login_error_message(exc)) from exc

        session_jwt: str = login_res.get("session_jwt", "") if login_res else ""
        if not session_jwt:
            raise ValueError("Authentication failed: no session token received. " "Please verify the Access Key and Base URL.")

        query_data: dict = {
            "query": (
                "query GetAccessKey($id: String!) {  getAccessKey(id: $id) {    id    name    description    "
                "status    createdBy    createdAt    expireTime    roles    bindings {      role      "
                "scopeId      scopeName    }    secretValue  }}"
            ),
            "variables": {"id": self.access_key_id},
        }

        try:
            query_res = self._http_request(
                method="POST",
                url_suffix="query",
                headers=self._auth_headers(session_jwt),
                json_data=query_data,
                resp_type="json",
                ok_codes=(200,),
            )
        except Exception as exc:
            raise ValueError(_test_connection_query_error_message(exc)) from exc

        errors = query_res.get("errors")
        data = query_res.get("data") or {}
        get_access_key = data.get("getAccessKey")

        if errors or get_access_key is None:
            raise ValueError(TEST_CONNECTION_ACCESS_KEY_ID_ERROR)

        roles = get_access_key.get("roles") or []

        if not any(re.search(r"(?i)editor|admin", role) for role in roles):
            raise ValueError("You do not have required access to fetch incidents.")

        return query_res

    def get_alerts(
        self,
        severities: list[str] | None = None,
        statuses: list[str] | None = None,
        verdicts: list[str] | None = None,
        from_time: str | None = None,
        alert_ids: list[str] | None = None,
        limit: int | None = None,
        offset: int = 0,
    ) -> dict:
        """Fetch alerts from the Vega API.

        Args:
            severities: Filter by alert severities.
            statuses: Filter by alert statuses.
            verdicts: Filter by alert verdicts.
            from_time: Fetch alerts created after this time (ISO 8601).
            limit: Optional maximum number of alerts per request. When omitted, the API default is used.
            offset: Offset for pagination.

        Returns:
            The getAlerts response data.
        """
        variables: dict[str, Any] = {"offset": offset}
        if limit is not None:
            variables["limit"] = limit
        if severities:
            variables["alertSeverities"] = severities
        if statuses:
            variables["statuses"] = statuses
        if verdicts:
            variables["alertVerdicts"] = verdicts
        if from_time:
            variables["from"] = from_time
        if alert_ids:
            variables["alertIds"] = alert_ids

        response = self._graphql_request(GET_ALERTS_QUERY, variables)
        data = response.get("data", {})
        return data.get("getAlerts", {})

    def get_alert_by_id(self, alert_id: str) -> dict:
        """Fetch a single Vega alert by ID."""
        response = self.get_alerts(alert_ids=[alert_id], limit=1)
        alerts = response.get("alerts") or []
        return alerts[0] if alerts else {}

    def get_incidents(
        self,
        severities: list[str] | None = None,
        statuses: list[str] | None = None,
        verdicts: list[str] | None = None,
        from_time: str | None = None,
        incident_ids: list[str] | None = None,
        limit: int | None = None,
        offset: int = 0,
    ) -> dict:
        """Fetch incidents from the Vega API.

        Args:
            severities: Filter by incident severities.
            statuses: Filter by incident statuses.
            verdicts: Filter by incident verdicts.
            from_time: Fetch incidents created after this time (ISO 8601).
            limit: Optional maximum number of incidents per request. When omitted, the API default is used.
            offset: Offset for pagination.

        Returns:
            The getIncidents response data.
        """
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
        if incident_ids:
            variables["incidentIds"] = incident_ids

        response = self._graphql_request(GET_INCIDENTS_QUERY, variables)
        data = response.get("data", {})
        return data.get("getIncidents", {})

    def get_incident_by_id(self, incident_id: str) -> dict:
        """Fetch a single Vega incident by ID."""
        response = self.get_incidents(incident_ids=[incident_id], limit=1)
        incidents = response.get("incidents") or []
        return incidents[0] if incidents else {}

    def update_alerts(self, update_input: dict[str, Any]) -> dict:
        """Update one or more Vega alerts."""
        response = self._graphql_request(UPDATE_ALERTS_MUTATION, {"input": update_input})
        data = response.get("data", {})
        result = data.get("updateAlerts", {})
        api_error = result.get("error")
        if isinstance(api_error, dict) and api_error.get("message"):
            raise DemistoException(f"Vega API error updating alerts: {api_error.get('message')}")
        return result

    def update_incidents(self, update_input: dict[str, Any]) -> dict:
        """Update one or more Vega incidents."""
        response = self._graphql_request(UPDATE_INCIDENTS_MUTATION, {"input": update_input})
        data = response.get("data", {})
        result = data.get("updateIncidents", {})
        errors = result.get("errors") or []
        if errors:
            messages = [err.get("message", "") for err in errors if isinstance(err, dict)]
            raise DemistoException(f"Vega API error updating incidents: {', '.join(filter(None, messages))}")
        return result

    def get_incident_details(self, incident_id: str) -> dict:
        """Fetch full incident details including timeline events.

        Args:
            incident_id: Vega incident UUID.

        Returns:
            The incident object from the GraphQL response, or an empty dict if not found.
        """
        response = self._graphql_request(GET_INCIDENT_DETAILS_QUERY, {"id": incident_id})
        data = response.get("data", {})
        incident = data.get("incident")
        return incident if isinstance(incident, dict) else {}

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
        data = response.get("data", {})
        return data.get("getAlertsEvents", {})

    def set_detections_state(self, detection_ids: list[str], state: str) -> dict:
        """Set the state for one or more Vega detections."""
        response = self._graphql_request(
            SET_DETECTIONS_STATE_MUTATION,
            {"input": {"ids": detection_ids, "state": state}},
        )
        data = response.get("data", {})
        result = data.get("setDetectionsState", {})
        return result if isinstance(result, dict) else {}

    def update_detections(self, detections: list[dict[str, Any]]) -> dict:
        """Update one or more Vega detections."""
        response = self._graphql_request(
            UPDATE_DETECTIONS_MUTATION,
            {"input": {"detections": detections}},
        )
        data = response.get("data", {})
        result = data.get("updateDetections", {})
        return result if isinstance(result, dict) else {}


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


def _vega_status_field_name(entity_type_suffix: str) -> str:
    """Return the XSOAR custom field name used for Vega status on the given entity type."""
    if entity_type_suffix == MIRROR_ENTITY_SUFFIX_INCIDENT:
        return VEGA_INCIDENT_STATUS_FIELD
    return VEGA_ALERT_STATUS_FIELD


def _get_status_from_fields(
    custom_fields: dict[str, Any],
    delta: dict[str, Any],
    entity_type_suffix: str,
) -> Any:
    """Read Vega status from custom fields or delta, with legacy fallback for incidents."""
    field_name = _vega_status_field_name(entity_type_suffix)
    status = custom_fields.get(field_name) or delta.get(field_name)
    if not status and entity_type_suffix == MIRROR_ENTITY_SUFFIX_INCIDENT:
        status = custom_fields.get(VEGA_ALERT_STATUS_FIELD) or delta.get(VEGA_ALERT_STATUS_FIELD)
    return status


def _collect_incident_custom_fields(incident: dict[str, Any]) -> dict[str, Any]:
    """Merge incident CustomFields with flattened custom-field keys."""
    custom_fields: dict[str, Any] = dict(incident.get("CustomFields") or incident.get("customFields") or {})
    for field_name in (
        "vegaalertid",
        "vegaincidentid",
        "dbotmirrorid",
        "vegaalerteventsloadedfor",
        "vegaalertevents",
        "vegaalerteventsoffset",
        "vegaalerteventstotal",
        VEGA_ALERT_STATUS_FIELD,
        VEGA_INCIDENT_STATUS_FIELD,
        "vegaverdict",
        "vegaverdictreasoning",
    ):
        if field_name not in custom_fields and incident.get(field_name) is not None:
            custom_fields[field_name] = incident.get(field_name)
    return custom_fields


def load_current_incident() -> dict[str, Any]:
    """Load the current investigation incident from the integration runtime context."""
    incident = demisto.incident() or {}
    if not incident.get("id"):
        try:
            incidents = demisto.incidents()
            if incidents:
                incident = incidents[0] or {}
        except Exception as exc:
            demisto.debug(f"Vega: demisto.incidents() failed: {exc}")
    return incident


def resolve_alert_id_from_incident(args: dict[str, Any], incident: dict[str, Any]) -> str | None:
    """Resolve Vega alert ID from command args or the current Vega Alert incident."""
    alert_id = args.get("alert_id")
    if alert_id is not None and str(alert_id).strip():
        return str(alert_id).strip()

    custom_fields = _collect_incident_custom_fields(incident)

    vega_alert_id = custom_fields.get("vegaalertid")
    if vega_alert_id is not None and str(vega_alert_id).strip():
        return str(vega_alert_id).strip()

    loaded_for = custom_fields.get("vegaalerteventsloadedfor")
    if loaded_for is not None and str(loaded_for).strip():
        return str(loaded_for).strip()

    mirror_id = custom_fields.get("dbotmirrorid") or custom_fields.get("dbotMirrorId")
    if mirror_id is not None and str(mirror_id).strip():
        try:
            entity_id, entity_type = parse_mirror_id(str(mirror_id).strip())
            if entity_type == MIRROR_ENTITY_SUFFIX_ALERT:
                return entity_id
        except ValueError:
            pass

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
    if offset >= total and total > 0:
        offset = max(0, total - page_limit)
        offset = (offset // page_limit) * page_limit
    page_events = all_events[offset : offset + page_limit]
    events_markdown = _format_alert_events_markdown(page_events, total, offset=offset, page_size=page_limit)

    persisted_fields = build_alert_events_custom_fields(alert_id, events_markdown, total, offset)
    return _alert_events_command_results(
        events_markdown,
        {
            "AlertId": alert_id,
            "Total": total,
            "Offset": offset,
            "Limit": page_limit,
            "Count": len(page_events),
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


def _normalize_detection_severity(severity: Any) -> str:
    """Normalize a detection severity value to the GraphQL API enum format."""
    return str(severity or "").strip().upper()


def _normalize_detection_status(status: Any) -> str:
    """Normalize a detection status value to the GraphQL API enum format."""
    return str(status or "").strip().upper()


def _build_detection_update_payload(
    detection_id: str,
    severity: str | None = None,
    status: str | None = None,
) -> dict[str, Any]:
    """Build a single detection update payload for updateDetections."""
    payload: dict[str, Any] = {"detectionId": detection_id}
    if severity is not None:
        payload["severity"] = severity
    if status is not None:
        payload["status"] = status
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
        "ValidationStatus": result_item.get("status"),
    }


def update_detections_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Update severity and/or status for one or more Vega detections."""
    detection_ids = [item.strip() for item in argToList(args.get("detection_id")) if str(item).strip()]
    if not detection_ids:
        raise DemistoException(
            "detection_id is required and must contain at least one detection ID. "
            "Example: !vega-update-detections detection_id=det-1 severity=HIGH status=VISIBLE"
        )

    severity_arg = args.get("severity")
    status_arg = args.get("status")
    severity = _normalize_detection_severity(severity_arg) if severity_arg not in (None, "") else None
    status = _normalize_detection_status(status_arg) if status_arg not in (None, "") else None

    if severity is None and status is None:
        raise DemistoException("At least one of severity or status must be provided.")

    if severity is not None and severity not in VALID_DETECTION_SEVERITIES:
        raise DemistoException(f"severity must be one of: {', '.join(sorted(VALID_DETECTION_SEVERITIES))}")

    detections = [_build_detection_update_payload(detection_id, severity, status) for detection_id in detection_ids]
    result = client.update_detections(detections)
    _raise_update_detections_errors(result)

    outputs = [_format_update_detection_output(item) for item in result.get("results") or [] if isinstance(item, dict)]
    summary = result.get("summary") if isinstance(result.get("summary"), dict) else {}
    readable = tableToMarkdown(
        "Updated Vega Detections",
        outputs,
        headers=["ID", "Name", "Severity", "Status", "ValidationStatus"],
        removeNull=True,
    )
    if summary:
        readable += "\n\n" + tableToMarkdown(
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

    return CommandResults(
        readable_output=readable,
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


MITRE_TACTIC_KEYS = ("mitreTactics", "mitre_tactics", "tactics")
MITRE_TECHNIQUE_KEYS = ("mitreTechniques", "mitre_techniques", "techniques")


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
        demisto.debug("Vega alert has no MITRE data to format.")
        return

    mitre_attack = _format_mitre_attack(mitre_payload)
    if mitre_attack:
        raw["vegaMitreAttack"] = mitre_attack
    else:
        demisto.debug(f"Vega MITRE payload could not be formatted: {mitre_payload!r}")


def _build_vega_alert_custom_fields(raw: dict) -> dict[str, str]:
    """Build CustomFields for Vega alerts (set directly on ingest, not via mapper)."""
    custom_fields: dict[str, str] = {}
    alert_id = raw.get("id")
    if alert_id is not None and str(alert_id).strip():
        custom_fields["vegaalertid"] = str(alert_id).strip()
    mitre_attack = raw.get("vegaMitreAttack")
    if mitre_attack:
        custom_fields["vegamitreattack"] = str(mitre_attack)
    created_at = raw.get("createdAt")
    if created_at:
        custom_fields["vegacreatedat"] = str(created_at)
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


def _timeline_footer_html(event: dict) -> str:
    """Build footer badges (data sources, severity, entities) for a timeline event."""
    parts: list[str] = []

    data_sources = event.get("dataSources")
    if isinstance(data_sources, list):
        for source in data_sources:
            if not isinstance(source, dict):
                continue
            label = _timeline_data_source_label(source)
            if label:
                parts.append(f"<span style='{_TIMELINE_PILL_STYLE}'>{_escape_html(label)}</span>")

    alert = event.get("alert")
    if isinstance(alert, dict) and alert.get("displayName"):
        severity_label = _timeline_alert_severity_label(alert.get("severity"))
        parts.append(f"<span style='{_TIMELINE_PILL_STYLE}'>Severity: {_escape_html(severity_label)}</span>")

    entities = event.get("entities")
    if isinstance(entities, list):
        for entity in entities:
            if not isinstance(entity, dict):
                continue
            entity_type = str(entity.get("type", "")).strip()
            category = str(entity.get("category", "")).strip()
            value = str(entity.get("value", "")).strip()
            if not value:
                continue
            meta_parts = [part for part in (entity_type, category) if part]
            pill_text = value
            if meta_parts:
                pill_text = f"{pill_text} ({', '.join(meta_parts)})"
            parts.append(f"<span style='{_TIMELINE_PILL_STYLE}'>{_escape_html(pill_text)}</span>")

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
    if isinstance(alert_data, dict) and str(alert_data.get("displayName", "")).strip():
        alert_name = _escape_html(str(alert_data.get("displayName", "")).strip())
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
    created_at = raw.get("createdAt")
    if created_at:
        custom_fields["vegacreatedat"] = str(created_at)
    timeline_html = raw.get("vegaTimelineEvents")
    if timeline_html:
        custom_fields["vegatimelineevents"] = str(timeline_html)
    findings_html = raw.get("vegaIncidentFindings")
    if findings_html:
        custom_fields["vegaincidentfindings"] = str(findings_html)
    return custom_fields


def _finding_text(finding: Any) -> str:
    """Normalize a single finding entry to display text."""
    if isinstance(finding, dict):
        return json.dumps(finding)
    return str(finding).strip()


def _normalize_findings_list(findings: Any) -> list[str]:
    """Extract non-empty finding strings from API data."""
    if findings is None or not isinstance(findings, list):
        return []
    texts: list[str] = []
    for finding in findings:
        text = _finding_text(finding)
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

    if raw.get("verdict") is not None:
        raw["verdict"] = _normalize_vega_verdict_for_display(raw.get("verdict"))

    if entity_type == "Vega Alert":
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
    _apply_vega_mitre_attack_format(raw)


def get_mirroring() -> dict[str, Any]:
    """Return mirroring metadata applied to fetched Vega entities."""
    params = demisto.params()
    autoclosure = argToBoolean(params.get("autoclosure", DEFAULT_AUTO_CLOSURE))
    mirror_direction = "Both" if autoclosure else "In"
    comment_tag = str(params.get("comment_tag", DEFAULT_COMMENT_TAG)).strip() or DEFAULT_COMMENT_TAG
    return {
        "mirror_direction": mirror_direction,
        "mirror_instance": demisto.integrationInstance(),
        "mirror_tags": comment_tag,
    }


def build_mirror_id(entity_id: str, entity_type: str) -> str:
    """Build a stable Vega mirror ID for XSOAR mirroring."""
    return f"{entity_id}-{entity_type}"


def parse_mirror_id(mirror_id: str) -> tuple[str, str]:
    """Parse a Vega mirror ID into entity ID and entity type suffix."""
    incident_suffix = f"-{MIRROR_ENTITY_SUFFIX_INCIDENT}"
    alert_suffix = f"-{MIRROR_ENTITY_SUFFIX_ALERT}"
    if mirror_id.endswith(incident_suffix):
        return mirror_id[: -len(incident_suffix)], MIRROR_ENTITY_SUFFIX_INCIDENT
    if mirror_id.endswith(alert_suffix):
        return mirror_id[: -len(alert_suffix)], MIRROR_ENTITY_SUFFIX_ALERT
    raise ValueError(f"Invalid Vega mirror ID: {mirror_id}")


def _apply_mirroring_to_raw(raw: dict, entity_type_suffix: str) -> None:
    """Attach mirroring metadata to raw entity JSON before XSOAR ingestion."""
    entity_id = _normalize_entity_id(raw)
    if not entity_id:
        return
    raw.update(get_mirroring())
    raw["mirror_id"] = build_mirror_id(entity_id, entity_type_suffix)


def _resolve_mirror_last_update_dt(args: dict[str, Any]) -> datetime:
    """Parse the mirroring cursor timestamp, falling back to a recent window when missing."""
    last_update_raw = args.get("lastUpdate") or args.get("last_update")
    if last_update_raw:
        try:
            parsed_dt = arg_to_datetime(arg=last_update_raw, arg_name="lastUpdate", required=False)
            if parsed_dt is not None:
                return parsed_dt  # type: ignore[return-value]
        except Exception as exc:
            demisto.debug(f"Vega mirroring failed to parse lastUpdate={last_update_raw}: {exc}")

    fallback_dt = datetime.now(UTC) - timedelta(minutes=MIRROR_LAST_UPDATE_FALLBACK_MINUTES)
    demisto.debug(f"Vega mirroring using fallback lastUpdate={fallback_dt.isoformat()}")
    return fallback_dt


def _entity_updated_since(entity: dict, since_dt: datetime) -> bool:
    """Return True when a Vega incident was updated after the given timestamp."""
    updated_raw = entity.get("lastUpdated") or entity.get("updatedAt") or entity.get("lastUpdate")
    updated_dt = arg_to_datetime(str(updated_raw), is_utc=True) if updated_raw else None
    if updated_dt is None:
        return False
    return updated_dt > since_dt  # type: ignore[operator]


def _normalize_mirror_timestamp(value: Any) -> str:
    """Normalize a Vega timestamp to a stable ISO 8601 UTC string for mirroring comparisons."""
    if not value:
        return ""
    parsed_dt = arg_to_datetime(str(value), is_utc=True)
    if parsed_dt is None:
        return str(value)
    return parsed_dt.strftime("%Y-%m-%dT%H:%M:%SZ")  # type: ignore[union-attr]


def _incident_mirror_last_updated(incident: dict) -> str:
    """Return the Vega incident last-updated timestamp used for mirroring."""
    updated_raw = incident.get("lastUpdated") or incident.get("updatedAt") or incident.get("lastUpdate")
    return _normalize_mirror_timestamp(updated_raw)


def _normalize_incident_verdict_value(verdict: Any) -> str:
    """Normalize a Vega incident verdict to a string for XSOAR mapping."""
    if isinstance(verdict, dict):
        return str(verdict.get("value") or verdict.get("verdict") or "")
    return str(verdict or "")


def _normalize_vega_verdict_for_display(verdict: Any) -> str:
    """Normalize a Vega verdict to a value accepted by the XSOAR single-select field."""
    normalized = _normalize_incident_verdict_value(verdict).strip().upper()
    return VERDICT_DISPLAY_TO_API.get(normalized, normalized)


def _incident_mirror_fingerprint(incident: dict) -> str:
    """Build a stable fingerprint for Vega incident fields that can change during mirroring."""
    payload = {
        "lastUpdated": _incident_mirror_last_updated(incident),
        "status": incident.get("status"),
        "severity": incident.get("severity"),
        "verdict": _normalize_vega_verdict_for_display(incident.get("verdict")),
        "verdictReasoning": incident.get("verdictReasoning"),
        "assigneeEmail": _alert_assignee_email(incident),
    }
    return json.dumps(payload, sort_keys=True)


def _legacy_incident_mirror_fingerprint(cached_value: Any) -> str:
    """Convert a legacy incident mirror cache entry to the current fingerprint format."""
    if isinstance(cached_value, dict):
        return json.dumps(
            {
                "lastUpdated": str(cached_value.get("lastUpdated") or ""),
                "status": cached_value.get("status"),
                "severity": cached_value.get("severity"),
                "verdict": cached_value.get("verdict"),
                "verdictReasoning": cached_value.get("verdictReasoning"),
                "assigneeEmail": cached_value.get("assigneeEmail"),
            },
            sort_keys=True,
        )
    return json.dumps(
        {
            "lastUpdated": _normalize_mirror_timestamp(cached_value),
            "status": None,
            "severity": None,
            "verdict": None,
            "verdictReasoning": None,
            "assigneeEmail": None,
        },
        sort_keys=True,
    )


def _load_incident_mirror_fingerprints() -> dict[str, str]:
    """Load cached Vega incident mirror fingerprints from integration context."""
    integration_context = demisto.getIntegrationContext() or {}
    fingerprints = integration_context.get(INCIDENT_MIRROR_LAST_UPDATED_KEY, {})
    if isinstance(fingerprints, str):
        try:
            fingerprints = json.loads(fingerprints)
        except json.JSONDecodeError:
            fingerprints = {}
    if not isinstance(fingerprints, dict):
        return {}

    normalized_fingerprints: dict[str, str] = {}
    for incident_id, cached_value in fingerprints.items():
        if isinstance(cached_value, str) and cached_value.startswith("{"):
            normalized_fingerprints[str(incident_id)] = cached_value
        else:
            normalized_fingerprints[str(incident_id)] = _legacy_incident_mirror_fingerprint(cached_value)
    return normalized_fingerprints


def _save_incident_mirror_fingerprints(fingerprints: dict[str, str]) -> None:
    """Persist Vega incident mirror fingerprints to integration context."""
    integration_context = demisto.getIntegrationContext() or {}
    integration_context[INCIDENT_MIRROR_LAST_UPDATED_KEY] = fingerprints
    demisto.setIntegrationContext(integration_context)


def _store_incident_mirror_fingerprint(incident: dict) -> None:
    """Cache the current Vega incident fingerprint for incoming mirroring."""
    incident_id = _normalize_entity_id(incident)
    if not incident_id:
        return
    fingerprints = _load_incident_mirror_fingerprints()
    fingerprints[incident_id] = _incident_mirror_fingerprint(incident)
    _save_incident_mirror_fingerprints(fingerprints)


def _incident_mirror_state_changed(incident: dict) -> bool:
    """Return True when a Vega incident's mirrored fields differ from the cached fingerprint."""
    incident_id = _normalize_entity_id(incident)
    if not incident_id:
        return False
    fingerprints = _load_incident_mirror_fingerprints()
    return fingerprints.get(incident_id) != _incident_mirror_fingerprint(incident)


def _incident_cached_status(incident_id: str) -> Any:
    """Return the cached Vega incident status from the mirror fingerprint, if available."""
    cached_fingerprint = _load_incident_mirror_fingerprints().get(incident_id)
    if not cached_fingerprint:
        return None
    try:
        cached_payload = json.loads(cached_fingerprint)
    except json.JSONDecodeError:
        return None
    return cached_payload.get("status")


def _incident_status_changed(incident: dict) -> bool:
    """Return True when a Vega incident status differs from the cached fingerprint."""
    incident_id = _normalize_entity_id(incident)
    if not incident_id:
        return False
    cached_status = _incident_cached_status(incident_id)
    if cached_status is None:
        return True
    return cached_status != incident.get("status")


def _append_changed_incident_mirror_ids(
    incidents: list[dict],
    fingerprints: dict[str, str],
    modified_ids: list[str],
) -> None:
    """Append mirror IDs for cached Vega incidents whose fingerprint differs from the API payload."""
    for incident in incidents:
        if len(modified_ids) >= MAX_MIRRORING_LIMIT:
            return
        entity_id = _normalize_entity_id(incident)
        if not entity_id or entity_id not in fingerprints:
            continue
        mirror_id = build_mirror_id(entity_id, MIRROR_ENTITY_SUFFIX_INCIDENT)
        if mirror_id in modified_ids:
            continue
        if fingerprints.get(entity_id) != _incident_mirror_fingerprint(incident):
            modified_ids.append(mirror_id)


def _collect_modified_incident_mirror_ids(
    client: Client,
    command_last_run_iso: str,
    incident_severities: list[str] | None,
    incident_statuses: list[str] | None,
    incident_verdicts: list[str] | None,
) -> list[str]:
    """Return mirror IDs for Vega incidents created or changed since the last mirroring run."""
    modified_ids: list[str] = []
    fingerprints = _load_incident_mirror_fingerprints()

    newly_created_incidents = _fetch_paginated_entities(
        client.get_incidents,
        entities_key="incidents",
        severities=incident_severities,
        statuses=incident_statuses,
        verdicts=incident_verdicts,
        from_time=command_last_run_iso,
    )
    for incident in newly_created_incidents:
        entity_id = _normalize_entity_id(incident)
        if entity_id:
            modified_ids.append(build_mirror_id(entity_id, MIRROR_ENTITY_SUFFIX_INCIDENT))

    tracked_incident_ids = list(fingerprints.keys())
    for incident_id_chunk in _chunked(tracked_incident_ids, INCIDENT_MIRROR_IDS_BATCH_SIZE):
        if len(modified_ids) >= MAX_MIRRORING_LIMIT:
            break
        chunk_response = client.get_incidents(incident_ids=incident_id_chunk, limit=len(incident_id_chunk))
        tracked_incidents = chunk_response.get("incidents") or []
        if len(tracked_incidents) < len(incident_id_chunk):
            demisto.debug(
                "Vega incident mirror poll requested "
                f"{len(incident_id_chunk)} cached incident IDs but received {len(tracked_incidents)} incidents."
            )
        _append_changed_incident_mirror_ids(tracked_incidents, fingerprints, modified_ids)
        del tracked_incidents
        del chunk_response

    return modified_ids


def _alert_assignee_email(alert: dict) -> str | None:
    """Extract the primary assignee email from a Vega alert."""
    assignee = alert.get("assignee")
    if isinstance(assignee, dict):
        email = assignee.get("email")
        return str(email) if email else None
    return None


def _alert_mirror_fingerprint(alert: dict) -> str:
    """Build a stable fingerprint for Vega alert fields that can change during mirroring."""
    payload = {
        "status": alert.get("status"),
        "severity": alert.get("severity"),
        "verdict": _normalize_vega_verdict_for_display(alert.get("verdict")),
        "verdictReasoning": alert.get("verdictReasoning"),
        "assigneeEmail": _alert_assignee_email(alert),
        "eventCount": alert.get("eventCount"),
        "dedupCount": alert.get("dedupCount"),
    }
    return json.dumps(payload, sort_keys=True)


def _load_alert_mirror_fingerprints() -> dict[str, str]:
    """Load cached Vega alert mirror fingerprints from integration context."""
    integration_context = demisto.getIntegrationContext() or {}
    fingerprints = integration_context.get(ALERT_MIRROR_FINGERPRINTS_KEY, {})
    if isinstance(fingerprints, str):
        try:
            fingerprints = json.loads(fingerprints)
        except json.JSONDecodeError:
            fingerprints = {}
    return fingerprints if isinstance(fingerprints, dict) else {}


def _save_alert_mirror_fingerprints(fingerprints: dict[str, str]) -> None:
    """Persist Vega alert mirror fingerprints to integration context."""
    integration_context = demisto.getIntegrationContext() or {}
    integration_context[ALERT_MIRROR_FINGERPRINTS_KEY] = fingerprints
    demisto.setIntegrationContext(integration_context)


def _store_alert_mirror_fingerprint(alert: dict) -> None:
    """Cache the current fingerprint for a Vega alert."""
    alert_id = _normalize_entity_id(alert)
    if not alert_id:
        return
    fingerprints = _load_alert_mirror_fingerprints()
    fingerprints[alert_id] = _alert_mirror_fingerprint(alert)
    _save_alert_mirror_fingerprints(fingerprints)


def _alert_mirror_state_changed(alert: dict) -> bool:
    """Return True when a Vega alert's mirrored fields differ from the cached fingerprint."""
    alert_id = _normalize_entity_id(alert)
    if not alert_id:
        return False
    fingerprints = _load_alert_mirror_fingerprints()
    return fingerprints.get(alert_id) != _alert_mirror_fingerprint(alert)


def _alert_status_changed(alert: dict) -> bool:
    """Return True when a Vega alert status differs from the cached fingerprint."""
    alert_id = _normalize_entity_id(alert)
    if not alert_id:
        return False
    fingerprints = _load_alert_mirror_fingerprints()
    cached_fingerprint = fingerprints.get(alert_id)
    if not cached_fingerprint:
        return True
    try:
        cached_payload = json.loads(cached_fingerprint)
    except json.JSONDecodeError:
        return True
    return cached_payload.get("status") != alert.get("status")


def _append_changed_alert_mirror_ids(
    alerts: list[dict],
    fingerprints: dict[str, str],
    modified_ids: list[str],
) -> None:
    """Append mirror IDs for cached Vega alerts whose fingerprint differs from the API payload."""
    for alert in alerts:
        if len(modified_ids) >= MAX_MIRRORING_LIMIT:
            return
        entity_id = _normalize_entity_id(alert)
        if not entity_id or entity_id not in fingerprints:
            continue
        mirror_id = build_mirror_id(entity_id, MIRROR_ENTITY_SUFFIX_ALERT)
        if mirror_id in modified_ids:
            continue
        if fingerprints.get(entity_id) != _alert_mirror_fingerprint(alert):
            modified_ids.append(mirror_id)


def _collect_modified_alert_mirror_ids(
    client: Client,
    command_last_run_iso: str,
    alert_severities: list[str] | None,
    alert_statuses: list[str] | None,
    alert_verdicts: list[str] | None,
) -> list[str]:
    """Return mirror IDs for Vega alerts created or changed since the last mirroring run.

    Vega alerts do not expose ``lastUpdated``, so newly created alerts are detected via
    ``createdAt`` and updates to existing alerts are detected via a cached field fingerprint.
    """
    modified_ids: list[str] = []
    fingerprints = _load_alert_mirror_fingerprints()

    newly_created_alerts = _fetch_paginated_entities(
        client.get_alerts,
        entities_key="alerts",
        severities=alert_severities,
        statuses=alert_statuses,
        verdicts=alert_verdicts,
        from_time=command_last_run_iso,
    )
    for alert in newly_created_alerts:
        entity_id = _normalize_entity_id(alert)
        if entity_id:
            modified_ids.append(build_mirror_id(entity_id, MIRROR_ENTITY_SUFFIX_ALERT))

    tracked_alert_ids = list(fingerprints.keys())
    for alert_id_chunk in _chunked(tracked_alert_ids, ALERT_MIRROR_IDS_BATCH_SIZE):
        if len(modified_ids) >= MAX_MIRRORING_LIMIT:
            break
        tracked_alerts_response = client.get_alerts(alert_ids=alert_id_chunk, limit=len(alert_id_chunk))
        tracked_alerts = tracked_alerts_response.get("alerts") or []
        if len(tracked_alerts) < len(alert_id_chunk):
            demisto.debug(
                "Vega alert mirror poll requested "
                f"{len(alert_id_chunk)} cached alert IDs but received {len(tracked_alerts)} alerts."
            )
        _append_changed_alert_mirror_ids(tracked_alerts, fingerprints, modified_ids)
        del tracked_alerts
        del tracked_alerts_response

    return modified_ids


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


def _prepare_incoming_mirrored_object(entity: dict, entity_type_suffix: str) -> dict:
    """Prepare a Vega entity payload for incoming mirroring field updates."""
    raw = dict(entity)
    raw["vegaEntityType"] = "Vega Alert" if entity_type_suffix == MIRROR_ENTITY_SUFFIX_ALERT else "Vega Incident"
    _format_raw_entity_for_xsoar(raw)
    severity_label = str(entity.get("severity", "")).upper()
    raw["severity"] = entity.get("severity")
    raw["xsoarSeverity"] = VEGA_SEVERITY_TO_XSOAR.get(severity_label, IncidentSeverity.UNKNOWN)
    return raw


def _incoming_comment_entries(
    comments: list[dict],
    command_last_run_dt: datetime,
) -> list[dict]:
    """Build war room entries for new Vega comments."""
    entries: list[dict] = []
    for comment in comments:
        if not isinstance(comment, dict):
            continue
        text = str(comment.get("text", "")).strip()
        if not text or MIRRORED_FROM_XSOAR in text:
            continue
        added_at_raw = comment.get("addedAt")
        added_at_dt = arg_to_datetime(str(added_at_raw), is_utc=True) if added_at_raw else None
        if added_at_dt is not None and added_at_dt <= command_last_run_dt:  # type: ignore[operator]
            continue
        added_by = comment.get("addedBy", "Unknown")
        entries.append(
            {
                "Type": EntryType.NOTE,
                "Contents": (
                    f"{MIRRORED_FROM_VEGA}\n" f"Added By: {added_by}\n" f"Added At: {added_at_raw} UTC\n" f"Comment: {text}"
                ),
                "ContentsFormat": EntryFormat.TEXT,
                "Note": True,
            }
        )
    return entries


def _incoming_status_entries(status: str, entity_type_suffix: str) -> list[dict]:
    """Build close or reopen entries based on the remote Vega status."""
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


def get_modified_remote_data_command(
    client: Client,
    args: dict[str, Any],
    params: dict[str, Any],
    alert_severities: list[str] | None,
    alert_statuses: list[str] | None,
    alert_verdicts: list[str] | None,
    incident_severities: list[str] | None,
    incident_statuses: list[str] | None,
    incident_verdicts: list[str] | None,
) -> GetModifiedRemoteDataResponse:
    """Return Vega alert/incident mirror IDs modified since the last mirroring run."""
    command_last_run_dt = _resolve_mirror_last_update_dt(args)
    command_last_run_iso = command_last_run_dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    demisto.debug(f"Vega get-modified-remote-data lastUpdate={command_last_run_iso}")

    vega_entities = argToList(params.get("vega_entities") or ["Alerts", "Incidents"])
    modified_ids: list[str] = []

    if "Incidents" in vega_entities:
        modified_ids.extend(
            _collect_modified_incident_mirror_ids(
                client,
                command_last_run_iso,
                incident_severities,
                incident_statuses,
                incident_verdicts,
            )
        )

    if "Alerts" in vega_entities:
        modified_ids.extend(
            _collect_modified_alert_mirror_ids(
                client,
                command_last_run_iso,
                alert_severities,
                alert_statuses,
                alert_verdicts,
            )
        )

    modified_ids = list(dict.fromkeys(modified_ids))[:MAX_MIRRORING_LIMIT]
    demisto.debug(f"Vega get-modified-remote-data returning {len(modified_ids)} IDs")
    return GetModifiedRemoteDataResponse(modified_incident_ids=modified_ids)


def get_remote_data_command(
    client: Client,
    args: dict[str, Any],
) -> GetRemoteDataResponse:
    """Fetch the latest Vega entity state and war room entries for incoming mirroring."""
    try:
        parsed_args = GetRemoteDataArgs(args)
        mirror_id = str(parsed_args.remote_incident_id).strip()
        entity_id, entity_type_suffix = parse_mirror_id(mirror_id)
        command_last_run_dt = _resolve_mirror_last_update_dt(args)
        demisto.debug(f"Vega get-remote-data for {mirror_id}")

        if entity_type_suffix == MIRROR_ENTITY_SUFFIX_INCIDENT:
            remote_entity = client.get_incident_by_id(entity_id)
        else:
            remote_entity = client.get_alert_by_id(entity_id)

        if not remote_entity:
            return GetRemoteDataResponse(
                {"incoming_mirror_error": f"Vega {entity_type_suffix} not found for mirror ID {mirror_id}."},
                [],
            )

        entries: list[dict] = []
        entity_changed = False
        status_changed = False

        if entity_type_suffix == MIRROR_ENTITY_SUFFIX_INCIDENT:
            entity_changed = _incident_mirror_state_changed(remote_entity)
            if not entity_changed:
                updated_raw = (
                    remote_entity.get("lastUpdated") or remote_entity.get("updatedAt") or remote_entity.get("lastUpdate")
                )
                updated_dt = arg_to_datetime(str(updated_raw), is_utc=True) if updated_raw else None
                entity_changed = updated_dt is not None and updated_dt > command_last_run_dt  # type: ignore[operator]
            status_changed = _incident_status_changed(remote_entity)
            comments = remote_entity.get("comments") or []
            if isinstance(comments, list):
                entries.extend(_incoming_comment_entries(comments, command_last_run_dt))  # type: ignore[arg-type]
        else:
            entity_changed = _alert_mirror_state_changed(remote_entity)
            status_changed = _alert_status_changed(remote_entity)

        if status_changed:
            status = str(remote_entity.get("status", ""))
            entries.extend(_incoming_status_entries(status, entity_type_suffix))

        mirrored_object = _prepare_incoming_mirrored_object(remote_entity, entity_type_suffix)
        _apply_mirroring_to_raw(mirrored_object, entity_type_suffix)

        has_field_updates = entity_changed or bool(entries)
        if not has_field_updates:
            demisto.debug(f"Vega get-remote-data found no incoming changes for {mirror_id}.")
            return GetRemoteDataResponse({}, entries)

        if entity_type_suffix == MIRROR_ENTITY_SUFFIX_INCIDENT:
            _store_incident_mirror_fingerprint(remote_entity)
        else:
            _store_alert_mirror_fingerprint(remote_entity)

        return GetRemoteDataResponse(mirrored_object, entries)
    except Exception as exc:
        mirror_id = str(args.get("id", "")).strip()
        demisto.debug(f"Vega get-remote-data failed for {mirror_id}: {exc}")
        return GetRemoteDataResponse({"incoming_mirror_error": str(exc)}, [])


def _entry_has_mirror_tag(entry: dict, mirror_tags: str) -> bool:
    """Return True when a war room entry should be mirrored to Vega."""
    if not mirror_tags:
        return False
    entry_tags = entry.get("tags") or []
    if isinstance(entry_tags, str):
        entry_tags = argToList(entry_tags)
    normalized_tags = {str(tag).strip().lower() for tag in entry_tags if str(tag).strip()}
    return mirror_tags.strip().lower() in normalized_tags


def _build_alert_update_input(entity_id: str, data: dict[str, Any], delta: dict[str, Any]) -> dict[str, Any]:
    """Build an UpdateAlertsInput payload from XSOAR incident changes."""
    custom_fields = data.get("CustomFields") or {}
    update_input: dict[str, Any] = {"alertIds": [entity_id]}

    status = _get_status_from_fields(custom_fields, delta, MIRROR_ENTITY_SUFFIX_ALERT)
    if status:
        update_input["status"] = _normalize_vega_status_for_api(str(status), MIRROR_ENTITY_SUFFIX_ALERT)

    verdict = custom_fields.get("vegaverdict") or delta.get("vegaverdict")
    if verdict:
        update_input["verdict"] = _normalize_vega_verdict_for_api(str(verdict))

    verdict_reasoning = custom_fields.get("vegaverdictreasoning") or delta.get("vegaverdictreasoning")
    if verdict_reasoning:
        update_input["verdictReasoning"] = str(verdict_reasoning)

    assignee_email = custom_fields.get("vegaassigneeemail") or delta.get("vegaassigneeemail")
    if assignee_email:
        update_input["assignee"] = str(assignee_email)

    return update_input


def _build_incident_update_input(
    entity_id: str,
    data: dict[str, Any],
    delta: dict[str, Any],
    comment: str | None = None,
) -> dict[str, Any]:
    """Build an UpdateIncidentsInput payload from XSOAR incident changes."""
    custom_fields = data.get("CustomFields") or {}
    update_input: dict[str, Any] = {"incidentIds": [entity_id]}

    status = _get_status_from_fields(custom_fields, delta, MIRROR_ENTITY_SUFFIX_INCIDENT)
    if status:
        update_input["status"] = _normalize_vega_status_for_api(str(status), MIRROR_ENTITY_SUFFIX_INCIDENT)

    verdict = custom_fields.get("vegaverdict") or delta.get("vegaverdict")
    verdict_reasoning = custom_fields.get("vegaverdictreasoning") or delta.get("vegaverdictreasoning")
    if verdict:
        update_input["verdict"] = {
            "value": _normalize_vega_verdict_for_api(str(verdict)),
            "reasoning": str(verdict_reasoning or ""),
        }

    assignee_email = custom_fields.get("vegaassigneeemail") or delta.get("vegaassigneeemail")
    if assignee_email:
        update_input["assigneeEmail"] = str(assignee_email)

    if comment:
        update_input["comment"] = comment

    return update_input


def _collect_alert_ids_from_args(args: dict[str, Any]) -> list[str]:
    """Collect unique Vega alert IDs from command arguments."""
    return list(dict.fromkeys(str(item).strip() for item in argToList(args.get("alert_id")) if str(item).strip()))


def _collect_incident_ids_from_args(args: dict[str, Any]) -> list[str]:
    """Collect unique Vega incident IDs from command arguments."""
    entity_ids: list[str] = []
    for key in ("incident_id", "incident_ids"):
        entity_ids.extend(str(item).strip() for item in argToList(args.get(key)) if str(item).strip())
    return list(dict.fromkeys(entity_ids))


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


def _build_direct_alert_update_payload(args: dict[str, Any]) -> dict[str, Any]:
    """Build an UpdateAlertsInput payload from explicit command arguments."""
    update_input: dict[str, Any] = {}
    status = args.get("status") or args.get("alert_status")
    if status is not None and str(status).strip():
        update_input["status"] = _validate_alert_status_value(str(status))
    verdict = args.get("verdict")
    if verdict is not None and str(verdict).strip():
        update_input["verdict"] = _validate_verdict_value(str(verdict))
    return update_input


def _build_direct_incident_update_payload(args: dict[str, Any]) -> dict[str, Any]:
    """Build an UpdateIncidentsInput payload from explicit command arguments."""
    update_input: dict[str, Any] = {}
    status = args.get("status") or args.get("incident_status")
    if status is not None and str(status).strip():
        update_input["status"] = _validate_incident_status_value(str(status))
    verdict = args.get("verdict")
    if verdict is not None and str(verdict).strip():
        update_input["verdict"] = {
            "value": _validate_verdict_value(str(verdict)),
            "reasoning": str(args.get("verdict_reasoning") or ""),
        }
    comment = args.get("comment")
    if comment is not None and str(comment).strip():
        update_input["comment"] = str(comment).strip()
    return update_input


def _format_push_alert_output(alert: dict[str, Any]) -> dict[str, str]:
    """Format a Vega alert update response for context output."""
    return {
        "id": str(alert.get("id") or ""),
        "status": _normalize_vega_status_for_display(str(alert.get("status") or ""), MIRROR_ENTITY_SUFFIX_ALERT),
        "verdict": _normalize_vega_verdict_for_display(alert.get("verdict")),
    }


def _format_push_incident_output(incident: dict[str, Any]) -> dict[str, str]:
    """Format a Vega incident update response for context output."""
    return {
        "id": str(incident.get("incidentId") or incident.get("id") or ""),
        "status": _normalize_vega_status_for_display(str(incident.get("status") or ""), MIRROR_ENTITY_SUFFIX_INCIDENT),
        "verdict": _normalize_vega_verdict_for_display(incident.get("verdict")),
    }


def _refresh_alert_mirror_fingerprints(client: Client, alert_ids: list[str], updated_alerts: list[dict]) -> None:
    """Refresh cached alert mirror fingerprints after a direct Vega update."""
    alerts_by_id = {str(alert.get("id")): alert for alert in updated_alerts if alert.get("id")}
    for alert_id in alert_ids:
        alert = alerts_by_id.get(alert_id) or client.get_alert_by_id(alert_id)
        if alert:
            _store_alert_mirror_fingerprint(alert)


def _refresh_incident_mirror_fingerprints(client: Client, incident_ids: list[str], updated_incidents: list[dict]) -> None:
    """Refresh cached incident mirror fingerprints after a direct Vega update."""
    incidents_by_id = {
        str(incident.get("incidentId") or incident.get("id")): incident
        for incident in updated_incidents
        if incident.get("incidentId") or incident.get("id")
    }
    for incident_id in incident_ids:
        incident = incidents_by_id.get(incident_id) or client.get_incident_by_id(incident_id)
        if incident:
            _store_incident_mirror_fingerprint(incident)


def resolve_incident_id_from_incident(args: dict[str, Any], incident: dict[str, Any]) -> str | None:
    """Resolve Vega incident ID from command args or the current Vega Incident investigation."""
    incident_ids = _collect_incident_ids_from_args(args)
    if incident_ids:
        return incident_ids[0]

    custom_fields = _collect_incident_custom_fields(incident)
    vega_incident_id = custom_fields.get("vegaincidentid")
    if vega_incident_id is not None and str(vega_incident_id).strip():
        return str(vega_incident_id).strip()

    mirror_id = custom_fields.get("dbotmirrorid") or custom_fields.get("dbotMirrorId")
    if mirror_id is not None and str(mirror_id).strip():
        try:
            entity_id, entity_type = parse_mirror_id(str(mirror_id).strip())
            if entity_type == MIRROR_ENTITY_SUFFIX_INCIDENT:
                return entity_id
        except ValueError:
            pass

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


def _matches_verdict_value(value: str) -> bool:
    """Return True when the value is a supported Vega verdict."""
    normalized = _normalize_vega_verdict_for_api(str(value or "").strip())
    return normalized in VALID_VERDICTS


def _matches_alert_status_value(value: str) -> bool:
    """Return True when the value is a supported Vega alert status."""
    try:
        _validate_alert_status_value(str(value or "").strip())
        return True
    except DemistoException:
        return False


def _matches_incident_status_value(value: str) -> bool:
    """Return True when the value is a supported Vega incident status."""
    try:
        _validate_incident_status_value(str(value or "").strip())
        return True
    except DemistoException:
        return False


def _resolve_field_change_update_args(args: dict[str, Any], entity_type_suffix: str) -> dict[str, str]:
    """Map a layout field-change ``new`` value to the status or verdict arg to update."""
    new_value = str(args.get("new") or "").strip()
    if not new_value:
        return {}

    if entity_type_suffix == MIRROR_ENTITY_SUFFIX_ALERT:
        if _matches_alert_status_value(new_value):
            return {"status": new_value}
        if _matches_verdict_value(new_value):
            return {"verdict": new_value}
        return {}

    if _matches_incident_status_value(new_value):
        return {"status": new_value}
    if _matches_verdict_value(new_value):
        return {"verdict": new_value}
    return {}


def _args_explicitly_set(args: dict[str, Any], *keys: str) -> bool:
    """Return True when at least one of the provided args was explicitly set."""
    for key in keys:
        value = args.get(key)
        if value is not None and str(value).strip() != "":
            return True
    return False


def _alert_update_fields_explicitly_set(args: dict[str, Any]) -> bool:
    """Return True when the caller provided alert status and/or verdict command arguments."""
    return _args_explicitly_set(args, "status", "alert_status", "verdict")


def _incident_update_fields_explicitly_set(args: dict[str, Any]) -> bool:
    """Return True when the caller provided incident status, verdict, and/or comment command arguments."""
    return _args_explicitly_set(args, "status", "incident_status", "verdict", "comment")


def _xsoar_incident_is_closed(incident: dict[str, Any]) -> bool:
    """Return True when the current XSOAR investigation is closed."""
    status = incident.get("status") or incident.get("Status")
    return status == IncidentStatus.DONE or (isinstance(status, str) and status.strip().lower() in {"closed", "done"})


def _resolve_alert_ids_for_update(args: dict[str, Any], incident: dict[str, Any]) -> list[str]:
    """Resolve Vega alert IDs from args or the current investigation."""
    alert_ids = _collect_alert_ids_from_args(args)
    if alert_ids:
        return alert_ids
    resolved_id = resolve_alert_id_from_incident(args, incident)
    return [resolved_id] if resolved_id else []


def _resolve_incident_ids_for_update(args: dict[str, Any], incident: dict[str, Any]) -> list[str]:
    """Resolve Vega incident IDs from args or the current investigation."""
    incident_ids = _collect_incident_ids_from_args(args)
    if incident_ids:
        return incident_ids
    resolved_id = resolve_incident_id_from_incident(args, incident)
    return [resolved_id] if resolved_id else []


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
        return effective_args

    if _args_explicitly_set(args, "status", "alert_status"):
        status = _resolve_alert_status_for_update(args, incident)
        if status is not None:
            effective_args["status"] = status
    if _args_explicitly_set(args, "verdict"):
        verdict = _resolve_verdict_for_update(args, incident)
        if verdict is not None:
            effective_args["verdict"] = verdict
    return effective_args


def _build_effective_incident_update_args(args: dict[str, Any], incident: dict[str, Any]) -> dict[str, Any]:
    """Build incident update args from explicit args, field changes, or current investigation fields."""
    if _is_field_change_trigger(args):
        return {**args, **_resolve_field_change_update_args(args, MIRROR_ENTITY_SUFFIX_INCIDENT)}

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
    return effective_args


def _should_sync_xsoar_alert(args: dict[str, Any], incident: dict[str, Any], alert_ids: list[str]) -> bool:
    """Return True when the open XSOAR investigation should be synced after an alert update."""
    if not incident.get("id"):
        return False
    if len(alert_ids) > 1 and _args_explicitly_set(args, "alert_id"):
        current_alert_id = resolve_alert_id_from_incident(args, incident)
        return bool(current_alert_id and current_alert_id in alert_ids)
    return True


def _should_sync_xsoar_incident(args: dict[str, Any], incident: dict[str, Any], incident_ids: list[str]) -> bool:
    """Return True when the open XSOAR investigation should be synced after an incident update."""
    if not incident.get("id"):
        return False
    if len(incident_ids) > 1 and _args_explicitly_set(args, "incident_id", "incident_ids"):
        current_incident_id = resolve_incident_id_from_incident(args, incident)
        return bool(current_incident_id and current_incident_id in incident_ids)
    return True


def _build_xsoar_alert_sync_entries(args: dict[str, Any], incident: dict[str, Any]) -> list[dict]:
    """Build war room entries that sync the open Vega Alert investigation without executeCommand."""
    if not incident.get("id"):
        demisto.debug("vega-update-alert: skipping XSOAR sync because no investigation ID is available.")
        return []

    entries: list[dict] = []
    field_change = _is_field_change_trigger(args)
    if not field_change and _args_explicitly_set(args, "status", "alert_status", "verdict"):
        custom_fields: dict[str, str] = {}
        status = _resolve_alert_status_for_update(args, incident)
        if status is not None:
            custom_fields[VEGA_ALERT_STATUS_FIELD] = _normalize_vega_status_for_display(status, MIRROR_ENTITY_SUFFIX_ALERT)
        verdict = _resolve_verdict_for_update(args, incident)
        if verdict is not None:
            custom_fields["vegaverdict"] = _normalize_vega_verdict_for_display(verdict)
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
        entries.extend(_incoming_status_entries(status, MIRROR_ENTITY_SUFFIX_ALERT))
    elif api_status in VEGA_ALERT_OPEN_STATUSES and _xsoar_incident_is_closed(incident):
        entries.extend(_incoming_status_entries(status, MIRROR_ENTITY_SUFFIX_ALERT))

    return entries


def _build_xsoar_incident_sync_entries(args: dict[str, Any], incident: dict[str, Any]) -> list[dict]:
    """Build war room entries that sync the open Vega Incident investigation without executeCommand."""
    if not incident.get("id"):
        demisto.debug("vega-update-incident: skipping XSOAR sync because no investigation ID is available.")
        return []

    entries: list[dict] = []
    field_change = _is_field_change_trigger(args)
    if not field_change and _args_explicitly_set(args, "status", "incident_status", "verdict"):
        custom_fields: dict[str, str] = {}
        status = _resolve_incident_status_for_update(args, incident)
        if status is not None:
            custom_fields[VEGA_INCIDENT_STATUS_FIELD] = _normalize_vega_status_for_display(status, MIRROR_ENTITY_SUFFIX_INCIDENT)
        verdict = _resolve_verdict_for_update(args, incident)
        if verdict is not None:
            custom_fields["vegaverdict"] = _normalize_vega_verdict_for_display(verdict)
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
        entries.extend(_incoming_status_entries(status, MIRROR_ENTITY_SUFFIX_INCIDENT))
    elif api_status in VEGA_INCIDENT_OPEN_STATUSES and _xsoar_incident_is_closed(incident):
        entries.extend(_incoming_status_entries(status, MIRROR_ENTITY_SUFFIX_INCIDENT))

    return entries


def update_alert_command(client: Client, args: dict[str, Any]) -> CommandResults | list[Any]:
    """Update Vega alert status and/or verdict, refresh mirror fingerprints, and sync XSOAR."""
    incident = load_current_incident()
    alert_ids = _resolve_alert_ids_for_update(args, incident)
    if not alert_ids:
        incident_type = str(incident.get("type") or incident.get("Type") or "unknown")
        xsoar_incident_id = incident.get("id") or "none"
        raise DemistoException(
            "At least one alert id is required when the command is not run from a Vega Alert incident. "
            f"Could not resolve alert ID from incident id={xsoar_incident_id}, type={incident_type}. "
            "Pass alert_id explicitly, for example: !vega-update-alert alert_id=alert-1 status=RESOLVED verdict=MALICIOUS"
        )

    effective_args = _build_effective_alert_update_args(args, incident)
    update_fields = _build_direct_alert_update_payload(effective_args)
    if not update_fields:
        raise DemistoException("At least one of status or verdict must be provided.")

    result = client.update_alerts({**update_fields, "alertIds": alert_ids})
    updated_alerts = result.get("alerts") or []
    _refresh_alert_mirror_fingerprints(client, alert_ids, updated_alerts)

    outputs = [_format_push_alert_output(alert) for alert in updated_alerts]
    readable = tableToMarkdown(
        "Updated Vega Alerts",
        outputs,
        headers=["id", "status", "verdict"],
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


def update_incident_command(client: Client, args: dict[str, Any]) -> CommandResults | list[Any]:
    """Update Vega incident status, verdict, and/or comment, refresh mirror fingerprints, and sync XSOAR."""
    incident = load_current_incident()
    incident_ids = _resolve_incident_ids_for_update(args, incident)
    if not incident_ids:
        incident_type = str(incident.get("type") or incident.get("Type") or "unknown")
        xsoar_incident_id = incident.get("id") or "none"
        raise DemistoException(
            "At least one incident id is required when the command is not run from a Vega Incident investigation. "
            f"Could not resolve incident ID from incident id={xsoar_incident_id}, type={incident_type}. "
            "Pass incident_id explicitly, for example: "
            "!vega-update-incident incident_id=inc-1 status=RESOLVED verdict=MALICIOUS comment=Updated"
        )

    effective_args = _build_effective_incident_update_args(args, incident)
    update_fields = _build_direct_incident_update_payload(effective_args)
    if not update_fields:
        raise DemistoException("At least one of status, verdict, or comment must be provided.")

    result = client.update_incidents({**update_fields, "incidentIds": incident_ids})
    updated_incidents = result.get("incidents") or []
    _refresh_incident_mirror_fingerprints(client, incident_ids, updated_incidents)

    outputs = [_format_push_incident_output(incident_item) for incident_item in updated_incidents]
    readable = tableToMarkdown(
        "Updated Vega Incidents",
        outputs,
        headers=["id", "status", "verdict"],
        removeNull=True,
    )
    command_result = CommandResults(
        readable_output=readable,
        outputs_prefix="Vega.Incident",
        outputs_key_field="id",
        outputs=outputs[0] if len(outputs) == 1 else outputs,
    )
    if not _should_sync_xsoar_incident(args, incident, incident_ids):
        return command_result

    sync_entries = _build_xsoar_incident_sync_entries(effective_args, incident)
    if sync_entries:
        return [command_result, *sync_entries]
    return command_result


def update_remote_system_command(client: Client, args: dict[str, Any], params: dict[str, Any]) -> str:
    """Push XSOAR incident changes to the corresponding Vega alert or incident."""
    if not argToBoolean(params.get("autoclosure", DEFAULT_AUTO_CLOSURE)):
        parsed_args = UpdateRemoteSystemArgs(args)
        demisto.debug("Vega autoclosure disabled; skipping outgoing mirroring.")
        return str(parsed_args.remote_incident_id)

    parsed_args = UpdateRemoteSystemArgs(args)
    remote_mirror_id = str(parsed_args.remote_incident_id)
    entity_id, entity_type_suffix = parse_mirror_id(remote_mirror_id)
    data = parsed_args.data or {}
    delta = parsed_args.delta or {}
    xsoar_incident_id = str(data.get("id", ""))
    mirror_tags = str(params.get("comment_tag", DEFAULT_COMMENT_TAG)).strip() or DEFAULT_COMMENT_TAG
    demisto.debug(f"Vega update-remote-system for {remote_mirror_id} (XSOAR incident {xsoar_incident_id})")

    if parsed_args.inc_status == IncidentStatus.DONE or "closingUserId" in delta:
        if entity_type_suffix == MIRROR_ENTITY_SUFFIX_ALERT:
            client.update_alerts({"alertIds": [entity_id], "status": "RESOLVED"})
        else:
            close_notes = str(data.get("closeNotes", "")).strip()
            close_reason = str(data.get("closeReason", "Resolved")).strip()
            comment = (
                f"{MIRRORED_FROM_XSOAR} XSOAR Incident ID: {xsoar_incident_id}\n\n"
                f"Close Reason: {close_reason}\n\n"
                f"Close Notes: {close_notes}"
            )
            client.update_incidents(
                _build_incident_update_input(
                    entity_id,
                    data,
                    {**delta, VEGA_INCIDENT_STATUS_FIELD: "RESOLVED"},
                    comment=comment,
                )
            )
        return remote_mirror_id

    if entity_type_suffix == MIRROR_ENTITY_SUFFIX_ALERT:
        update_input = _build_alert_update_input(entity_id, data, delta)
        if len(update_input) > 1:
            client.update_alerts(update_input)
    else:
        update_input = _build_incident_update_input(entity_id, data, delta)
        if len(update_input) > 1:
            client.update_incidents(update_input)

    for entry in parsed_args.entries or []:
        if not _entry_has_mirror_tag(entry, mirror_tags):
            continue
        entry_content = re.sub(r"([^\n])\n", r"\1\n\n", str(entry.get("contents", "")))
        if MIRRORED_FROM_VEGA in entry_content:
            continue
        entry_user = entry.get("user", "dbot") or "dbot"
        comment = (
            f"{MIRRORED_FROM_XSOAR} XSOAR Incident ID: {xsoar_incident_id}\n\n"
            f"Note: {entry_content}\n\n"
            f"Added By: {entry_user}"
        )
        if entity_type_suffix == MIRROR_ENTITY_SUFFIX_INCIDENT:
            client.update_incidents(_build_incident_update_input(entity_id, data, delta, comment=comment))

    return remote_mirror_id


def alert_to_incident(alert: dict, integration_url: str | None = None) -> dict:
    """Convert a Vega alert to an XSOAR incident.

    Args:
        alert: A single alert dict from the Vega API.
        integration_url: The Vega integration instance URL used to derive alert links.

    Returns:
        An XSOAR incident dict.
    """
    severity = VEGA_SEVERITY_TO_XSOAR.get(alert.get("severity", "").upper(), IncidentSeverity.UNKNOWN)
    created_at = alert.get("createdAt", "")

    # Inject vegaEntityType so the classifier transformer can route correctly
    raw = dict(alert)
    raw["vegaEntityType"] = "Vega Alert"
    _apply_vega_entity_link(raw, integration_url=integration_url)
    _apply_mirroring_to_raw(raw, MIRROR_ENTITY_SUFFIX_ALERT)
    _format_raw_entity_for_xsoar(raw)
    _store_alert_mirror_fingerprint(alert)

    xsoar_incident: dict[str, Any] = {
        "name": f"{raw.get('name', 'Unknown')}",
        "occurred": created_at,
        "severity": severity,
        "type": "Vega Alert",
        "rawJSON": json.dumps(raw),
    }
    custom_fields = _build_vega_alert_custom_fields(raw)
    if custom_fields:
        xsoar_incident["CustomFields"] = custom_fields
    return xsoar_incident


def incident_to_xsoar_incident(incident: dict, timeline_events: list[dict] | None = None) -> dict:
    """Convert a Vega incident to an XSOAR incident.

    Args:
        incident: A single incident dict from the Vega API.
        timeline_events: Optional timeline events from getIncidentsDetails.

    Returns:
        An XSOAR incident dict.
    """

    severity = VEGA_SEVERITY_TO_XSOAR.get(incident.get("severity", "").upper(), IncidentSeverity.UNKNOWN)
    created_at = incident.get("createdAt", "")

    # Inject vegaEntityType so the classifier transformer can route correctly
    raw = dict(incident)
    raw["vegaEntityType"] = "Vega Incident"
    _apply_mirroring_to_raw(raw, MIRROR_ENTITY_SUFFIX_INCIDENT)
    _store_incident_mirror_fingerprint(incident)
    if timeline_events is not None:
        raw["timelineEvents"] = timeline_events
        raw["vegaTimelineEvents"] = _format_timeline_events_html(timeline_events)
    _apply_vega_entity_link(raw)
    _format_raw_entity_for_xsoar(raw)

    xsoar_incident: dict[str, Any] = {
        "name": f"{raw.get('name', 'Unknown')}",
        "occurred": created_at,
        "severity": severity,
        "type": "Vega Incident",
        "rawJSON": json.dumps(raw),
    }
    custom_fields = _build_vega_incident_custom_fields(raw)
    if custom_fields:
        xsoar_incident["CustomFields"] = custom_fields
    return xsoar_incident


def _normalize_entity_id(entity: dict, id_key: str = "id") -> str:
    """Return a stable string ID for deduplication."""
    entity_id = entity.get(id_key)
    if entity_id is None or entity_id == "":
        return ""
    return str(entity_id)


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


def _resolve_next_fetch_state(
    last_run: dict,
    last_fetch_key: str,
    fetched_entities: list[dict],
    previous_last_fetch: str,
    previous_last_ids: list[str],
) -> tuple[str, list[str]]:
    """Advance fetch cursor state, using current time when initial backfill returns nothing."""
    new_last_fetch, new_last_ids = _update_fetch_state(fetched_entities, previous_last_fetch, previous_last_ids)
    if last_run.get(last_fetch_key) in (None, "") and not fetched_entities:
        demisto.debug(f"Vega {last_fetch_key}: initial backfill returned no entities, advancing cursor to current time.")
        return _current_fetch_timestamp(), []
    return new_last_fetch, new_last_ids


def _should_ingest_entity(
    entity: dict,
    last_fetch: str,
    last_ids: list[str],
    id_key: str = "id",
    time_key: str = "createdAt",
) -> bool:
    """Return True when an entity should be ingested based on cursor timestamp and boundary IDs."""
    entity_id = _normalize_entity_id(entity, id_key)
    if not entity_id:
        return False

    parsed_time_raw = _parse_entity_created_at(entity.get(time_key))
    last_dt_raw = _parse_entity_created_at(last_fetch)
    if parsed_time_raw is None or last_dt_raw is None:
        return True

    parsed_time = _normalize_fetch_datetime(parsed_time_raw)
    last_dt = _normalize_fetch_datetime(last_dt_raw)

    if parsed_time > last_dt:
        return True
    if parsed_time == last_dt:
        boundary_ids = {str(entity_id_value) for entity_id_value in last_ids if entity_id_value}
        return entity_id not in boundary_ids
    return False


def _fetch_paginated_entities(
    fetch_func: Callable[..., dict],
    entities_key: str,
    max_entities: int | None = None,
    **fetch_kwargs: Any,
) -> list[dict]:
    """Fetch entities from the Vega API with offset-based pagination.

    Paginates through all available pages until the API reports no more results,
    or until max_entities is reached when set.

    Args:
        fetch_func: Client method (get_alerts or get_incidents).
        entities_key: Response key holding the entity list ('alerts' or 'incidents').
        max_entities: Optional cap on total entities to retrieve across all pages.
        **fetch_kwargs: Keyword arguments forwarded to fetch_func (excluding limit/offset).

    Returns:
        Combined list of all entities returned by the API for the given filters.
    """
    entities: list[dict] = []
    offset = 0

    while True:
        request_kwargs = dict(fetch_kwargs)
        if max_entities is not None:
            remaining = max_entities - len(entities)
            if remaining <= 0:
                break
            request_kwargs["limit"] = remaining

        response = fetch_func(offset=offset, **request_kwargs)

        api_error = response.get("error")
        if api_error and api_error.get("message"):
            demisto.debug(f"Vega API error during pagination: {api_error.get('message')}")

        page = response.get(entities_key) or []
        if not page:
            break

        entities.extend(page)
        if max_entities is not None and len(entities) >= max_entities:
            entities = entities[:max_entities]
            break

        total = response.get("total")

        if total is not None and offset + len(page) >= total:
            break

        offset += len(page)

    demisto.debug(f"Paginated fetch for {entities_key}: retrieved {len(entities)} entities (offset up to {offset}).")
    return entities


def _update_fetch_state(
    fetched_entities: list[dict],
    previous_last_fetch: str,
    previous_last_ids: list[str],
    id_key: str = "id",
    time_key: str = "createdAt",
) -> tuple[str, list[str]]:
    """Calculate next-run last_fetch and last_ids from a paginated API response.

    Uses parsed UTC datetimes for comparisons so mixed timestamp formats (e.g. with/without
    milliseconds) do not break cursor advancement or boundary ID tracking.

    Args:
        fetched_entities: All entities returned across paginated API calls.
        previous_last_fetch: ISO 8601 timestamp from the previous run.
        previous_last_ids: Entity IDs seen at the previous last_fetch timestamp.
        id_key: Field name for the entity ID.
        time_key: Field name for the entity creation timestamp.

    Returns:
        Tuple of (new_last_fetch, new_last_ids).
    """
    if not fetched_entities:
        return previous_last_fetch, previous_last_ids

    parsed_entities: list[tuple[dict, datetime]] = []
    for entity in fetched_entities:
        parsed_time_raw = _parse_entity_created_at(entity.get(time_key))
        if parsed_time_raw is not None:
            parsed_entities.append((entity, _normalize_fetch_datetime(parsed_time_raw)))

    if not parsed_entities:
        return previous_last_fetch, previous_last_ids

    max_dt = max(parsed_time for _, parsed_time in parsed_entities)
    max_time = _format_fetch_timestamp(max_dt)
    previous_dt_raw = _parse_entity_created_at(previous_last_fetch)
    previous_dt = _normalize_fetch_datetime(previous_dt_raw) if previous_dt_raw is not None else None
    previous_last_ids_normalized = [str(entity_id) for entity_id in previous_last_ids if entity_id]

    ids_at_max: list[str] = []
    for entity, parsed_time in parsed_entities:
        if parsed_time == max_dt:
            entity_id = _normalize_entity_id(entity, id_key)
            if entity_id:
                ids_at_max.append(entity_id)

    if previous_dt is None or max_dt > previous_dt:
        return max_time, ids_at_max
    if max_dt == previous_dt:
        return max_time, list(set(previous_last_ids_normalized + ids_at_max))

    # Edge case: API returned entities older than last_fetch (inclusive from filter).
    return previous_last_fetch, list(set(previous_last_ids_normalized + ids_at_max))


def _build_fetch_filter_fingerprint(
    severities: list[str] | None,
    statuses: list[str] | None,
    verdicts: list[str] | None,
) -> str:
    """Build a stable fingerprint for fetch filter parameters."""
    payload = {
        "severities": sorted(severities or []),
        "statuses": sorted(statuses or []),
        "verdicts": sorted(verdicts or []),
    }
    return json.dumps(payload, sort_keys=True)


def _log_fetch_filter_change(
    last_run: dict,
    fetch_config_key: str,
    current_fetch_config: str,
    last_fetch_key: str,
) -> None:
    """Log when fetch filters changed; incremental fetch still uses the stored cursor."""
    stored_config = last_run.get(fetch_config_key)
    if stored_config is not None and stored_config != current_fetch_config:
        demisto.debug(
            f"Vega {last_fetch_key}: fetch filters changed (stored={stored_config}, current={current_fetch_config}). "
            "Re-fetching from the stored cursor with the updated filters."
        )


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
        demisto.debug(f"Vega {last_fetch_key}: using stored cursor from_time={stored_fetch}")
        return str(stored_fetch)

    if stored_fetch not in (None, ""):
        demisto.debug(
            f"Vega {last_fetch_key}: stored cursor is not anchored to fetch filters, "
            f"using backfill from_time={first_fetch_time}"
        )
        return first_fetch_time

    demisto.debug(f"Vega {last_fetch_key}: using backfill from_time={first_fetch_time}")
    return first_fetch_time


def fetch_incidents_command(
    client: Client,
    last_run: dict,
    fetch_alerts: bool,
    fetch_incidents: bool,
    alert_severities: list[str] | None,
    alert_statuses: list[str] | None,
    alert_verdicts: list[str] | None,
    incident_severities: list[str] | None,
    incident_statuses: list[str] | None,
    incident_verdicts: list[str] | None,
    first_fetch_time: str,
    integration_url: str | None = None,
) -> tuple[dict, list[dict]]:
    """Fetch alerts and/or incidents from Vega and return them as XSOAR incidents.

    Args:
        client: The Vega API client.
        last_run: The last run dict from demisto.getLastRun().
        integration_url: The Vega integration instance URL used to derive alert links.
        fetch_alerts: Whether to fetch alerts.
        fetch_incidents: Whether to fetch incidents.
        alert_severities: Filter alerts by severity.
        alert_statuses: Filter alerts by status.
        alert_verdicts: Filter alerts by verdict.
        incident_severities: Filter incidents by severity.
        incident_statuses: Filter incidents by status.
        incident_verdicts: Filter incidents by verdict.
        first_fetch_time: ISO 8601 timestamp to use as the start time on the first run.

    Returns:
        A tuple of (next_run, xsoar_incidents).
    """
    xsoar_incidents: list[dict] = []
    next_run: dict = dict(last_run)
    next_run.pop("alerts_seen_ids", None)
    next_run.pop("incidents_seen_ids", None)
    next_run.pop("vega_backfill_days", None)

    alerts_fetch_config = _build_fetch_filter_fingerprint(alert_severities, alert_statuses, alert_verdicts)
    incidents_fetch_config = _build_fetch_filter_fingerprint(incident_severities, incident_statuses, incident_verdicts)

    if fetch_alerts:
        _log_fetch_filter_change(last_run, "alerts_fetch_config", alerts_fetch_config, "alerts_last_fetch")
    if fetch_incidents:
        _log_fetch_filter_change(last_run, "incidents_fetch_config", incidents_fetch_config, "incidents_last_fetch")

    alerts_from_time = _resolve_fetch_from_time(last_run, "alerts_last_fetch", first_fetch_time)
    incidents_from_time = _resolve_fetch_from_time(last_run, "incidents_last_fetch", first_fetch_time)
    alerts_last_fetch = last_run.get("alerts_last_fetch") or first_fetch_time
    incidents_last_fetch = last_run.get("incidents_last_fetch") or first_fetch_time
    alerts_last_ids: list[str] = last_run.get("alerts_last_ids", [])
    incidents_last_ids: list[str] = last_run.get("incidents_last_ids", [])

    if fetch_alerts:
        demisto.debug("Fetching Vega alerts...")
        try:
            alerts = _fetch_paginated_entities(
                client.get_alerts,
                entities_key="alerts",
                max_entities=GET_ALERTS_FETCH_LIMIT,
                severities=alert_severities,
                statuses=alert_statuses,
                verdicts=alert_verdicts,
                from_time=alerts_from_time,
            )
            demisto.debug(f"Fetched {len(alerts)} alerts from Vega. Boundary IDs at cursor: {len(alerts_last_ids)}.")

            new_alerts = 0
            for alert in alerts:
                if not _should_ingest_entity(alert, alerts_last_fetch, alerts_last_ids):
                    continue
                xsoar_incidents.append(alert_to_incident(alert, integration_url=integration_url))
                new_alerts += 1

            next_run["alerts_last_fetch"], next_run["alerts_last_ids"] = _resolve_next_fetch_state(
                last_run, "alerts_last_fetch", alerts, alerts_last_fetch, alerts_last_ids
            )
            previous_alerts_fetch_config = last_run.get("alerts_fetch_config")
            if previous_alerts_fetch_config is not None and previous_alerts_fetch_config != alerts_fetch_config:
                next_run["alerts_last_ids"] = list(
                    set([str(entity_id) for entity_id in alerts_last_ids if entity_id] + next_run["alerts_last_ids"])
                )
            next_run["alerts_fetch_config"] = alerts_fetch_config
            demisto.debug(f"Vega alerts ingest: {new_alerts} new, {len(alerts) - new_alerts} skipped as duplicates.")

        except Exception as e:
            demisto.debug(f"Error fetching Vega alerts: {e}")
            raise

    if fetch_incidents:
        demisto.debug("Fetching Vega incidents...")
        try:
            incidents = _fetch_paginated_entities(
                client.get_incidents,
                entities_key="incidents",
                severities=incident_severities,
                statuses=incident_statuses,
                verdicts=incident_verdicts,
                from_time=incidents_from_time,
            )
            demisto.debug(f"Fetched {len(incidents)} incidents from Vega. Boundary IDs at cursor: {len(incidents_last_ids)}.")

            new_incidents = 0
            for incident in incidents:
                incident_id = _normalize_entity_id(incident)
                if not _should_ingest_entity(incident, incidents_last_fetch, incidents_last_ids):
                    continue
                timeline_events: list[dict] = []
                if incident_id:
                    try:
                        details = client.get_incident_details(str(incident_id))
                        fetched_events = details.get("timelineEvents")
                        if isinstance(fetched_events, list):
                            timeline_events = [event for event in fetched_events if isinstance(event, dict)]
                        key_findings = details.get("keyFindings")
                        if isinstance(key_findings, list) and key_findings:
                            incident["keyFindings"] = key_findings
                    except Exception as details_error:
                        demisto.debug(f"Could not fetch incident details for Vega incident {incident_id}: {details_error}")
                xsoar_incidents.append(incident_to_xsoar_incident(incident, timeline_events=timeline_events))
                new_incidents += 1

            next_run["incidents_last_fetch"], next_run["incidents_last_ids"] = _resolve_next_fetch_state(
                last_run, "incidents_last_fetch", incidents, incidents_last_fetch, incidents_last_ids
            )
            previous_incidents_fetch_config = last_run.get("incidents_fetch_config")
            if previous_incidents_fetch_config is not None and previous_incidents_fetch_config != incidents_fetch_config:
                next_run["incidents_last_ids"] = list(
                    set([str(entity_id) for entity_id in incidents_last_ids if entity_id] + next_run["incidents_last_ids"])
                )
            next_run["incidents_fetch_config"] = incidents_fetch_config
            demisto.debug(f"Vega incidents ingest: {new_incidents} new, {len(incidents) - new_incidents} skipped as duplicates.")

        except Exception as e:
            demisto.debug(f"Error fetching Vega incidents: {e}")
            raise

    demisto.debug(f"Total XSOAR incidents to ingest: {len(xsoar_incidents)}")
    return next_run, xsoar_incidents


def test_module(client: Client, backfill_days: str | int | None = None):
    try:
        client.test_connection(backfill_days)
        return "ok"
    except Exception as e:
        return str(e)


def main() -> None:
    params = demisto.params()
    command = demisto.command()

    access_key = params.get("access_key")
    access_key_id = params.get("access_key_id")
    verify_certificate = not argToBoolean(params.get("insecure", False))
    proxy = argToBoolean(params.get("proxy", False))

    base_url = params.get("url")

    demisto.debug(f"Command being called is {command}")

    try:
        vega_entities = argToList(
            params.get("vega_entities") if params.get("vega_entities") is not None else ["Alerts", "Incidents"]
        )
        fetch_alerts = "Alerts" in vega_entities
        fetch_incidents = "Incidents" in vega_entities
        if not fetch_alerts and not fetch_incidents:
            raise ValueError("At least one of 'Fetch Alerts' or 'Fetch Incidents' must be checked.")

        # Parse filter parameters
        alert_severities = filter_alert_severities(argToList(params.get("alert_severities")) or None)
        alert_statuses = filter_alert_statuses(argToList(params.get("alert_statuses")) or None)
        alert_verdicts = filter_alert_verdicts(argToList(params.get("alert_verdicts")) or None)
        incident_severities = filter_incident_severities(argToList(params.get("incident_severities")) or None)
        incident_statuses = filter_incident_statuses(argToList(params.get("incident_statuses")) or None)
        incident_verdicts = filter_incident_verdicts(argToList(params.get("incident_verdicts")) or None)

        backfill_days = params.get("backfill_days")
        first_fetch_time = parse_backfill_days(
            backfill_days,
            legacy_first_fetch=params.get("first_fetch"),
        )

        client = Client(
            base_url=base_url,
            verify=verify_certificate,
            proxy=proxy,
            access_key=access_key,
            access_key_id=access_key_id,
        )

        if command == "test-module":
            result = test_module(client, backfill_days)
            return_results(result)

        elif command == "vega-fetch-alert-events":
            return_results(fetch_alert_events_command(client, demisto.args()))

        elif command == "vega-set-detections-state":
            return_results(set_detections_state_command(client, demisto.args()))

        elif command == "vega-update-detections":
            return_results(update_detections_command(client, demisto.args()))

        elif command == "vega-update-alert":
            return_results(update_alert_command(client, demisto.args()))

        elif command == "vega-update-incident":
            return_results(update_incident_command(client, demisto.args()))

        elif command == "get-modified-remote-data":
            return_results(
                get_modified_remote_data_command(
                    client,
                    demisto.args(),
                    params,
                    alert_severities=alert_severities,
                    alert_statuses=alert_statuses,
                    alert_verdicts=alert_verdicts,
                    incident_severities=incident_severities,
                    incident_statuses=incident_statuses,
                    incident_verdicts=incident_verdicts,
                )
            )

        elif command == "get-remote-data":
            return_results(get_remote_data_command(client, demisto.args()))

        elif command == "update-remote-system":
            return_results(update_remote_system_command(client, demisto.args(), params))

        elif command == "fetch-incidents":
            last_run = demisto.getLastRun()
            next_run, xsoar_incidents = fetch_incidents_command(
                client=client,
                last_run=last_run,
                fetch_alerts=fetch_alerts,
                fetch_incidents=fetch_incidents,
                alert_severities=alert_severities,
                alert_statuses=alert_statuses,
                alert_verdicts=alert_verdicts,
                incident_severities=incident_severities,
                incident_statuses=incident_statuses,
                incident_verdicts=incident_verdicts,
                first_fetch_time=first_fetch_time,
                integration_url=base_url,
            )
            demisto.setLastRun(next_run)
            demisto.incidents(xsoar_incidents)

        else:
            raise NotImplementedError(f"Command {command} is not implemented")

    except Exception as e:
        return_error(f"Failed to execute {command} command.\nError:\n{str(e)}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
