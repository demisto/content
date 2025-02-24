from collections import defaultdict
import http
from functools import wraps
from http import HTTPStatus
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from requests import Response
from typing import get_type_hints, Union, Any, Optional, get_origin, get_args, Callable
import inspect

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

import urllib3

# Disable insecure warnings
urllib3.disable_warnings()


""" CONSTANTS """

VENDOR = "forcepoint"
PRODUCT = "forcepoint_dlp"
DEFAULT_MAX_FETCH = 10000
API_DEFAULT_LIMIT = 10000
MAX_GET_IDS_CHUNK_SIZE = 1000
DEFAULT_TEST_MODULE_SINCE_TIME = "3 days"
DATEPARSER_SETTINGS = {
    "RETURN_AS_TIMEZONE_AWARE": True,
    "TIMEZONE": "UTC",
}
DATE_TIME_FORMAT = "%d/%m/%Y %H:%M:%S"


""" CLIENT CLASS """


def to_str_time(t: datetime) -> str:
    return t.strftime(DATE_TIME_FORMAT)


def from_str_time(s: str) -> datetime:
    return datetime.strptime(s, DATE_TIME_FORMAT)


NO_CONTENT_CODE = 420
NO_CONTENT_MESSAGE = "No data to show"
MISSING_RULE_NAME = "The argument 'rule_name' is required when using policy_name."
DATE_FORMAT = "%d/%m/%Y %H:%M:%S"
XSOAR_DATE_FORMAT = "%Y-%m-%dT%H:%M:%S.000Z"
MIRRORING_FIELDS = [
    "status",
    "severity",
    "false_positive",
]
INTEGRATION_NAME = "fp-dlp"
INCIDENT_UPDATE_MAPPER = [
    ("status", "STATUS"),
    ("assign", "ASSIGN_TO"),
    ("tag", "TAG"),
    ("severity", "SEVERITY"),
    ("release", "RELEASE"),
    ("false_positive", "FALSE_POSITIVE"),
]
INTEGRATION_PREFIX = "ForcepointDlp"
CLASSIFIER_HEADERS = [
    "predefined",
    "position",
    "threshold_type",
    "threshold_value_from",
    "threshold_value_to",
    "threshold_calculate_type",
]
RULE_EXCEPTION_HEADERS = [
    "exception_rule_name",
    "enabled",
    "description",
    "display_description",
    "condition_enabled",
    "destination_enabled",
]
INCIDENT_HEADERS = [
    "id",
    "event_id",
    "severity",
    "action",
    "status",
    "source_ip_address",
    "event_time",
    "channel",
    "tag",
    "assigned_to",
]
MIRROR_DIRECTION_MAPPING = {
    "None": None,
    "Incoming": "In",
    "Outgoing": "Out",
    "Incoming And Outgoing": "Both",
}
FP_XSOAR_SEVERITY_MAPPER = {
    "LOW": 2,
    "MEDIUM": 3,
    "HIGH": 4,
}
XSOAR_FP_SEVERITY_MAPPER = {
    0: "LOW",
    1: "LOW",
    2: "LOW",
    3: "MEDIUM",
    4: "HIGH",
    5: "HIGH",
}
DEFAULT_LIMIT = 50


class ValidatableMixin:
    """
    Mixin that adds automatic validation to dataclasses using __post_init__ and inspect.
    """

    def __post_init__(self):
        self.validate_fields()

    def validate_fields(self):
        """
        Validate all fields in the dataclass based on type hints and custom validators.
        """
        sig = inspect.signature(self.__init__)
        type_hints = get_type_hints(self.__class__)  # Type annotations for the dataclass

        for param_name, _ in sig.parameters.items():
            if param_name == "self":  # Skip 'self'
                continue
            value = getattr(self, param_name, None)
            expected_type = type_hints.get(param_name, Any)  # Default to Any if not annotated

            # Handle None values
            if value is None and not self._is_optional(expected_type):
                raise DemistoException(f"Field '{param_name}' cannot be None.")

            # Handle Union types (e.g., `str | None` or `Union[str, int]`)
            if self._is_union(expected_type):
                allowed_types = get_args(expected_type)
                if not any(isinstance(value, t) for t in allowed_types if t is not type(None)):
                    raise TypeError(
                        f"Field '{param_name}' must be of type {expected_type}, "
                        f"got {type(value).__name__} instead."
                    )

            # Handle generic types like list[int], dict[str, int]
            elif (origin := get_origin(expected_type)) is not None:
                if not isinstance(value, origin):
                    raise TypeError(
                        f"Field '{param_name}' must be of type {expected_type}, "
                        f"got {type(value).__name__} instead."
                    )

            # Standard type check
            elif expected_type is not Any and not isinstance(value, expected_type):
                raise TypeError(
                    f"Field '{param_name}' must be of type {expected_type}, "
                    f"got {type(value).__name__} instead."
                )

            # Custom field validator if defined (validate_<field_name>)
            custom_validator = getattr(self, f"validate_{param_name}", None)
            if callable(custom_validator):
                custom_validator(value)

    def _is_optional(self, expected_type):
        """Check if a type hint allows None (i.e., Optional, Union with None, or new-style '| None')."""
        return self._is_union(expected_type) and type(None) in get_args(expected_type)

    def _is_union(self, expected_type):
        """Check if a type hint is a Union type (including new-style '|')."""
        return get_origin(expected_type) is Union


@dataclass
class Classifier(ValidatableMixin):
    """
    Represents a classifier inside a rule
    """

    classifier_name: str
    predefined: str
    position: int
    threshold_type: str
    threshold_value_from: int
    threshold_calculate_type: str
    threshold_value_to: Optional[int] = None

    def __post_init__(self) -> None:
        if self.threshold_type == "CHECK_IN_RANGE" and self.threshold_value_to is None:
            raise DemistoException(
                f"Field 'threshold_value_to' for classifier {self.classifier_name} cannot be None."
            )
        if (
            self.threshold_value_to
            and self.threshold_type == "CHECK_IN_RANGE"
            and self.threshold_value_from > self.threshold_value_to
        ):
            raise DemistoException(
                f"Field 'threshold_value_from' for classifier {self.classifier_name}\
                      shoud be lower than field 'threshold_value_to'."
            )
        if self.predefined not in ["true", "false"]:
            raise DemistoException(
                f"Invalid value for classifier {self.classifier_name} 'predefined': {self.predefined}.\
                  Must be 'true' or 'false'."
            )


@dataclass
class SeverityActionClassifier(ValidatableMixin):
    """
    Represents severity and action classifier.
    """

    number_of_matches: int
    selected: str
    severity_type: str
    action_plan: str
    dup_severity_type: str

    def __post_init__(self) -> None:
        if self.selected not in ["true", "false"]:
            raise DemistoException(
                f"Invalid value for severity classifier {self.number_of_matches} \
                    'selected': {self.selected}. Must be 'true' or 'false'."
            )


@dataclass
class Rule(ValidatableMixin):
    """
    Represents a policy rule.
    """

    rule_name: str
    enabled: str
    parts_count_type: str
    condition_relation_type: str
    classifiers: list[Classifier]

    def __post_init__(self) -> None:
        if self.enabled not in ["true", "false"]:
            raise DemistoException(
                f"Invalid value for {self.rule_name} 'enabled': {self.enabled}. Must be 'true' or 'false'."
            )
        if not self.classifiers:
            raise DemistoException(f"Rule '{self.rule_name}' must have at least one classifier.")

        positions = []
        for classifier in self.classifiers:
            positions.append(classifier.position)

        if len(set(positions)) < len(self.classifiers):
            raise DemistoException("The classifier position already exists.")

        if set(range(1, len(self.classifiers) + 1)) != set(positions):
            raise DemistoException("Invalid classifier position.")


@dataclass
class SeverityActionException(ValidatableMixin):
    """
    Represents a severity and action exception in rule.
    """

    max_matches: str
    classifier_details: list[SeverityActionClassifier]

    def __post_init__(self) -> None:
        if len(self.classifier_details) > 3:
            raise DemistoException(
                "The maximum number of classifiers is 3.\
                      Use `override_classifier_number_of_matches` to override another classifier."
            )


@dataclass
class ExceptionRule(ValidatableMixin):
    """
    Represents an exception of a rule.
    """

    exception_rule_name: str
    enabled: str
    condition_enabled: str
    source_enabled: str
    destination_enabled: str
    parts_count_type: str
    condition_relation_type: str
    classifiers: list[Classifier]
    severity_action: SeverityActionException
    description: Optional[str] = None
    display_description: Optional[str] = None

    def __post_init__(self) -> None:
        if self.enabled not in ["true", "false"]:
            raise DemistoException(
                f"Invalid value for 'enabled': {self.enabled}. Must be 'true' or 'false'."
            )
        if not self.classifiers:
            raise DemistoException(
                f"Exception Rule '{self.exception_rule_name}' must have at least one classifier."
            )

        positions = []
        for classifier in self.classifiers:
            positions.append(classifier.position)

        if len(set(positions)) < len(self.classifiers):
            raise DemistoException("The classifier position already exists.")

        if set(range(1, len(self.classifiers) + 1)) != set(positions):
            raise DemistoException("Invalid classifier position.")


@dataclass
class SeverityActionRule(ValidatableMixin):
    """
    Represents severity and action settings in rule.
    """

    rule_name: str
    type: str
    max_matches: str
    classifier_details: list[SeverityActionClassifier]
    risk_adaptive_protection_enabled: str
    count_type: Optional[str] = None
    count_time_period: Optional[str] = None
    count_time_period_window: Optional[str] = None

    def __post_init__(self) -> None:
        if self.risk_adaptive_protection_enabled not in ["true", "false"]:
            raise DemistoException(
                f"Invalid value for 'selected': {self.risk_adaptive_protection_enabled}. Must be 'true' or 'false'."
            )
        if self.type == "CUMULATIVE_CONDITION" and not self.count_type:
            raise DemistoException(
                "The field `rule_count_type` is required when the type is `CUMULATIVE_CONDITION`."
            )
        if self.type == "CUMULATIVE_CONDITION" and not self.count_time_period:
            raise DemistoException(
                "The field `count_time_period` is required when the type is `CUMULATIVE_CONDITION`."
            )
        if self.type == "CUMULATIVE_CONDITION" and not self.count_time_period_window:
            raise DemistoException(
                "The field `rule_rate_match_period` is required when the type is `CUMULATIVE_CONDITION`."
            )

        if len(self.classifier_details) > 3:
            raise DemistoException(
                "The maximum number of classifiers is 3.\
                      Use `override_classifier_number_of_matches` to override another classifier."
            )


@dataclass
class Resource(ValidatableMixin):
    """
    Represents a resoure in rule.
    """

    resource_name: str
    type: str
    include: Optional[str]

    def __post_init__(self) -> None:
        if self.include and self.include not in ["true", "false"]:
            raise DemistoException(
                f"Invalid value for resource 'include': {self.include}. Must be 'true' or 'false'."
            )


@dataclass
class Channel(ValidatableMixin):
    """
    Represents a channel in rule source and destination.
    """

    channel_type: str
    enabled: str
    resources: list[Resource] = field(default_factory=list)
    user_operations: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        if self.enabled not in ["true", "false"]:
            raise DemistoException(
                f"Invalid value for the channel ({self.channel_type}) \
                    'enabled': {self.enabled}. Must be 'true' or 'false'."
            )


@dataclass
class RuleDestination(ValidatableMixin):
    """
    Represents destination settings in source and destination rule.
    """

    email_monitor_directions: list[str]
    channels: list[Channel]


@dataclass
class RuleSource(ValidatableMixin):
    """
    Represents source settings in source and destination rule.
    """

    endpoint_channel_machine_type: str
    endpoint_connection_type: str
    resources: list[Resource] = field(default_factory=list)


@dataclass
class SourceDestinationRule(ValidatableMixin):
    """
    Represents source and destination settings rule.
    """

    rule_name: str
    rule_source: RuleSource
    rule_destination: RuleDestination


@dataclass
class PolicyLevel(ValidatableMixin):
    """
    Represents the rule policy level.
    """

    level: int
    data_type: Optional[str] = None


@dataclass
class PolicyRule(ValidatableMixin):
    """
    Represents a rule in policy.
    """

    dlp_version: str
    policy_name: str
    enabled: str
    predefined_policy: str
    description: str
    policy_level: PolicyLevel
    rules: list[Rule]

    def __post_init__(self) -> None:
        if self.enabled not in ["true", "false"]:
            raise DemistoException(
                f"Invalid value for 'enabled': {self.enabled}. Must be 'true' or 'false'."
            )
        if self.predefined_policy not in ["true", "false"]:
            raise DemistoException(
                f"Invalid value for 'predefined_policy': {self.predefined_policy}. Must be 'true' or 'false'."
            )
        if not self.rules:
            raise DemistoException("Policy must have at least one rule.")


@dataclass
class PolicySeverityAction(ValidatableMixin):
    """
    Represents severity and action rule.
    """

    policy_name: str
    rules: list[SeverityActionRule]


@dataclass
class PolicySourceDestination(ValidatableMixin):
    """
    Represents source and destination rule.
    """

    policy_name: str
    rules: list[SourceDestinationRule]


@dataclass
class PolicyExceptionRule(ValidatableMixin):
    """
    Represents exception rule.
    """

    parent_policy_name: str
    parent_rule_name: str
    policy_type: str
    exception_rules: list[ExceptionRule]


def validate_authentication(func: Callable) -> Callable:
    """
    Decorator to manage authentication for API requests.

    This decorator first attempts to execute the provided function using an existing authentication
    access token stored in the 'integration_context'. If the current token is not available or invalid
    (indicated by an HTTP FORBIDDEN status), it will attempt to re-authenticate with the API and then
    retry the function execution.

    The 'integration_context' is used to store and retrieve the authentication token, ensuring that
    the latest valid authentication details are used across different executions.

    Args:
        func (Callable): The API request function to be decorated and executed.

    Raises:
        DemistoException:
            - If the API returns an HTTP FORBIDDEN status during the initial request attempt and
              re-authentication also fails.
            - If the API returns any other error during the request.

    Returns:
        Callable: The result from executing 'func' with the provided arguments and keyword arguments.
    """

    @wraps(wrapped=func)
    def wrapper(client: "Client", *args, **kwargs):
        def try_request():
            """
            Attempts to execute the API request function. If the request fails due to authorization,
            it triggers a re-authentication and retries the request.
            """
            try:
                return func(client, *args, **kwargs)
            except DemistoException as err:
                if err.res.status_code in (
                    http.HTTPStatus.FORBIDDEN,
                    err.res.status_code == http.HTTPStatus.BAD_REQUEST,
                ):
                    demisto.debug(f"Got {err.res.status_code}. GOTO update_headers")
                    update_headers()
                return func(client, *args, **kwargs)

        def try_authentication():
            """
            Attempts to authenticate with the API and extract the access token from the response.
            In case of error or exceptions, it handles them appropriately,
            updating the integration context or raising a tailored exception.
            """
            demisto.debug("Attempting authentication")
            try:
                res = client.authenticate()
                if res.status_code == HTTPStatus.FORBIDDEN:
                    raise DemistoException("AUTHORIZATION_ERROR")
                return res.json().get("access_token")

            except DemistoException as err:
                integration_context = get_integration_context()
                integration_context["access_token"] = None
                set_integration_context(integration_context)
                raise DemistoException("AUTHORIZATION_ERROR", res=err.res)

        def update_headers():
            """Updates the session and integration context with a new access token."""
            access_token = try_authentication()
            demisto.debug("Save new token to integration context")
            client._headers = {"Authorization": f"Bearer {access_token}"}
            integration_context = get_integration_context()
            integration_context["access_token"] = access_token
            set_integration_context(integration_context)

        demisto.debug("Try to request with integration context token")
        integration_context = get_integration_context()
        access_token = integration_context.get("access_token")
        client._headers = {"Authorization": f"Bearer {access_token}"}
        return try_request()

    return wrapper


class Client(BaseClient):
    def __init__(
        self,
        base_url: str,
        username: str,
        password: str,
        verify: bool,
        proxy: bool,
        utc_now: datetime,
        api_limit=API_DEFAULT_LIMIT,
        **kwargs,
    ):
        self.username = username
        self.password = password
        self.api_limit = api_limit
        self.utc_now = utc_now
        super().__init__(
            base_url=urljoin(base_url, "dlp/rest/v1"),
            verify=verify,
            proxy=proxy,
        )
        self._headers = {}

    @validate_authentication
    def _http_request(self, *args, **kwargs):
        kwargs["error_handler"] = self.error_handler
        return super()._http_request(*args, **kwargs)

    def error_handler(self, res: Response):
        """Error handler for the API response.

        Args:
            res (Response): Error response.

        Raises:
            DemistoException: There is no data to return.
        """
        error_code = res.status_code
        if error_code == NO_CONTENT_CODE:
            raise DemistoException(
                NO_CONTENT_MESSAGE,
                res=res,
            )
        else:
            raise DemistoException(
                "ERROR:",
                res=res,
            )

    def authenticate(self) -> Response:
        return super()._http_request(
            method="POST",
            url_suffix="auth/refresh-token",
            headers={"username": self.username, "password": self.password},
            resp_type="response",
            ok_codes=[HTTPStatus.OK],
        )

    def list_policies(self, policy_type: str = "DLP") -> dict:
        return self._http_request(
            method="GET",
            url_suffix="policy/enabled-names",
            params={"type": policy_type},
        )

    def list_policy_rules(self, policy_name: str) -> dict:
        return self._http_request(
            method="GET",
            url_suffix="policy/rules",
            params={"policyName": policy_name},
        )

    def list_exception_rules(self, policy_type: str = "DLP") -> dict:
        return self._http_request(
            method="GET",
            url_suffix="policy/rules/exceptions/all",
            params={"type": policy_type},
        )

    def get_exception_rule(
        self,
        policy_type: str,
        policy_name: str,
        rule_name: str,
    ) -> dict:
        return self._http_request(
            method="GET",
            url_suffix="policy/rules/exceptions",
            params={
                "type": policy_type,
                "policyName": policy_name,
                "ruleName": rule_name,
            },
        )

    def get_rule_severity_action(
        self,
        policy_name: str,
    ) -> dict:
        return self._http_request(
            method="GET",
            url_suffix="policy/rules/severity-action",
            params={"policyName": policy_name},
        )

    def get_rule_source_destination(
        self,
        policy_name: str,
    ) -> dict:
        return self._http_request(
            method="GET",
            url_suffix="policy/rules/source-destination",
            params={"policyName": policy_name},
        )

    def list_incidents(
        self,
        incident_type: str = "INCIDENTS",
        ids: list[int] | None = None,
        sort_by: str | None = None,
        from_date: str | None = None,
        to_date: str | None = None,
        detected_by: str | None = None,
        analyzed_by: str | None = None,
        event_id: str | None = None,
        destination: str | None = None,
        policies: list[str] | None = None,
        action: str | None = None,
        source: str | None = None,
        status: str | None = None,
        severity: str | None = None,
        endpoint_type: str | None = None,
        channel: str | None = None,
        assigned_to: str | None = None,
        tag: str | None = None,
        remove_ignored_incidents: bool | None = None,
    ) -> dict:
        """
        Retrieve incidents based on the provided filters or by incident IDs.

        Args:
            incident_type (str): The type of incidents to retrieve. Valid values: INCIDENTS, DISCOVERY.
            ids (list[int] | None): Comma-separated list of incident IDs. Overrides all filters if provided.
            sort_by (str | None): Field to sort by. Valid value: INSERT_DATE.
            from_date (str | None): Start date for filtering incidents (dd/MM/yyyy HH:mm:ss).
            to_date (str | None): End date for filtering incidents (dd/MM/yyyy HH:mm:ss).
            detected_by (str | None): Agent that detected the incident.
            analyzed_by (str | None): Policy engine ID.
            event_id (str | None): Event ID number.
            destination (str | None): Destination associated with the incident.
            policies (list[str] | None): Policies that triggered the incidents.
            action (str | None): Action taken on the incident.
            source (str | None): Source associated with the incident.
            status (str | None): Status of the incident.
            severity (str | None): Severity level of the incident.
            endpoint_type (str | None): Endpoint type.
            channel (str | None): Channel associated with the incident.
            assigned_to (str | None): Administrator assigned to the incident.
            tag (str | None): Incident tag.
            remove_ignored_incidents (bool): Filter out ignored incidents (default is False).

        Returns:
            dict: API response with the retrieved incidents.
        """
        if ids:
            json_data = {"type": incident_type, "ids": ids}
        else:
            json_data = remove_empty_elements(
                {
                    "type": incident_type,
                    "sort_by": sort_by,
                    "from_date": from_date,
                    "to_date": to_date,
                    "detected_by": detected_by,
                    "analyzed_by": analyzed_by,
                    "event_id": event_id,
                    "destination": destination,
                    "policies": policies,
                    "action": action,
                    "source": source,
                    "status": status,
                    "severity": severity,
                    "endpoint_type": endpoint_type,
                    "channel": channel,
                    "assigned_to": assigned_to,
                    "tag": tag,
                    "remove_ignored_incidents": remove_ignored_incidents,
                }
            )

        return self._http_request(
            method="POST",
            url_suffix="incidents",
            json_data=json_data,
        )

    def update_rule(
        self,
        rule: dict,
    ) -> dict:
        return self._http_request(
            method="POST",
            url_suffix="policy/rules",
            json_data=rule,
            resp_type="response",
        )

    def update_rule_severity_action(
        self,
        severity_action_rule: dict,
    ) -> dict:
        return self._http_request(
            method="POST",
            url_suffix="policy/rules/severity-action",
            json_data=severity_action_rule,
            resp_type="response",
        )

    def update_rule_source_destination(
        self,
        source_destination_rule: dict,
    ) -> dict:
        return self._http_request(
            method="POST",
            url_suffix="policy/rules/source-destination",
            json_data=source_destination_rule,
            resp_type="response",
        )

    def update_incidents(
        self,
        event_ids: list[str],
        incident_type: str,
        action_type: str,
        value: str,
        comment: str | None = None,
        scan_partitions: str | None = None,
    ) -> dict:
        """
        Update incidents based on specified parameters.

        Args:
            type (str): The type of incidents to update (e.g., INCIDENTS, DISCOVERY).
            action_type (str): The type of action to perform (e.g., STATUS, SEVERITY, ASSIGN_TO, etc.).
            value (str): The value associated with the action type.
            comment (str | None): A comment to attach to the incidents (required for ADD_COMMENT).
            scan_partitions (str | None): Parameter to identify if partition_index is provided (e.g., ALL, NONE, LAST_ACTIVE).
            event_ids (list[str] | None): List of event IDs to update incidents.
            incident_keys (list[dict] | None): List of incident keys to update incidents.

        Returns:
            dict: Response from the update incidents API.
        """
        payload = remove_empty_elements(
            {
                "type": incident_type,
                "action_type": action_type,
                "value": value,
                "comment": comment,
                "scan_partitions": scan_partitions,
                "event_ids": event_ids,
            }
        )
        demisto.debug(f"update incident request with {payload=}")
        return self._http_request(
            method="POST",
            url_suffix="incidents/update",
            json_data=payload,
            resp_type="response",
        )

    def update_exception_rule(
        self,
        parent_policy_name: str,
        exception_rule: dict,
    ) -> dict:
        """
        Sends a request to create an exception rule in a specified policy and rule.

        Args:
            See arguments from the create_exception_rule_command.

        Returns:
            dict: Response from the server.
        """

        return self._http_request(
            method="POST",
            url_suffix="policy/rules/exceptions",
            params={"policyName": parent_policy_name},
            json_data=exception_rule,
            resp_type="response",
        )


""" HELPER FUNCTIONS """


""" COMMAND FUNCTIONS """


def get_events_command(
    client: Client, args: dict[str, Any]
) -> tuple[CommandResults, List[dict[str, Any]]]:
    limit: int = arg_to_number(args.get("limit")) or DEFAULT_MAX_FETCH
    since_time = arg_to_datetime(args.get("since_time"), settings=DATEPARSER_SETTINGS)
    assert isinstance(since_time, datetime)
    events, _, _ = fetch_events_command_sub(client, limit, datetime.utcnow(), since_time)

    result = CommandResults(
        readable_output=tableToMarkdown("Incidents", events),
        raw_response=events,
    )
    return result, events


def fetch_events_command_sub(
    client: Client,
    max_fetch: int,
    to_time: datetime,
    last_fetch_time: datetime,
    last_run_ids: list[int] | None = None,
) -> tuple[list[dict[str, Any]], list[int], str]:
    """
    Fetches Forcepoint DLP incidents as events to XSIAM.
    Note: each report of incident will be considered as an event.
    """
    from_time = last_fetch_time
    events = []
    last_run_ids = set(last_run_ids or set())
    new_last_run_ids: dict[str, set] = defaultdict(set)
    incidents_response = client.list_incidents(
        from_date=to_str_time(from_time), to_date=to_str_time(to_time)
    )
    incidents = incidents_response["incidents"]
    for incident in incidents:
        if incident["id"] not in last_run_ids:
            incident["_collector_source"] = "API"
            events.append(incident)
            new_last_run_ids[incident["event_time"]].add(incident["id"])
            if len(events) == max_fetch:
                break

    if not events and incidents:
        # Anti-starvation protection, we've exhausted all events for this second, but they're all duplicated.
        # This means that we've more events in the minimal epoch, that we're able to get in a single fetch,
        # and we'll ignore any additional events in this particular second.
        next_fetch_time: str = to_str_time(from_time + timedelta(seconds=1))
        demisto.info(
            f"Moving the fetch to the next second:{next_fetch_time}. Any additional events in this "
            f"second will be lost!"
        )
        return [], [], next_fetch_time

    # We've got events for this time span, so start from that to_time in the next fetch,
    # otherwise use the to_time - 1 second (as we might have more events for this second)
    next_fetch_time = (
        events[-1]["event_time"] if events else to_str_time(to_time - timedelta(seconds=1))
    )

    return events, list(new_last_run_ids[next_fetch_time]), next_fetch_time


def test_module(client: Client) -> str:
    """
    Test module.

    Args:
        client (Client): Forcepoint DLP client.
    Raises:
        DemistoException: In case of wrong request.

    Returns:
        str: Output message.
    """
    try:
        client.authenticate()
    except DemistoException as err:
        if err.res and err.res.status_code == HTTPStatus.FORBIDDEN:
            return "Authentication failed"
        return f"Error: {err}"
    except Exception as err:
        return f"Error: {err}"
    return "ok"


def fetch_events(client, first_fetch, max_fetch):
    events = []
    forward = demisto.getLastRun().get("forward") or {
        "last_fetch": to_str_time(datetime.utcnow() + timedelta(seconds=1)),
        "last_events_ids": [],
    }

    from_time = from_str_time(forward["last_fetch"])
    to_time = client.utc_now
    demisto.info(f"looking for backward events from:{from_time} to:{to_time}")
    forward_events, last_events_ids, next_fetch_time = fetch_events_command_sub(
        client, max_fetch, to_time, from_time, forward["last_events_ids"]
    )
    forward = {
        "last_fetch": next_fetch_time,
        "last_events_ids": last_events_ids,
    }
    events.extend(forward_events)

    send_events_to_xsiam(events, VENDOR, PRODUCT)  # noqa
    demisto.setLastRun(
        {
            "forward": forward,
        }
    )


def list_policy_command(client: Client, args: dict) -> CommandResults:
    """
    List the names of all enabled policies displayed in the 'Manage DLP and Discovery Policies' section.

    Args:
        client (Client): Forcepoint DLP client.
        args (dict): Command arguments.

    Returns:
        CommandResults: Outputs for XSOAR.
    """

    policy_type = args.get("type", "DLP")
    all_results = argToBoolean(args.get("all_results", False))
    limit = arg_to_number(args.get("limit")) or 50

    response = client.list_policies(policy_type=policy_type)
    results = get_paginated_data(
        response.get("enabled_policies", []),
        limit,
        all_results,
    )

    outputs = [{"name": policy} for policy in results]

    return CommandResults(
        outputs_prefix=f"{INTEGRATION_PREFIX}.Policy",
        outputs_key_field="name",
        outputs=outputs,
        readable_output=tableToMarkdown(
            name="Policies List:",
            t=outputs,
            headers=["name"],
            removeNull=True,
            headerTransform=string_to_table_header,
        ),
    )


def list_policy_rule_command(client: Client, args: dict) -> list[CommandResults]:
    """
    List the details of policy rules and classifiers, including condition properties.

    Args:
        client (Client): ForcePoint DLP client.
        args (dict): Command arguments.

    Returns:
        CommandResults: Command results to return to the war room.
    """
    policy_name = args["policy_name"]
    all_results = argToBoolean(args.get("all_results", False))
    limit = arg_to_number(args.get("limit")) or 50

    response = client.list_policy_rules(policy_name=policy_name)
    rules = get_paginated_data(
        response.get("rules", []),
        limit,
        all_results,
    )

    description = response.get("description")
    policy_level = dict_safe_get(response, ["policy_level", "level"])

    outputs = {
        "dlp_version": response.get("dlp_version"),
        "policy_name": response.get("policy_name"),
        "enabled": response.get("enabled"),
        "predefined_policy": response.get("predefined_policy"),
        "description": description,
        "policy_level": policy_level,
        "policy_level_data_type": dict_safe_get(response, ["policy_level", "data_type"]),
        "Rule": [
            {
                "rule_name": rule.get("rule_name"),
                "enabled": rule.get("enabled"),
                "parts_count_type": rule.get("parts_count_type"),
                "condition_relation_type": rule.get("condition_relation_type"),
                "Classifier": rule.get("classifiers", []),
            }
            for rule in rules
        ],
    }

    readable_output = tableToMarkdown(
        f"Policy `{policy_name}` Rule List:\nDescription: {description}\nPolicy level: {policy_level}\n",
        outputs.get("Rule", []),
        headers=[
            "rule_name",
            "enabled",
            "parts_count_type",
            "condition_relation_type",
        ],
        removeNull=True,
        headerTransform=string_to_table_header,
    )

    command_results = [
        CommandResults(
            readable_output=readable_output,
            outputs_prefix=f"{INTEGRATION_PREFIX}.Policy",
            outputs_key_field="policy_name",
            raw_response=response,
            outputs=outputs,
        )
    ]

    for rule in outputs.get("Rule", []):
        for clsf in rule.get("Classifier", []):
            rule_name = rule.get("rule_name")
            clsf_name = clsf.get("classifier_name")
            readable_output = tableToMarkdown(
                f"Rule `{rule_name}` Classifier `{clsf_name}`:",
                clsf,
                headers=CLASSIFIER_HEADERS,
                removeNull=True,
                headerTransform=string_to_table_header,
            )

            command_results.append(
                CommandResults(
                    readable_output=readable_output,
                )
            )
    return command_results


def list_exception_rule_command(client: Client, args: dict) -> CommandResults:
    """
    List all exception rules associated with policies, including detailed information about conditions and classifiers.

    Args:
        client (Client): ForcePoint DLP client.
        args (dict): Command arguments.

    Returns:
        CommandResults: Outputs for XSOAR.
    """
    policy_type = args.get("policy_type", "DLP")  # Defaults to "DLP" if not provided

    if policy_name := args.get("policy_name"):
        if not (rule_name := args.get("rule_name")):
            raise DemistoException(MISSING_RULE_NAME)

        response = client.get_exception_rule(
            policy_type=policy_type,
            policy_name=policy_name,
            rule_name=rule_name,
        )

        outputs: dict[str, Any] = transform_keys(
            response,
            {
                "classifier_details": "Classifier",
                "classifiers": "Classifier",
                "exception_rules": "RuleException",
            },
        )
        readable_output = tableToMarkdown(
            f"Policy `{policy_name}` \nRule: `{rule_name}` exceptions:",
            outputs.get("RuleException", []),
            headers=RULE_EXCEPTION_HEADERS,
            removeNull=True,
            headerTransform=string_to_table_header,
        )

    else:
        response = client.list_exception_rules(policy_type=policy_type)

        outputs = get_paginated_data(
            data=response.get("exception_rules", []),
            limit=arg_to_number(args.get("limit")) or DEFAULT_LIMIT,
            all_results=argToBoolean(args.get("all_results", False)),
        )

        readable_output = tableToMarkdown(
            name="Exception Rules List:",
            t=outputs,
            headers=["policy_name", "rule_name", "exception_rule_names"],
            removeNull=True,
            headerTransform=string_to_table_header,
        )

    return CommandResults(
        outputs_prefix=f"{INTEGRATION_PREFIX}.PolicyException",
        outputs_key_field="policy_name",
        outputs=outputs,
        readable_output=readable_output,
        raw_response=response,
    )


def get_rule_severity_action_command(client: Client, args: dict) -> list[CommandResults]:
    """
    Retrieve details of rule severity and corresponding action properties for a specified policy.

    Args:
        client (Client): ForcePoint DLP client.
        args (dict): Command arguments.

    Returns:
        CommandResults: Command results to return to the war room.
    """
    policy_name = args["policy_name"]

    response = client.get_rule_severity_action(policy_name=policy_name)
    outputs: dict[str, Any] = transform_keys(
        response,
        {
            "classifier_details": "ClassifierDetail",
            "rules": "Rule",
        },
    )

    command_results = []

    for rule in outputs.get("Rule", []):
        rule_name = rule.get("rule_name")
        max_matches = rule.get("max_matches")
        readable_output = tableToMarkdown(
            f"Policy `{policy_name}` Rule `{rule_name}` Severity and Actions:\nMax matches: {max_matches}",
            rule.get("ClassifierDetail", []),
            headers=[
                "number_of_matches",
                "selected",
                "action_plan",
            ],
            removeNull=True,
            headerTransform=string_to_table_header,
        )
        command_results.append(
            CommandResults(
                outputs=outputs,
                outputs_prefix=f"{INTEGRATION_PREFIX}.SeverityActionRule",
                outputs_key_field="policy_name",
                readable_output=readable_output,
                raw_response=response,
            )
        )

    return command_results


def get_rule_source_destination_command(client: Client, args: dict) -> CommandResults:
    """
    Retrieve the source and destination details of rules associated with a specified policy.

    Args:
        client (Client): ForcePoint DLP client.
        args (dict): Command arguments.

    Returns:
        CommandResults: Command results to return to the war room.
    """
    policy_name = args["policy_name"]

    # Call the API
    response = client.get_rule_source_destination(policy_name=policy_name)

    outputs: dict[str, Any] = transform_keys(
        response,
        {
            "rules": "Rule",
            "rule_source": "Source",
            "rule_destination": "Destination",
            "channels": "Channel",
        },
    )
    hr = [
        rule
        | {
            "source_endpoint_channel_machine_type": dict_safe_get(
                rule, ["Source", "endpoint_channel_machine_type"]
            ),
            "source_endpoint_connection_type": dict_safe_get(
                rule, ["Source", "endpoint_connection_type"]
            ),
            "destination_email_monitor_directions": dict_safe_get(
                rule, ["Destination", "email_monitor_directions"]
            ),
        }
        for rule in outputs.get("Rule", []) or []
    ]

    return CommandResults(
        outputs=outputs,
        outputs_prefix=f"{INTEGRATION_PREFIX}.SourceDestinationRule",
        outputs_key_field="policy_name",
        readable_output=tableToMarkdown(
            f"Policy `{policy_name}` Source and Destination Rules Details:",
            hr,
            headers=[
                "rule_name",
                "source_endpoint_channel_machine_type",
                "source_endpoint_connection_type",
                "destination_email_monitor_directions",
            ],
            removeNull=True,
            headerTransform=string_to_table_header,
        ),
        raw_response=response,
    )


def list_incidents_command(client: Client, args: dict) -> CommandResults:
    """
    Retrieve a list of incidents based on specified filters.

    Args:
        client (Client): The ForcePoint DLP client instance.
        args (dict): Command arguments.

    Returns:
        CommandResults: Results to return to the war room.
    """
    incident_type = args.get("type", "INCIDENTS")  # Default to INCIDENTS

    from_date = arg_to_datetime(args["from_date"])
    to_date = arg_to_datetime(args["to_date"])

    if from_date is None or to_date is None:
        raise DemistoException("Please provide correct dates")

    status = args.get("status")
    ids = argToList(args.get("ids"))

    incidents_response = client.list_incidents(
        incident_type=incident_type,
        ids=ids,
        from_date=from_date.strftime(DATE_FORMAT),
        to_date=to_date.strftime(DATE_FORMAT),
        status=status,
    )

    incidents = incidents_response.get("incidents", [])
    incidents = get_paginated_data(
        incidents,
        arg_to_number(args.get("limit")) or 50,
        argToBoolean(args.get("all_results", False)),
    )
    outputs = transform_keys(incidents, {"history": "history"})
    return CommandResults(
        outputs_prefix=f"{INTEGRATION_PREFIX}.Incident",
        outputs_key_field="id",
        outputs=outputs,
        readable_output=tableToMarkdown(
            name="Incidents List:",
            t=incidents,
            headers=INCIDENT_HEADERS,
            removeNull=True,
            headerTransform=string_to_table_header,
        ),
    )


def create_rule_command(client: Client, args: dict) -> CommandResults:
    """
    Create a new rule in a specified DLP policy with a single classifier.
    If the specified policy does not exist, it will be created automatically.

    Args:
        client (Client): ForcePoint DLP client.
        args (dict): Command arguments.

    Returns:
        CommandResults: Command results to return to the war room.
    """
    policy_name = args["policy_name"]
    payload = None

    if entry_id := args.get("entry_id"):
        payload = read_entry_id(entry_id=entry_id)

    policy = None
    rule_name = args["rule_name"]
    if policy_name in client.list_policies().get("enabled_policies", []):
        policy = client.list_policy_rules(policy_name=policy_name)
        if find_rule(
            policy,
            rule_name,
        ):
            raise DemistoException("The rule is already exist. Use the update command.")

    client.update_rule(
        rule=build_rule_payload(
            dlp_version=args.get("dlp_version"),
            policy_name=policy_name,
            policy_enabled=args.get("policy_enabled"),
            predefined_policy=args.get("predefined_policy"),
            rule_name=rule_name,
            rule_enabled=args.get("rule_enabled"),
            parts_count_type=args.get("rule_parts_count_type"),
            condition_relation_type=args.get("rule_condition_relation_type"),
            classifier_name=args.get("classifier_name"),
            classifier_predefined=args.get("classifier_predefined"),
            classifier_position=arg_to_number(args.get("classifier_position")),
            threshold_type=args.get("classifier_threshold_type"),
            threshold_value_from=arg_to_number(args.get("classifier_threshold_value_from")),
            threshold_value_to=arg_to_number(args.get("classifier_threshold_value_to")),
            threshold_calculate_type=args.get("classifier_threshold_calculate_type"),
            description=args.get("policy_description", ""),
            policy_level=arg_to_number(args.get("policy_level")),
            policy_level_data_type=args.get("policy_data_type"),
            policy=policy,
            payload=payload,
        )
    )

    return CommandResults(
        readable_output=f"Rule `{rule_name}` was successfully created in policy '{policy_name}'.",
    )


def update_rule_command(client: Client, args: dict) -> CommandResults:
    """
    Update an existing rule in a specific DLP policy or create a classifier within it.

    Args:
        client (Client): ForcePoint DLP client.
        args (dict): Command arguments.

    Returns:
        CommandResults: Command results to return to the war room.
    """
    policy_name = args["policy_name"]
    payload = None
    if entry_id := args.get("entry_id"):
        payload = read_entry_id(entry_id=entry_id)

    rule_name = args["rule_name"]

    if policy_name not in client.list_policies().get("enabled_policies", []):
        raise DemistoException("The policy does not exist. Use the create command.")

    policy = client.list_policy_rules(policy_name=policy_name)

    if not (
        find_rule(
            policy,
            rule_name,
        )
    ):
        raise DemistoException("The rule does not exist. Use the create command.")

    client.update_rule(
        rule=remove_empty_elements(
            build_rule_payload(
                dlp_version=args.get("dlp_version"),
                policy_name=policy_name,
                policy_enabled=args.get("policy_enabled"),
                predefined_policy=args.get("predefined_policy"),
                rule_name=rule_name,
                rule_enabled=args.get("rule_enabled"),
                parts_count_type=args.get("rule_parts_count_type"),
                condition_relation_type=args.get("rule_condition_relation_type"),
                classifier_name=args.get("classifier_name"),
                classifier_predefined=args.get("classifier_predefined"),
                classifier_position=arg_to_number(args.get("classifier_position")),
                threshold_type=args.get("classifier_threshold_type"),
                threshold_value_from=arg_to_number(args.get("classifier_threshold_value_from")),
                threshold_value_to=arg_to_number(args.get("classifier_threshold_value_to")),
                threshold_calculate_type=args.get("classifier_threshold_calculate_type"),
                description=args.get("policy_description", ""),
                policy_level=arg_to_number(args.get("policy_level")),
                policy_level_data_type=args.get("policy_data_type"),
                payload=payload,
                policy=policy,
            )
        )
    )

    return CommandResults(
        readable_output=f"Rule `{rule_name}` was successfully updated in policy '{policy_name}'.",
    )


def update_rule_severity_action_command(client: Client, args: dict) -> CommandResults:
    """
    Update the severity actions for a rule in a specific DLP policy.

    Args:
        client (Client): ForcePoint DLP client.
        args (dict): Command arguments.

    Returns:
        CommandResults: Command results to return to the war room.
    """
    payload = None
    if entry_id := args.get("entry_id"):
        payload = read_entry_id(entry_id=entry_id)

    policy_name = args["policy_name"]
    rule_name = args["rule_name"]
    classifier_number_of_matches = args.get("classifier_number_of_matches")
    override_classifier_number_of_matches = arg_to_number(
        args.get("override_classifier_number_of_matches")
    )

    policy = client.get_rule_severity_action(policy_name=policy_name)
    rule = find_rule(
        policy=policy,
        rule_name=rule_name,
    )

    if not rule:
        raise DemistoException("The rule not found.")

    client.update_rule_severity_action(
        severity_action_rule=remove_empty_elements(
            build_severity_action_payload(
                rule_name=rule_name,
                rule_type=args.get("rule_type"),
                rule_count_type=args.get("rule_count_type"),
                rule_count_period=args.get("rule_count_period"),
                rule_rate_match_period=args.get("rule_rate_match_period"),
                rule_max_matches=args.get("rule_max_matches"),
                classifier_selected=args.get("classifier_selected"),
                classifier_number_of_matches=classifier_number_of_matches,
                override_classifier_number_of_matches=override_classifier_number_of_matches,
                classifier_severity_type=args.get("classifier_severity_type"),
                classifier_action_plan=args.get("classifier_action_plan"),
                policy=policy,
                payload=payload,
            )
        )
    )

    return CommandResults(
        readable_output=f"Severity actions for Rule `{rule_name}` in policy '{policy_name}' was successfully updated.",
    )


def update_rule_source_destination_command(client: Client, args: dict) -> CommandResults:
    """
    Update the source and destination settings for a rule in a specific DLP policy.

    Args:
        client (Client): ForcePoint DLP client.
        args (dict): Command arguments.

    Returns:
        CommandResults: Command results to return to the war room.
    """
    payload = None

    if entry_id := args.get("entry_id"):
        payload = read_entry_id(entry_id=entry_id)

    policy_name = args["policy_name"]
    rule_name = args["rule_name"]

    policy = client.get_rule_source_destination(policy_name=policy_name)

    if not find_rule(
        policy=policy,
        rule_name=rule_name,
    ):
        raise DemistoException("The rule not found.")

    client.update_rule_source_destination(
        source_destination_rule=build_source_destination_payload(
            rule_name=rule_name,
            endpoint_channel_machine_type=args.get("rule_source_endpoint_channel_machine_type"),
            endpoint_connection_type=args.get("rule_source_endpoint_connection_type"),
            email_monitor_directions=argToList(
                args.get("rule_destination_email_monitor_directions")
            ),
            channel_type=args.get("channel_type"),
            channel_enabled=args.get("channel_enabled"),
            resource_name=args.get("resource_name"),
            resource_type=args.get("resource_type"),
            resource_include=args.get("resource_include"),
            policy=policy,
            payload=payload,
        )
    )

    return CommandResults(
        readable_output=f"Source and destination for Rule `{rule_name}` in policy '{policy_name}' was successfully updated.",
    )


def create_exception_rule_command(client: Client, args: dict) -> CommandResults:
    """
    Create an exception rule for a specified parent rule and policy type.

    Args:
        client (Client): ForcePoint DLP client.
        args (dict): Command arguments.

    Returns:
        CommandResults: Command results to return to the war room.
    """
    # Extract entry ID if provided
    payload = None
    if entry_id := args.get("entry_id"):
        payload = read_entry_id(entry_id=entry_id)

    parent_policy_name = args["parent_policy_name"]
    parent_rule_name = args["parent_rule_name"]
    policy_type = args["policy_type"]
    exception_rule_name = args["exception_rule_name"]
    exception_rules_policy = client.get_exception_rule(
        policy_type,
        parent_policy_name,
        parent_rule_name,
    )

    if parent_policy_name in client.list_policies().get("enabled_policies", []):
        if find_exception_rule(
            exception_rules_policy.get("exception_rules", []),
            exception_rule_name,
        ):
            raise DemistoException("The exception rule is already exist. Use the update command.")

    # Request to create the exception rule
    client.update_exception_rule(
        parent_policy_name=parent_policy_name,
        exception_rule=remove_empty_elements(
            build_exception_rule_payload(
                parent_policy_name=parent_policy_name,
                parent_rule_name=parent_rule_name,
                policy_type=policy_type,
                exception_rule_name=exception_rule_name,
                enabled=args.get("enabled"),
                description=args.get("description"),
                parts_count_type=args.get("parts_count_type"),
                condition_relation_type=args.get("condition_relation_type"),
                condition_enabled=args.get("condition_enabled"),
                source_enabled=args.get("source_enabled"),
                destination_enabled=args.get("destination_enabled"),
                classifier_name=args.get("classifier_name"),
                classifier_predefined=args.get("classifier_predefined"),
                classifier_position=arg_to_number(args.get("classifier_position")),
                classifier_threshold_type=args.get("classifier_threshold_type"),
                classifier_threshold_value_from=arg_to_number(
                    args.get("classifier_threshold_value_from")
                ),
                classifier_threshold_value_to=arg_to_number(
                    args.get("classifier_threshold_value_to")
                ),
                classifier_threshold_calculate_type=args.get("classifier_threshold_calculate_type"),
                severity_classifier_max_matches=args.get("severity_classifier_max_matches"),
                severity_classifier_selected=args.get("severity_classifier_selected"),
                severity_classifier_number_of_matches=arg_to_number(
                    args.get("severity_classifier_number_of_matches")
                ),
                override_severity_classifier_number_of_matches=arg_to_number(
                    args.get("override_severity_classifier_number_of_matches")
                ),
                severity_classifier_severity_type=args.get("severity_classifier_severity_type"),
                severity_classifier_action_plan=args.get("severity_classifier_action_plan"),
                exception_policy=exception_rules_policy,
                payload=payload,
            )
        ),
    )

    return CommandResults(
        readable_output=f"Exception rule '{exception_rule_name}' was successfully created in rule "
        f"'{parent_rule_name}' under policy '{parent_policy_name}'.",
    )


def update_exception_rule_command(client: Client, args: dict) -> CommandResults:
    """
    Update an existing exception rule for a specified parent rule and policy type.

    Args:
        client (Client): ForcePoint DLP client.
        args (dict): Command arguments.

    Returns:
        CommandResults: Command results to return to the war room.
    """
    payload = None
    if entry_id := args.get("entry_id"):
        payload = read_entry_id(entry_id=entry_id)

    parent_policy_name = args["parent_policy_name"]
    parent_rule_name = args["parent_rule_name"]
    policy_type = args["policy_type"]
    exception_rule_name = args["exception_rule_name"]
    exception_rules_policy = client.get_exception_rule(
        policy_type,
        parent_policy_name,
        parent_rule_name,
    )
    if parent_policy_name in client.list_policies().get("enabled_policies", []):
        if (
            find_exception_rule(
                exception_rules_policy.get("exception_rules", []),
                exception_rule_name,
            )
            is None
        ):
            raise DemistoException("The exception rule is not exist. Use the create command.")
    # Request to create the exception rule
    client.update_exception_rule(
        parent_policy_name=parent_policy_name,
        exception_rule=remove_empty_elements(
            build_exception_rule_payload(
                parent_policy_name=parent_policy_name,
                parent_rule_name=parent_rule_name,
                policy_type=policy_type,
                exception_rule_name=exception_rule_name,
                enabled=args.get("enabled"),
                description=args.get("description"),
                parts_count_type=args.get("parts_count_type"),
                condition_relation_type=args.get("condition_relation_type"),
                condition_enabled=args.get("condition_enabled"),
                source_enabled=args.get("source_enabled"),
                destination_enabled=args.get("destination_enabled"),
                classifier_name=args.get("classifier_name"),
                classifier_predefined=args.get("classifier_predefined"),
                classifier_position=arg_to_number(args.get("classifier_position")),
                classifier_threshold_type=args.get("classifier_threshold_type"),
                classifier_threshold_value_from=arg_to_number(
                    args.get("classifier_threshold_value_from")
                ),
                classifier_threshold_value_to=arg_to_number(
                    args.get("classifier_threshold_value_to")
                ),
                classifier_threshold_calculate_type=args.get("classifier_threshold_calculate_type"),
                severity_classifier_max_matches=args.get("severity_classifier_max_matches"),
                severity_classifier_selected=args.get("severity_classifier_selected"),
                severity_classifier_number_of_matches=arg_to_number(
                    args.get("severity_classifier_number_of_matches")
                ),
                override_severity_classifier_number_of_matches=arg_to_number(
                    args.get("override_severity_classifier_number_of_matches")
                ),
                severity_classifier_severity_type=args.get("severity_classifier_severity_type"),
                severity_classifier_action_plan=args.get("severity_classifier_action_plan"),
                exception_policy=exception_rules_policy,
                payload=payload,
            )
        ),
    )

    return CommandResults(
        readable_output=f"Exception rule '{exception_rule_name}' was successfully updated in rule "
        f"'{parent_rule_name}' under policy '{parent_policy_name}'.",
    )


def update_incident_command(client: Client, args: dict) -> CommandResults:
    """
    Update an incident's attributes such as status, severity, assignment, comments, tags, release flag,
    or false positive indication.

    Args:
        client (Client): ForcePoint DLP client.
        args (dict): Command arguments.

    Returns:
        CommandResults: Command results to return to the war room.
    """
    ids = argToList(args.get("event_ids"))
    incident_type = args["type"]
    comment = args.get("comment")

    for arg_key, action_type in INCIDENT_UPDATE_MAPPER:
        value = args.get(arg_key)
        if arg_key == "false_positive" and value:
            value = 1 if argToBoolean(value) else 0

        if value:
            client.update_incidents(
                event_ids=ids,
                incident_type=incident_type,
                action_type=action_type,
                value=value,
                comment=comment,
            )

    return CommandResults(
        readable_output="Incidents was successfully updated.",
    )


def fetch_incidents(
    client: Client, first_fetch: datetime, max_fetch: int, mirror_direction: str | None
) -> tuple[list[dict], dict[str, Any]]:
    """
    Fetch Forcepoint DLP incidents.
    The incident endpoint doesn't supports pagination we manage it in the code.
    The incident endpoint has sort body parameter that now works, we sort the response in the code.
    The incident endpoint doesn't supports offset, we use the start time and when needed, add 1 second.

    Args:
        client (Client): ForcePoint DLP client.
        params (dict): Instance parameters.

    Returns:
        tuple[list[dict], dict[str, Any]]: Incidents and the next fetch metadata.
    """

    last_run = arg_to_datetime(demisto.getLastRun().get("time"))
    last_run_id = arg_to_number(demisto.getLastRun().get("last_run_id"))

    demisto.debug(f"fetch: {last_run=} {last_run_id=}")

    start_date = last_run or first_fetch
    start_time = start_date.strftime(DATE_FORMAT)
    end_time = get_end_time()

    demisto.debug(f"fetch: start time: {start_time} end time: {end_time}.")

    response = client.list_incidents(
        incident_type="INCIDENTS",
        sort_by="INSERT_DATE",
        from_date=start_time,
        to_date=end_time,
    )

    incidents = response.get("incidents", []) or []
    incidents.sort(key=lambda i: datetime.strptime(i["incident_time"], DATE_FORMAT))

    # Update the first incident time if not exists.
    integration_context = get_integration_context()
    if incidents and not integration_context.get("first_incident_time"):
        integration_context.update({"first_incident_time": incidents[0]["incident_time"]})
        set_integration_context(integration_context)

    if last_run_id:
        new_incidents = [incident for incident in incidents if incident["id"] > last_run_id]
        if not new_incidents:
            demisto.debug("fetch: not found new incidents.")
            if any(incident["id"] == last_run_id for incident in incidents):
                demisto.debug(
                    f"fetch: {last_run_id} exists in the response, add 1 second and request again."
                )
                start_date = start_date + timedelta(seconds=1)
                response = client.list_incidents(
                    incident_type="INCIDENTS",
                    sort_by="INSERT_DATE",
                    from_date=start_date.strftime(DATE_FORMAT),
                    to_date=end_time,
                )
                incidents = response.get("incidents", [])
        else:
            demisto.debug(f"fetch: found: {len(new_incidents)} after {last_run_id}.")
            incidents = new_incidents

    incidents = incidents[:max_fetch]

    new_last_run = start_date
    # Get the last incident time
    if incidents and incidents[-1].get("incident_time"):
        new_last_run = arg_to_datetime(incidents[-1]["incident_time"]) or start_date

    outputs = []
    for incident in incidents:
        incident_time = arg_to_datetime(incident["incident_time"])

        if incident_time:
            event_id = incident["event_id"]
            incident_id = incident["id"]
            id = f"{event_id}-{incident_id}"
            incident["mirror_direction"] = mirror_direction
            incident["mirror_instance"] = demisto.integrationInstance()
            outputs.append(
                {
                    "name": f"Forcepoint DLP Incident - {incident_id}",
                    "occurred": incident_time.strftime(XSOAR_DATE_FORMAT),
                    "rawJSON": json.dumps(incident),
                    "severity": FP_XSOAR_SEVERITY_MAPPER.get(incident.get("severity", "LOW")),
                    "dbotMirrorId": str(id),
                    "mirror_direction": mirror_direction,
                    "mirror_instance": demisto.integrationInstance(),
                }
            )

    return outputs, {
        "time": new_last_run.strftime(DATE_FORMAT),
        "last_run_id": incidents[-1]["id"] if incidents else last_run_id,
    }


def get_mapping_fields_command() -> GetMappingFieldsResponse:
    """
    Pulls the remote schema for the different incident types, and their associated incident fields, from the remote system.

    Returns:
        GetMappingFieldsResponse: Dictionary with keys as field names.
    """
    demisto.debug("Get Forcepoint DLP mapping fields")
    mapping_response = GetMappingFieldsResponse()

    incident_type_scheme = SchemeTypeMapping(type_name="Forcepoint Incident")
    for mirror_field in MIRRORING_FIELDS:
        incident_type_scheme.add_field(name=mirror_field)

    mapping_response.add_scheme_type(incident_type_scheme)

    return mapping_response


def update_remote_system(
    client: Client,
    args: dict[str, Any],
) -> str:
    """
    This command pushes local changes to the remote system.
    Args:
        client: XSOAR Client to use.
        args:
            args['data']: the data to send to the remote system.
            args['entries']: the entries to send to the remote system.
            args['incident_changed']: boolean telling us if the local incident indeed changed or not.
            args['remote_incident_id']: the remote incident id.
    Returns: The remote incident id - ticket_id
    """
    demisto.debug("update_remote_system")
    parsed_args = UpdateRemoteSystemArgs(args)

    incident_id = parsed_args.remote_incident_id

    demisto.debug(
        f"Got the following delta keys {str(list(parsed_args.delta))}"
        if parsed_args.delta
        else "There is no delta fields in Forcepoint DLP"
    )

    if parsed_args.incident_changed:
        demisto.debug(f"Incident changed: {parsed_args.incident_changed}, {parsed_args.delta=}")

        update_args = parsed_args.delta
        updated_arguments = {}

        for changed_key, changed_value in update_args.items():
            if isinstance(changed_value, bool):
                changed_value = str(1 if changed_value else 0)

            if changed_key == "severity":
                changed_value = XSOAR_FP_SEVERITY_MAPPER.get(changed_value, 1)

            demisto.debug(f"{changed_key=}")
            if changed_key in MIRRORING_FIELDS:
                updated_arguments[changed_key] = changed_value
                client.update_incidents(
                    event_ids=[incident_id.split("-")[0]],
                    incident_type="INCIDENTS",
                    action_type=changed_key.upper(),
                    value=(
                        changed_value.upper() if isinstance(changed_value, str) else changed_value
                    ),
                )
                demisto.debug(
                    f"Updating [{changed_key}] -> {changed_value} to incident {incident_id} Forcepoint DLP.\
                          {updated_arguments=}|| {update_args=}"
                )
            elif changed_key == "closingUserId":
                demisto.debug("closing incident")
                client.update_incidents(
                    event_ids=[incident_id.split("-")[0]],
                    incident_type="INCIDENTS",
                    action_type="STATUS",
                    value="CLOSE",
                )
                demisto.debug(
                    f"Updating [STATUS] -> CLOSE to incident {incident_id} Forcepoint DLP.\
                          {updated_arguments=}|| {update_args=}"
                )

    demisto.info(f"Remote data of {incident_id}: {parsed_args.data}")

    return incident_id


def get_remote_data_command(
    client: Client,
    args: dict[str, Any],
) -> GetRemoteDataResponse:
    """
    Gets new information about the incidents in the remote system
    and updates existing incidents in Cortex XSOAR.
    Args:
        client: Forcepoint DLP API client.
        args (Dict[str, Any]): command arguments.
    Returns:
        GetRemoteDataResponse: first entry is the incident (which can be completely empty) and the new entries.
    """
    parsed_args = GetRemoteDataArgs(args)

    incident_id = parsed_args.remote_incident_id.split("-")[1]

    last_update = parsed_args.last_update

    demisto.debug(f"Check {incident_id} update from {last_update}")

    response = client.list_incidents(
        ids=[incident_id],
    )
    incidents = response.get("incidents", [])
    entries = []

    if not incidents:
        return GetRemoteDataResponse({}, [])

    mirrored_ticket: dict[str, Any] = incidents[0]
    ticket_last_update = mirrored_ticket.get("incident_time")

    demisto.debug(f"Incident {incident_id} - {ticket_last_update=} {last_update=}")

    if mirrored_ticket.get("status") == "Closed":
        entries.append(
            {
                "Type": EntryType.NOTE,
                "Contents": {
                    "dbotIncidentClose": True,
                    "closeReason": "Closed from Forcepoint DLP.",
                },
                "ContentsFormat": EntryFormat.JSON,
            }
        )

    return GetRemoteDataResponse(mirrored_ticket, entries)


def get_modified_remote_data_command(
    client: Client,
    args: dict[str, Any],
):
    """
    Queries for incidents that were modified since the last update.

    Args:
        client: Forcepoint DLP client.
        args (Dict[str, Any]): command arguments.

    Returns:
        GetModifiedRemoteDataResponse: modified tickets from Cyberint.
    """
    remote_args = GetModifiedRemoteDataArgs(args)
    last_update_time = arg_to_datetime(remote_args.last_update)
    modified_incident_ids = []

    integration_context = get_integration_context()
    first_incident_time = integration_context.get("first_incident_time")
    from_date = first_incident_time

    demisto.debug(f"get_modified_remote_data_command: {last_update_time=}.")
    demisto.debug(f"get_modified_remote_data_command: {first_incident_time=}.")

    if not from_date:
        demisto.debug("get_modified_remote_data_command: first incident time not found")
        return GetModifiedRemoteDataResponse([])

    end_time = get_end_time()
    demisto.debug(
        f"get_modified_remote_data_command: start time: {from_date} end time: {end_time}."
    )

    response = client.list_incidents(
        incident_type="INCIDENTS",
        sort_by="INSERT_DATE",
        from_date=from_date,
        to_date=end_time,
    )

    incidents = response.get("incidents", [])

    demisto.debug(
        f"get_modified_remote_data_command: got: {len(incidents)} incidents,\
              start to filter for the updated after {last_update_time}."
    )

    for incident in incidents:
        history = incident.get("history", [])
        if history:
            update_time = arg_to_datetime(history[0]["update_time"])
            demisto.debug(
                f"get_modified_remote_data_command: got: {update_time=} > {last_update_time=}."
            )
            if update_time and last_update_time:
                update_time = update_time.replace(tzinfo=None)
                last_update_time = last_update_time.replace(tzinfo=None)

            if (update_time and last_update_time and update_time > last_update_time) or (
                not last_update_time
            ):
                event_id = incident["event_id"]
                incident_id = incident["id"]
                modified_incident_ids.append(f"{event_id}-{incident_id}")

    demisto.debug(
        f"get_modified_remote_data_command: got: {len(modified_incident_ids)} updated incidents."
    )

    return GetModifiedRemoteDataResponse(modified_incident_ids)


def get_end_time():
    return datetime.now().strftime(DATE_FORMAT)


# HELPERS #


def from_dict(cls: Any, data: Any) -> Any:
    """
    Recursively converts a dictionary or list of dictionaries into an instance of the given dataclass.

    Args:
        cls (Type[Any]): The target dataclass type to instantiate.
        data (Any): The input data, which can be a dictionary, a list of dictionaries, or a primitive type.

    Returns:
        Any: An instance of the specified dataclass or a list of instances if the input is a list.

    """
    if isinstance(data, list):
        return [from_dict(cls.__args__[0], item) for item in data]  # Convert list items recursively
    elif isinstance(data, dict):
        field_types = {
            f.name: f.type for f in cls.__dataclass_fields__.values()
        }  # Get expected field types
        return cls(
            **{
                key: from_dict(field_types[key], value)
                for key, value in data.items()
                if key in field_types
            }
        )
    else:
        return data


def get_paginated_data(data: list, limit: int, all_results: bool):
    return data if all_results else data[:limit]


def transform_keys(data: dict | list, key_map: dict[str, str] = {}) -> dict | list:
    if isinstance(data, list):
        return [transform_keys(item, key_map) for item in data]

    if isinstance(data, dict):
        return {
            key_map.get(
                key,
                (
                    camelize_string(key)
                    if isinstance(value, dict)
                    or (value and isinstance(value, list) and isinstance(value[0], dict))
                    else key
                ),
            ): (transform_keys(value, key_map) if isinstance(value, (dict, list)) else value)
            for key, value in data.items()
        }

    return data


def read_entry_id(entry_id: str) -> dict[str, Any]:
    file_data = demisto.getFilePath(entry_id)
    with open(file_data["path"], "rb") as f:
        args = json.load(f)
    return args


def find_rule(policy: dict, rule_name: str) -> dict[str, Any] | None:
    """Find a rule by its name in the policy."""
    return next(
        (rule for rule in policy.get("rules", []) if rule.get("rule_name") == rule_name), None
    )


def find_exception_rule(exception_rules: list[dict[str, Any]], name: str) -> dict[str, Any] | None:
    """Find a rule by its name in the policy."""
    return next((rule for rule in exception_rules if rule.get("exception_rule_name") == name), None)


def update_classifier(rule: dict, position: int | None, classifier_updates: dict):
    """Update an existing classifier or add a new one."""
    for clsf in rule.get("classifiers", []):
        if clsf.get("position") == position:
            clsf.update(remove_empty_elements(classifier_updates))
            return
    classifier_updates = remove_empty_elements(classifier_updates)
    if classifier_updates:
        rule.get("classifiers", []).append(classifier_updates)


def update_severity_classifier_details(
    rule: dict,
    details: dict,
    classifiers_key: str = "severity_classifier_details",
    id: int | None = None,
) -> None:
    """
    Update or add severity classifier details in a rule.

    Args:
        rule (dict): The rule object containing `severity_classifier_details`.
        details (dict): The new details to update or add.

    Example details:
        {
            "max_matches": "GREATEST_NUMBER",
            "selected": "true",
            "number_of_matches": 5,
            "severity_type": "HIGH",
            "action_plan": "Block"
        }
    """
    if not rule.get(classifiers_key):
        rule[classifiers_key] = []

    classifiers = rule[classifiers_key]
    # Update an existing classifier if it matches the `number_of_matches`
    for classifier in classifiers:
        if arg_to_number(classifier.get("number_of_matches")) == id:
            classifier.update(remove_empty_elements(details))
            return
    if id:
        raise DemistoException(f"{id} does not exists in the classifiers `number_of_matches`")

    # If no existing classifier matches, add a new one
    if details:
        classifiers.append(details)

    classifiers.sort(
        key=lambda x: (x.get("number_of_matches") is None, x.get("number_of_matches", 0)),
        reverse=True,
    )


def build_rule_payload(
    dlp_version: str | None,
    policy_name: str | None,
    policy_enabled: str | None,
    predefined_policy: str | None,
    rule_name: str,
    rule_enabled: str | None,
    parts_count_type: str | None,
    condition_relation_type: str | None,
    classifier_name: str | None,
    classifier_predefined: str | None,
    classifier_position: int | None,
    threshold_type: str | None,
    threshold_value_from: int | None,
    threshold_value_to: int | None,
    threshold_calculate_type: str | None,
    description: str | None,
    policy_level: int | None,
    policy_level_data_type: str | None,
    policy: dict[str, Any] | None = None,
    payload: dict | None = None,
) -> dict:
    # update case
    if not payload and policy:
        policy.update(
            remove_empty_elements(
                {
                    "dlp_version": dlp_version,
                    "policy_name": policy_name,
                    "enabled": policy_enabled,
                    "predefined_policy": predefined_policy,
                    "description": description,
                }
            )
        )
        policy["policy_level"].update(
            remove_empty_elements(
                {
                    "level": policy_level,
                    "data_type": policy_level_data_type,
                }
            )
        )
        rule = find_rule(policy, rule_name)
        if not rule:
            rules: list = policy.get("rules", [])
            rules.append(
                {
                    "rule_name": rule_name,
                    "enabled": rule_enabled,
                    "parts_count_type": parts_count_type,
                    "condition_relation_type": condition_relation_type,
                    "classifiers": [
                        {
                            "classifier_name": classifier_name,
                            "predefined": classifier_predefined,
                            "position": classifier_position,
                            "threshold_type": threshold_type,
                            "threshold_value_from": threshold_value_from,
                            "threshold_value_to": threshold_value_to,
                            "threshold_calculate_type": threshold_calculate_type,
                        }
                    ],
                }
            )
        else:
            rule.update(
                remove_empty_elements(
                    {
                        "enabled": rule_enabled,
                        "parts_count_type": parts_count_type,
                        "condition_relation_type": condition_relation_type,
                    }
                )
            )
            update_classifier(
                rule,
                classifier_position,
                {
                    "classifier_name": classifier_name,
                    "predefined": classifier_predefined,
                    "position": classifier_position,
                    "threshold_type": threshold_type,
                    "threshold_value_from": threshold_value_from,
                    "threshold_value_to": threshold_value_to,
                    "threshold_calculate_type": threshold_calculate_type,
                },
            )
    else:
        # create case
        policy = (
            {
                "dlp_version": dlp_version,
                "policy_name": policy_name,
                "enabled": policy_enabled,
                "predefined_policy": predefined_policy,
                "description": description,
                "policy_level": {
                    "level": policy_level,
                    "data_type": policy_level_data_type,
                },
                "rules": [
                    {
                        "rule_name": rule_name,
                        "enabled": rule_enabled,
                        "parts_count_type": parts_count_type,
                        "condition_relation_type": condition_relation_type,
                        "classifiers": [
                            {
                                "classifier_name": classifier_name,
                                "predefined": classifier_predefined,
                                "position": classifier_position,
                                "threshold_type": threshold_type,
                                "threshold_value_from": threshold_value_from,
                                "threshold_value_to": threshold_value_to,
                                "threshold_calculate_type": threshold_calculate_type,
                            }
                        ],
                    }
                ],
            }
            if not payload
            else payload
        )
    from_dict(PolicyRule, policy)
    return remove_empty_elements(policy)


def build_severity_action_payload(
    rule_name: str,
    rule_type: str | None,
    rule_count_type: str | None,
    rule_count_period: str | None,
    rule_rate_match_period: str | None,
    rule_max_matches: str | None,
    classifier_selected: str | None,
    classifier_number_of_matches: int | None,
    override_classifier_number_of_matches: int | None,
    classifier_severity_type: str | None,
    classifier_action_plan: str | None,
    policy: dict[str, Any],
    payload: dict[str, Any] | None = None,
) -> dict:
    if not payload:
        rule = find_rule(policy, rule_name)
        if not rule:
            raise DemistoException(f"Rule `{rule_name}` not found.")
        rule.update(
            remove_empty_elements(
                {
                    "type": rule_type,
                    "max_matches": rule_max_matches,
                    "risk_adaptive_protection_enabled": "false",
                }
            )
        )
        if rule_type == "CUMULATIVE_CONDITION":
            rule.update(
                remove_empty_elements(
                    {
                        "count_type": rule_count_type,
                        "count_time_period": rule_count_period,
                        "count_time_period_window": rule_rate_match_period,
                    }
                )
            )

        # if there is no classifiers
        if not rule.get("classifier_details", []):
            rule["classifier_details"] = [
                {
                    "selected": classifier_selected,
                    "number_of_matches": classifier_number_of_matches,
                    "severity_type": classifier_severity_type,
                    "dup_severity_type": classifier_severity_type,
                    "action_plan": classifier_action_plan,
                },
                {
                    "selected": "false",
                    "number_of_matches": classifier_number_of_matches,
                    "severity_type": classifier_severity_type,
                    "dup_severity_type": classifier_severity_type,
                    "action_plan": classifier_action_plan,
                },
                {
                    "selected": "false",
                    "number_of_matches": classifier_number_of_matches,
                    "severity_type": classifier_severity_type,
                    "dup_severity_type": classifier_severity_type,
                    "action_plan": classifier_action_plan,
                },
            ]
        else:
            if override_classifier_number_of_matches is not None:
                update_severity_classifier_details(
                    rule=rule,
                    details={
                        "number_of_matches": arg_to_number(classifier_number_of_matches),
                        "selected": classifier_selected,
                        "severity_type": classifier_severity_type,
                        "dup_severity_type": classifier_severity_type,
                        "action_plan": classifier_action_plan,
                    },
                    classifiers_key="classifier_details",
                    id=override_classifier_number_of_matches,
                )
            else:
                update_severity_classifier_details(
                    rule=rule,
                    details={
                        "number_of_matches": arg_to_number(classifier_number_of_matches),
                        "selected": classifier_selected,
                        "severity_type": classifier_severity_type,
                        "dup_severity_type": classifier_severity_type,
                        "action_plan": classifier_action_plan,
                    },
                    classifiers_key="classifier_details",
                    id=arg_to_number(classifier_number_of_matches),
                )
    policy = policy if not payload else payload
    from_dict(PolicySeverityAction, policy)
    return remove_empty_elements(policy)


def build_source_destination_payload(
    rule_name: str,
    endpoint_channel_machine_type: str | None,
    endpoint_connection_type: str | None,
    email_monitor_directions: list[str] | None,
    channel_type: str | None,
    channel_enabled: str | None,
    resource_name: str | None,
    resource_type: str | None,
    resource_include: str | None,
    policy: dict[str, Any],
    payload: dict[str, Any] | None,
) -> dict:
    if not payload:
        rule = find_rule(policy, rule_name)
        if not rule:
            raise DemistoException(f"Rule `{rule_name}` not found.")
        channels = dict_safe_get(rule, ["rule_destination", "channels"], [])

        for channel in channels:
            if channel.get("channel_type") == channel_type:
                channel.update(
                    remove_empty_elements(
                        {
                            "enabled": channel_enabled,
                        }
                    )
                )
                if resource_name:
                    for resource in channel.get("resources", []):
                        if resource.get("resource_name") == resource_name:
                            resource.update(
                                remove_empty_elements(
                                    {
                                        "type": resource_type,
                                        "include": resource_include,
                                    }
                                )
                            )
                            break
                    else:
                        channel["resources"] = channel.get("resources", [])
                        channel["resources"].append(
                            {
                                "resource_name": resource_name,
                                "type": resource_type,
                                "include": resource_include,
                            }
                        )
                break
        else:
            channel = {
                "channel_type": channel_type,
                "enabled": channel_enabled,
                "resources": [
                    {
                        "resource_name": resource_name,
                        "type": resource_type,
                        "include": resource_include,
                    }
                ],
            }
            if remove_empty_elements(channel):
                channels.append(channel)

        rule["rule_source"].update(
            remove_empty_elements(
                {
                    "endpoint_channel_machine_type": endpoint_channel_machine_type,
                    "endpoint_connection_type": endpoint_connection_type,
                }
            )
        )
        rule["rule_destination"].update(
            remove_empty_elements(
                {
                    "email_monitor_directions": email_monitor_directions,
                }
            )
        )
        rule["rule_destination"].update(
            {
                "channels": channels,
            }
        )

    policy = policy if not payload else payload
    from_dict(PolicySourceDestination, policy)
    return remove_empty_elements(policy)


def build_exception_rule_payload(
    parent_policy_name: str,
    parent_rule_name: str,
    policy_type: str,
    exception_rule_name: str,
    enabled: str | None,
    description: str | None = None,
    parts_count_type: str | None = None,
    condition_relation_type: str | None = None,
    condition_enabled: str | None = None,
    source_enabled: str | None = None,
    destination_enabled: str | None = None,
    classifier_name: str | None = None,
    classifier_predefined: str | None = None,
    classifier_position: int | None = None,
    classifier_threshold_type: str | None = None,
    classifier_threshold_value_from: int | None = None,
    classifier_threshold_value_to: int | None = None,
    classifier_threshold_calculate_type: str | None = None,
    severity_classifier_max_matches: str | None = None,
    severity_classifier_selected: str | None = None,
    severity_classifier_number_of_matches: int | None = None,
    override_severity_classifier_number_of_matches: int | None = None,
    severity_classifier_severity_type: str | None = None,
    severity_classifier_action_plan: str | None = None,
    exception_policy: dict = {},
    payload: dict | None = None,
) -> dict:
    """
    Build a payload for creating or updating exception rules in a policy.

    Args:
        parent_policy_name (str): Name of the parent policy.
        parent_rule_name (str): Name of the parent rule.
        policy_type (str): Type of the policy (DLP or DISCOVERY).
        exception_rule_name (str): Name of the exception rule.
        enabled (str): Indicates if the rule is enabled.
        description (str | None): Description of the rule.
        parts_count_type (str | None): Parts count type of the exception rule.
        condition_relation_type (str | None): Relation type of the condition.
        condition_enabled (str | None): Whether the condition is enabled.
        source_enabled (str | None): Whether the source condition is enabled (DLP only).
        destination_enabled (str | None): Whether the destination condition is enabled (DLP only).
        classifier_name (str | None): Name of the classifier.
        classifier_predefined (str | None): Whether the classifier is predefined.
        classifier_position (int | None): Position of the classifier.
        classifier_threshold_type (str | None): Threshold type for the classifier.
        classifier_threshold_value_from (int | None): Threshold value for the classifier.
        classifier_threshold_calculate_type (str | None): Calculation type for the threshold.
        severity_classifier_max_matches (str | None): Maximum matches method.
        severity_classifier_selected (str | None): Whether the classifier is selected.
        severity_classifier_number_of_matches (int | None): Number of matches for the classifier.
        severity_classifier_severity_type (str | None): Severity type for the classifier.
        severity_classifier_action_plan (str | None): Action plan for the classifier.
        exception_policy (dict | None): Existing exception policy data.

    Returns:
        dict: Built payload for the exception rule.
    """
    if not payload and not exception_policy:
        raise DemistoException("Exception policy data is required.")

    if payload:
        return payload

    # Ensure top-level attributes are consistent
    exception_policy.update(
        remove_empty_elements(
            {
                "parent_policy_name": parent_policy_name,
                "parent_rule_name": parent_rule_name,
                "policy_type": policy_type,
            }
        )
    )
    # Locate the existing exception rules or initialize the list
    exception_rules = exception_policy.get("exception_rules", [])
    # Check if the exception rule exists by name
    existing_rule = next(
        (
            rule
            for rule in exception_rules
            if rule.get("exception_rule_name") == exception_rule_name
        ),
        None,
    )

    # Update the existing rule or append a new one
    if existing_rule:
        existing_rule.update(
            remove_empty_elements(
                {
                    "enabled": enabled,
                    "description": description,
                    "display_description": description,
                    "parts_count_type": parts_count_type,
                    "condition_relation_type": condition_relation_type,
                    "condition_enabled": condition_enabled,
                    "source_enabled": source_enabled,
                    "destination_enabled": destination_enabled,
                }
            )
        )
        classifier = {
            "classifier_name": classifier_name,
            "predefined": classifier_predefined,
            "position": classifier_position,
            "threshold_type": classifier_threshold_type,
            "threshold_value_from": classifier_threshold_value_from,
            "threshold_value_to": classifier_threshold_value_to,
            "threshold_calculate_type": classifier_threshold_calculate_type,
        }
        if remove_empty_elements(classifier):
            update_classifier(
                existing_rule,
                classifier_position,
                classifier,
            )
        existing_rule["severity_action"] = existing_rule.get("severity_action", {})
        existing_rule["severity_action"].update(
            remove_empty_elements({"max_matches": severity_classifier_max_matches})
        )
        if override_severity_classifier_number_of_matches is not None:
            update_severity_classifier_details(
                rule=existing_rule["severity_action"],
                details={
                    "selected": severity_classifier_selected,
                    "number_of_matches": arg_to_number(severity_classifier_number_of_matches),
                    "severity_type": severity_classifier_severity_type,
                    "dup_severity_type": severity_classifier_severity_type,
                    "action_plan": severity_classifier_action_plan,
                },
                classifiers_key="classifier_details",
                id=override_severity_classifier_number_of_matches,
            )
        else:
            severity_classifier = {
                "selected": severity_classifier_selected,
                "number_of_matches": arg_to_number(severity_classifier_number_of_matches),
                "severity_type": severity_classifier_severity_type,
                "dup_severity_type": severity_classifier_severity_type,
                "action_plan": severity_classifier_action_plan,
            }
            if remove_empty_elements(severity_classifier):
                update_severity_classifier_details(
                    rule=existing_rule["severity_action"],
                    details=severity_classifier,
                    classifiers_key="classifier_details",
                    id=arg_to_number(severity_classifier_number_of_matches),
                )
    else:
        # Add a new exception rule
        new_rule = {
            "exception_rule_name": exception_rule_name,
            "enabled": enabled,
            "description": description,
            "display_description": description,
            "parts_count_type": parts_count_type,
            "condition_relation_type": condition_relation_type,
            "condition_enabled": condition_enabled,
            "source_enabled": source_enabled,
            "destination_enabled": destination_enabled,
            "classifiers": [
                {
                    "classifier_name": classifier_name,
                    "predefined": classifier_predefined,
                    "position": classifier_position,
                    "threshold_type": classifier_threshold_type,
                    "threshold_value_from": classifier_threshold_value_from,
                    "threshold_calculate_type": classifier_threshold_calculate_type,
                }
            ],
            "severity_action": {
                "max_matches": severity_classifier_max_matches,
                "classifier_details": [
                    {
                        "selected": severity_classifier_selected,
                        "number_of_matches": severity_classifier_number_of_matches,
                        "severity_type": severity_classifier_severity_type,
                        "dup_severity_type": severity_classifier_severity_type,
                        "action_plan": severity_classifier_action_plan,
                    },
                    {
                        "selected": "false",
                        "number_of_matches": severity_classifier_number_of_matches,
                        "severity_type": severity_classifier_severity_type,
                        "dup_severity_type": severity_classifier_severity_type,
                        "action_plan": severity_classifier_action_plan,
                    },
                    {
                        "selected": "false",
                        "number_of_matches": severity_classifier_number_of_matches,
                        "severity_type": severity_classifier_severity_type,
                        "dup_severity_type": severity_classifier_severity_type,
                        "action_plan": severity_classifier_action_plan,
                    },
                ],
            },
        }
        exception_rules.append(new_rule)
    # Update the policy with the modified exception rules
    exception_policy["exception_rules"] = exception_rules
    from_dict(PolicyExceptionRule, exception_policy)
    return remove_empty_elements(exception_policy)


def main():  # pragma: no cover
    command = demisto.command()
    params = demisto.params()
    args = demisto.args()
    demisto.debug(f"Command being called is {command}")
    base_url: str = params["url"]
    username: str = params.get("credentials", {}).get("identifier", "")
    password: str = params.get("credentials", {}).get("password", "")
    commands: dict[str, Callable] = {
        f"{INTEGRATION_NAME}-policy-list": list_policy_command,
        f"{INTEGRATION_NAME}-policy-rule-list": list_policy_rule_command,
        f"{INTEGRATION_NAME}-rule-exception-list": list_exception_rule_command,
        f"{INTEGRATION_NAME}-rule-severity-action-get": get_rule_severity_action_command,
        f"{INTEGRATION_NAME}-rule-source-destination-get": get_rule_source_destination_command,
        f"{INTEGRATION_NAME}-rule-create": create_rule_command,
        f"{INTEGRATION_NAME}-rule-update": update_rule_command,
        f"{INTEGRATION_NAME}-rule-severity-action-update": update_rule_severity_action_command,
        f"{INTEGRATION_NAME}-rule-source-destination-update": update_rule_source_destination_command,
        f"{INTEGRATION_NAME}-rule-exception-create": create_exception_rule_command,
        f"{INTEGRATION_NAME}-rule-exception-update": update_exception_rule_command,
        f"{INTEGRATION_NAME}-incident-list": list_incidents_command,
        f"{INTEGRATION_NAME}-incident-update": update_incident_command,
        "get-modified-remote-data": get_modified_remote_data_command,
        "update-remote-system": update_remote_system,
        "get-remote-data": get_remote_data_command,
    }

    try:
        first_fetch = (
            arg_to_datetime(params.get("first_fetch"), settings=DATEPARSER_SETTINGS)
            if params.get("first_fetch")
            else None
        )
        max_fetch = arg_to_number(params.get("max_fetch")) or DEFAULT_MAX_FETCH

        client = Client(
            base_url=base_url,
            verify=not params.get("insecure", False),
            proxy=params.get("proxy", False),
            username=username,
            password=password,
            utc_now=datetime.utcnow(),
        )
        if command == "test-module":
            return_results(test_module(client))

        elif command == "forcepoint-dlp-get-events":
            results, events = get_events_command(client, args)
            return_results(results)
            if argToBoolean(args.get("should_push_events")):
                send_events_to_xsiam(events, VENDOR, PRODUCT)  # noqa

        elif command == "fetch-events":
            fetch_events(client, first_fetch, max_fetch)
        elif command in commands:
            return_results(commands[command](client, args))
        elif command == "fetch-incidents":
            first_fetch = arg_to_datetime(params.get("first_fetch"))
            if not first_fetch:
                raise DemistoException("First fetch time must be specified.")

            incidents, last_run = fetch_incidents(
                client=client,
                first_fetch=first_fetch,
                max_fetch=arg_to_number(params.get("max_fetch")) or 50,
                mirror_direction=MIRROR_DIRECTION_MAPPING.get(
                    params.get("mirror_direction", "None")
                ),
            )
            demisto.debug(f"fetch: Update last run time to {last_run}.")
            demisto.debug(f"fetch: Fetched {len(incidents)} incidents.")
            demisto.setLastRun(last_run)
            demisto.incidents(incidents)
        elif command == "get-mapping-fields":
            return_results(get_mapping_fields_command())

    # Log exceptions
    except Exception as e:
        return_error(f"Failed to execute {demisto.command()} command. Error: {str(e)}")


if __name__ in ("__main__", "__builtin__", "builtins"):  # pragma: no cover
    main()
