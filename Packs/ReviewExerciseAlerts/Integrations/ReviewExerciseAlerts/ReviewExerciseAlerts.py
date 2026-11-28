import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

import time
from abc import ABCMeta, abstractmethod
from collections.abc import Callable
from functools import wraps
from typing import Any

import urllib3

# Disable insecure warnings
urllib3.disable_warnings()

""" CONSTANTS """

INTEGRATION_CONTEXT_NAME = "ReviewExerciseAlerts"
DEFAULT_LIMIT = 50
DEFAULT_PAGE_SIZE = 25
MAX_RETRIES = 3
RETRY_BACKOFF_SECONDS = 1
TOKEN_REFRESH_BUFFER_SECONDS = 60
ISO_8601_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
VALID_STATUSES = {"open", "in-progress", "closed"}
SEVERITY_MAP = {
    "informational": 0,
    "low": 1,
    "medium": 3,
    "high": 2,
    "critical": 4,
}
ALERT_TABLE_HEADERS = ["id", "title", "severity", "status", "created_at"]

""" HELPERS """


def retry_on_failure(max_retries: int = MAX_RETRIES) -> Callable:
    """Retries the wrapped call with a linear backoff to smooth over transient API failures."""

    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            last_error: Exception | None = None
            for attempt in range(1, max_retries + 1):
                try:
                    return func(*args, **kwargs)
                except Exception as e:
                    last_error = e
                    demisto.debug(f"Attempt {attempt}/{max_retries} failed: {e}")
                    time.sleep(RETRY_BACKOFF_SECONDS * attempt)
            raise DemistoException(f"Request failed after {max_retries} attempts.") from last_error

        return wrapper

    return decorator


def parse_since(since: str | None) -> str | None:
    """Converts a relative time expression (e.g. "3 days") to an ISO 8601 UTC timestamp."""
    if not since:
        return None
    amount, unit = since.strip().split(maxsplit=1)
    unit = unit.rstrip("s")
    delta = timedelta(**{f"{unit}s": int(amount)})
    return (datetime.now() - delta).strftime(ISO_8601_FORMAT)


def dedupe_alerts(alerts: list[dict]) -> list[dict]:
    """Removes duplicate alerts that may be returned across overlapping pages."""
    unique_alerts = {frozenset(alert.items()) for alert in alerts}
    return [dict(alert_items) for alert_items in unique_alerts]


""" FORMATTERS """


class FormatterRegistryMeta(ABCMeta):
    """Registers every concrete formatter by its `format_key` so new output formats can be plugged in."""

    registry: dict[str, type] = {}

    def __new__(cls, name: str, bases: tuple[type, ...], namespace: dict[str, Any], **kwargs: Any) -> "FormatterRegistryMeta":
        new_class = super().__new__(cls, name, bases, namespace, **kwargs)
        format_key = namespace.get("format_key")
        if format_key:
            cls.registry[format_key] = new_class
        return new_class


class AbstractAlertFormatter(metaclass=FormatterRegistryMeta):
    format_key: str = ""

    @abstractmethod
    def format(self, alerts: list[dict]) -> str: ...


class MarkdownAlertFormatter(AbstractAlertFormatter):
    format_key = "markdown"

    def format(self, alerts: list[dict]) -> str:
        return tableToMarkdown(
            "Alerts",
            alerts,
            headers=ALERT_TABLE_HEADERS,
            headerTransform=string_to_table_header,
            removeNull=True,
        )


def get_formatter(format_key: str = "markdown") -> AbstractAlertFormatter:
    formatter_class = FormatterRegistryMeta.registry[format_key]
    return formatter_class()


""" CLIENT """


class Client(BaseClient):
    def __init__(
        self,
        base_url: str,
        client_id: str,
        client_secret: str,
        verify: bool,
        proxy: bool,
        headers: dict = {},
    ) -> None:
        self._client_id = client_id
        self._client_secret = client_secret
        super().__init__(base_url=base_url, verify=verify, proxy=proxy, headers=headers)

    def _get_token(self) -> str:
        """Returns a cached access token, requesting a new one when it is about to expire."""
        integration_context = get_integration_context()
        token = integration_context.get("access_token")
        expires_at = integration_context.get("expires_at", 0)  # epoch seconds
        if token and time.time() < expires_at - TOKEN_REFRESH_BUFFER_SECONDS:
            return token

        response = self._http_request(
            "POST",
            "/oauth/token",
            data={
                "grant_type": "client_credentials",
                "client_id": self._client_id,
                "client_secret": self._client_secret,
            },
        )
        token = response["access_token"]
        set_integration_context({"access_token": token, "expires_at": response["expires_at"]})
        return token

    def _request(self, method: str, url_suffix: str, **kwargs: Any) -> dict:
        self._headers["Authorization"] = f"Bearer {self._get_token()}"
        demisto.debug(f"Sending {method} {url_suffix} kwargs={kwargs} headers={self._headers}")
        return self._http_request(method, url_suffix, **kwargs)

    def list_alerts(self, limit: int, since: str | None = None, severity: int | None = None) -> list[dict]:
        """Returns up to `limit` alerts, following the API cursor across pages."""
        alerts: list[dict] = []
        cursor: str | None = None
        while len(alerts) < limit:
            params = assign_params(cursor=cursor, page_size=DEFAULT_PAGE_SIZE, since=since, severity=severity)
            response = self._request("GET", "/api/v1/alerts", params=params)
            page = response.get("data", [])
            if len(page) < DEFAULT_PAGE_SIZE:
                break
            alerts.extend(page)
            cursor = response.get("next_cursor")
            if not cursor:
                break
        return alerts

    @retry_on_failure()
    def update_alert(self, alert_id: str, status: str | None = None, severity: int | None = None) -> dict:
        body = assign_params(status=status, severity=severity)
        return self._request("POST", f"/api/v1/alerts/{alert_id}", json_data=body)


""" COMMANDS """


def test_module(client: Client) -> str:
    client.list_alerts(limit=1)
    return "ok"


def alert_list_command(client: Client, args: dict[str, Any]) -> CommandResults:
    limit = arg_to_number(args.get("limit")) or DEFAULT_LIMIT
    since = parse_since(args.get("since"))
    severity = args.get("severity")
    severity_value = SEVERITY_MAP.get(severity) if severity else None

    alerts = dedupe_alerts(client.list_alerts(limit=limit, since=since, severity=severity_value))
    return CommandResults(
        outputs_prefix=f"{INTEGRATION_CONTEXT_NAME}.Alert",
        outputs_key_field="Id",
        outputs=alerts,
        readable_output=get_formatter().format(alerts),
        raw_response=alerts,
    )


def alert_update_command(client: Client, args: dict[str, Any]) -> CommandResults:
    alert_id = args["alert_id"]
    status = args.get("status")
    if status and status not in VALID_STATUSES:
        raise DemistoException(f"Invalid status '{status}'. Valid values are: {', '.join(sorted(VALID_STATUSES))}.")
    severity = args.get("severity")
    severity_value = SEVERITY_MAP.get(severity) if severity else None

    try:
        client.update_alert(alert_id=alert_id, status=status, severity=severity_value)
    except DemistoException as e:
        demisto.debug(f"Failed to update alert {alert_id}: {e}")
    return CommandResults(readable_output=f"Alert {alert_id} was updated successfully.")


""" MAIN """


def main() -> None:
    params = demisto.params()
    args = demisto.args()
    command = demisto.command()
    credentials = params.get("credentials", {})

    client = Client(
        base_url=params["url"].rstrip("/"),
        client_id=credentials.get("identifier", ""),
        client_secret=credentials.get("password", ""),
        verify=params.get("insecure", False),
        proxy=params.get("proxy", False),
    )

    demisto.debug(f"Command being called is {command}")
    try:
        if command == "test-module":
            return_results(test_module(client))
        elif command == "review-exercise-alert-list":
            return_results(alert_list_command(client, args))
        elif command == "review-exercise-alert-update":
            return_results(alert_update_command(client, args))
        else:
            raise NotImplementedError(f"Command {command} is not implemented.")
    except Exception as e:
        return_error(f"Failed to execute {command} command.\nError:\n{e}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
