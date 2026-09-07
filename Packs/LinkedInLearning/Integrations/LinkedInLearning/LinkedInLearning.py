# ruff: noqa: F401
import traceback
from datetime import datetime, UTC
from math import ceil
from typing import Any

from pydantic import AnyUrl, Field, SecretStr, validator  # pylint: disable=no-name-in-module

import demistomock as demisto

from CommonServerPython import *
from CommonServerUserPython import *

from ContentClientApiModule import *
from BaseContentApiModule import *

"""LinkedIn Learning Event Collector Integration for Cortex XSIAM

Collects learning activity reports from the LinkedIn Learning API and sends them to XSIAM.

Uses the Two-legged OAuth 2.0 (Client Credentials) flow for authentication via
OAuth2ClientCredentialsHandler from ContentClientApiModule.

API Reference: https://learn.microsoft.com/en-us/linkedin/learning/
"""

# region Constants

VENDOR = "linkedin"
PRODUCT = "learning"
DATE_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
DEFAULT_MAX_FETCH = 1000
PAGE_SIZE = 100
MAX_PAGES = 10
# API allows a maximum time window of 14 days (2 weeks) per request.
MAX_TIME_OFFSET_DAYS = 14
DEFAULT_FIRST_FETCH_DAYS = MAX_TIME_OFFSET_DAYS
MS_PER_DAY = 24 * 60 * 60 * 1000

# Fixed content source used for the API request (per design).
DEFAULT_CONTENT_SOURCE = "ALL_SOURCES"
DEFAULT_ENGAGEMENT_METRIC_QUALIFIER = "TOTAL"
DEFAULT_PRIMARY_AGGREGATION = "ACCOUNT"
DEFAULT_SECONDARY_AGGREGATION = "CONTENT"

# endregion

# region Parameters


class LinkedInLearningParams(BaseParams):
    """Pydantic model for LinkedIn Learning integration parameters.

    Inherits proxy and insecure (verify) from BaseParams.
    """

    url: AnyUrl
    client_id: str
    client_secret: SecretStr
    is_fetch_events: bool | None = Field(default=False, alias="isFetchEvents")
    max_fetch: int = DEFAULT_MAX_FETCH
    engagement_metric_type: str | None = None
    engagement_metric_qualifier: str = DEFAULT_ENGAGEMENT_METRIC_QUALIFIER
    asset_type: str | None = None
    content_source: str = DEFAULT_CONTENT_SOURCE
    primary_aggregation_criteria: str = DEFAULT_PRIMARY_AGGREGATION
    secondary_aggregation_criteria: str = DEFAULT_SECONDARY_AGGREGATION

    @validator("url", allow_reuse=True)
    @classmethod
    def clean_url(cls, v: str) -> str:
        """Remove trailing forward slash from the URL parameter."""
        return str(v).rstrip("/")

    @validator("max_fetch", allow_reuse=True)
    @classmethod
    def validate_max_fetch(cls, v: int) -> int:
        """Cap max_fetch to a reasonable limit."""
        max_cap = PAGE_SIZE * MAX_PAGES
        if v > max_cap:
            demisto.debug(f"[Param validation] Lowered configured max_fetch={v} to {max_cap}.")
            return max_cap
        return v

    def build_filter_query(self) -> str:
        """Build the learningActivityReports query string from the discrete criteria parameters.

        Returns:
            A query string beginning with '?'.
        """
        query_params: dict[str, str] = {
            "q": "criteria",
            "aggregationCriteria.primary": self.primary_aggregation_criteria,
            "aggregationCriteria.secondary": self.secondary_aggregation_criteria,
            "contentSource": self.content_source,
        }
        # sortBy.engagementMetricQualifier only qualifies the sort metric, so it is
        # only meaningful when a sort metric type is also provided. Sending the
        # qualifier alone can be rejected or ignored by the API.
        if self.engagement_metric_type:
            query_params["sortBy.engagementMetricType"] = self.engagement_metric_type
            if self.engagement_metric_qualifier:
                query_params["sortBy.engagementMetricQualifier"] = self.engagement_metric_qualifier
        if self.asset_type:
            query_params["assetType"] = self.asset_type

        query = "&".join(f"{key}={value}" for key, value in query_params.items())
        return f"?{query}"


# endregion

# region Auth & Client


class LinkedInLearningClient(ContentClient):
    """LinkedIn Learning client that extends ContentClient for API interactions.

    Uses OAuth2ClientCredentialsHandler for two-legged OAuth 2.0 authentication.
    """

    def __init__(self, params: LinkedInLearningParams):
        """Initialize LinkedIn Learning client.

        Args:
            params: Integration parameters including URL, client_id, and client_secret.
        """
        base_url = str(params.url)
        token_url = base_url.replace("api.linkedin.com", "www.linkedin.com") + "/oauth/v2/accessToken"

        auth_handler = OAuth2ClientCredentialsHandler(
            token_url=token_url,
            client_id=params.client_id,
            client_secret=params.client_secret.get_secret_value(),
        )
        super().__init__(
            base_url=base_url,
            verify=params.verify,
            proxy=params.proxy,
            auth_handler=auth_handler,
            client_name="LinkedInLearningClient",
        )

    def get_learning_activity_reports(
        self,
        filter_query: str,
        started_at: int,
        duration_days: int,
        start: int = 0,
        count: int = PAGE_SIZE,
    ) -> dict[str, Any]:
        """Fetch learning activity reports from the LinkedIn Learning API.

        Args:
            filter_query: Query string filter for the API request.
            started_at: Epoch milliseconds for the start time filter.
            duration_days: Length of the time window in days (max 14 per API).
            start: Offset for pagination.
            count: Number of results per page.

        Returns:
            API response containing elements and paging information.
        """
        # Build the endpoint with filter query params
        endpoint = f"/v2/learningActivityReports{filter_query}"

        # Add pagination and time filter params
        separator = "&" if "?" in endpoint else "?"
        endpoint += (
            f"{separator}startedAt={started_at}"
            f"&timeOffset.unit=DAY"
            f"&timeOffset.duration={duration_days}"
            f"&count={count}"
            f"&start={start}"
        )

        return self.get(url_suffix=endpoint)

    def get_by_next_link(self, next_href: str) -> dict[str, Any]:
        """Fetch the next page of results using the paging next link.

        Args:
            next_href: The href from paging.links[rel="next"], relative to the base URL.

        Returns:
            API response containing elements and paging information.
        """
        return self.get(url_suffix=next_href)

    def log_optional_diagnostic_report(self) -> None:
        """Log a diagnostic report for troubleshooting if diagnostic mode is enabled."""
        if not self._diagnostic_mode:
            demisto.debug("[Client] Diagnostic mode is disabled. Skipping generating diagnostic report.")
            return

        try:
            report = self.get_diagnostic_report()
            demisto.debug(f"[Client] Diagnostic Report: {json.dumps(report.__dict__, default=str, indent=2)}")
            self.logger.log_metrics_summary()
        except Exception as e:
            demisto.debug(f"Failed to generate diagnostic report: {e}")


# endregion

# region Commands


class LinkedInLearningLastRun(ContentBaseModel):
    """State management for fetch-events command."""

    last_fetch_time: int | None = None


class LinkedInLearningGetEventsArgs(ContentBaseModel):
    """Arguments for linkedin-learning-get-events command."""

    limit: int = 50
    should_push_events: bool = False

    @validator("should_push_events", pre=True, allow_reuse=True)
    @classmethod
    def validate_should_push_events(cls, v: Any) -> bool:
        """Convert should_push_events to boolean."""
        return argToBoolean(v)


def add_time_to_events(events: list[dict]) -> None:
    """Add the _time key to events based on latestDataAt field.

    Args:
        events: List of event dictionaries to add the _time key to.
    """
    for event in events:
        latest_data_at = event.get("latestDataAt")
        if latest_data_at:
            dt = datetime.fromtimestamp(latest_data_at / 1000, tz=UTC)
            event["_time"] = dt.strftime(DATE_FORMAT)


def get_next_link(response: dict) -> str | None:
    """Extract the paging next link href from an API response.

    Args:
        response: API response dictionary.

    Returns:
        The href for the next page (relative to base URL), or None if absent.
    """
    paging_links = response.get("paging", {}).get("links", [])
    for link in paging_links:
        if link.get("rel") == "next" and link.get("href"):
            return link["href"]
    return None


def calculate_time_window(started_at: int, now_ms: int) -> tuple[int, int]:
    """Calculate the query time window, capped at the API maximum of 14 days.

    Args:
        started_at: Window start in epoch milliseconds.
        now_ms: Current time in epoch milliseconds.

    Returns:
        Tuple of (started_at, duration_days) where duration_days is 1..14.
    """
    span_ms = max(now_ms - started_at, 0)
    duration_days = ceil(span_ms / MS_PER_DAY) or 1
    duration_days = min(duration_days, MAX_TIME_OFFSET_DAYS)
    return started_at, duration_days


def fetch_all_events(
    client: LinkedInLearningClient,
    filter_query: str,
    started_at: int,
    duration_days: int,
    max_fetch: int,
) -> list[dict]:
    """Fetch all events with pagination.

    Follows ``paging.links[rel="next"]`` hrefs per the API design, and stops
    when the next link is absent, fewer than a full page is returned, max_fetch
    is reached, or the maximum page count is hit.

    Args:
        client: LinkedIn Learning client instance.
        filter_query: Query string filter for the API request.
        started_at: Epoch milliseconds for the start time filter.
        duration_days: Length of the time window in days (max 14 per API).
        max_fetch: Maximum number of events to fetch.

    Returns:
        List of event dictionaries.
    """
    all_events: list[dict] = []
    pages_fetched = 0
    next_link: str | None = None

    while len(all_events) < max_fetch and pages_fetched < MAX_PAGES:
        if next_link:
            demisto.debug(f"[Fetch events] Fetching next page via link: {next_link}.")
            response = client.get_by_next_link(next_link)
        else:
            demisto.debug(f"[Fetch events] Fetching first page with count={PAGE_SIZE}.")
            response = client.get_learning_activity_reports(
                filter_query=filter_query,
                started_at=started_at,
                duration_days=duration_days,
                start=0,
                count=PAGE_SIZE,
            )

        elements = response.get("elements", [])
        if not elements:
            demisto.debug("[Fetch events] No more elements returned. Stopping pagination.")
            break

        all_events.extend(elements)
        pages_fetched += 1

        next_link = get_next_link(response)
        if not next_link or len(elements) < PAGE_SIZE:
            demisto.debug("[Fetch events] No next link or fewer elements than page size. Stopping pagination.")
            break

    # Trim to max_fetch
    if len(all_events) > max_fetch:
        all_events = all_events[:max_fetch]

    demisto.debug(f"[Fetch events] Fetched {len(all_events)} total events across {pages_fetched} pages.")
    return all_events


def create_events(events: list[dict]) -> None:
    """Send events to XSIAM.

    Args:
        events: List of event dictionaries to send.
    """
    demisto.debug(f"[Create events] Sending {len(events)} events to XSIAM.")
    send_events_to_xsiam(
        events=events,
        vendor=VENDOR,
        product=PRODUCT,
    )
    demisto.debug(f"[Create events] Successfully sent {len(events)} events.")


def run_test_module(client: LinkedInLearningClient, params: LinkedInLearningParams) -> str:
    """Test API connectivity and authentication.

    Args:
        client: LinkedIn Learning client instance.
        params: Integration parameters.

    Returns:
        'ok' if test passed.
    """
    now_ms = int(datetime.now(tz=UTC).timestamp() * 1000)
    started_at = now_ms - (DEFAULT_FIRST_FETCH_DAYS * MS_PER_DAY)

    client.get_learning_activity_reports(
        filter_query=params.build_filter_query(),
        started_at=started_at,
        duration_days=DEFAULT_FIRST_FETCH_DAYS,
        start=0,
        count=1,
    )
    return "ok"


def fetch_events_command(
    client: LinkedInLearningClient,
    params: LinkedInLearningParams,
    last_run: LinkedInLearningLastRun,
) -> LinkedInLearningLastRun:
    """Fetch learning activity reports and send them to XSIAM.

    Args:
        client: LinkedIn Learning client instance.
        params: Integration parameters.
        last_run: State from the previous fetch execution.

    Returns:
        Next run state for the next fetch.
    """
    now_ms = int(datetime.now(tz=UTC).timestamp() * 1000)

    if last_run.last_fetch_time:
        started_at = last_run.last_fetch_time
    else:
        started_at = now_ms - (DEFAULT_FIRST_FETCH_DAYS * MS_PER_DAY)

    started_at, duration_days = calculate_time_window(started_at, now_ms)
    demisto.debug(f"[Fetch events] Starting fetch with started_at={started_at}, duration_days={duration_days}.")

    events = fetch_all_events(
        client=client,
        filter_query=params.build_filter_query(),
        started_at=started_at,
        duration_days=duration_days,
        max_fetch=params.max_fetch,
    )

    if not events:
        demisto.debug("[Fetch events] No new events found.")
        return last_run

    add_time_to_events(events)
    create_events(events)

    # Determine the latest latestDataAt for next run
    latest_time = max(
        (event.get("latestDataAt", 0) for event in events),
        default=started_at,
    )
    # Add 1ms to avoid re-fetching the same event
    next_run = LinkedInLearningLastRun(last_fetch_time=latest_time + 1)
    demisto.debug(f"[Fetch events] Completed. Fetched {len(events)} events. Next fetch from {next_run.last_fetch_time}.")
    return next_run


def get_events_command(
    client: LinkedInLearningClient,
    params: LinkedInLearningParams,
    args: LinkedInLearningGetEventsArgs,
) -> CommandResults:
    """Execute linkedin-learning-get-events command.

    Args:
        client: LinkedIn Learning client instance.
        params: Integration parameters.
        args: Validated command arguments.

    Returns:
        CommandResults with collected events.
    """
    now_ms = int(datetime.now(tz=UTC).timestamp() * 1000)
    started_at = now_ms - (DEFAULT_FIRST_FETCH_DAYS * MS_PER_DAY)
    started_at, duration_days = calculate_time_window(started_at, now_ms)

    demisto.debug(f"[Get events] Fetching events with limit={args.limit}.")

    events = fetch_all_events(
        client=client,
        filter_query=params.build_filter_query(),
        started_at=started_at,
        duration_days=duration_days,
        max_fetch=args.limit,
    )

    if args.should_push_events and events:
        add_time_to_events(events)
        create_events(events)

    readable_output = tableToMarkdown("LinkedIn Learning Events", events)
    return CommandResults(readable_output=readable_output)


# endregion

# region ExecutionConfig


class LinkedInLearningExecutionConfig(BaseExecutionConfig):
    """Extends BaseExecutionConfig for LinkedIn Learning integration."""

    @property
    def params(self) -> LinkedInLearningParams:
        """Get validated integration parameters.

        Returns:
            Validated integration parameters.
        """
        return LinkedInLearningParams(**self._raw_params)

    @property
    def get_events_args(self) -> LinkedInLearningGetEventsArgs:
        """Get validated arguments for the linkedin-learning-get-events command.

        Returns:
            Validated arguments.
        """
        return LinkedInLearningGetEventsArgs(**self._raw_args)

    @property
    def last_run(self) -> LinkedInLearningLastRun:
        """Get the last_run state for fetch-events command.

        Returns:
            State from the previous fetch execution.
        """
        return LinkedInLearningLastRun(**self._raw_last_run)


# endregion

# region Main


def main() -> None:  # pragma: no cover
    """Parse and validate configuration parameters and command arguments, then run commands."""
    execution = LinkedInLearningExecutionConfig()
    command = execution.command

    demisto.debug(f"[Main] Starting to execute {command=}.")
    client = None
    try:
        params = execution.params
        client = LinkedInLearningClient(params)

        match execution.command:
            case "test-module":
                return_results(run_test_module(client, params))

            case "fetch-events":
                demisto.debug("[Main] Starting fetch-events")
                last_run = execution.last_run
                next_run = fetch_events_command(client, params, last_run)
                next_run_dict = {"last_fetch_time": next_run.last_fetch_time}
                demisto.setLastRun(next_run_dict)
                demisto.debug(f"[Main] fetch-events completed. Next run: {next_run_dict}")

            case "linkedin-learning-get-events":
                get_events_args = execution.get_events_args
                results = get_events_command(client, params, get_events_args)
                return_results(results)

            case _:
                raise NotImplementedError(f"Command {command} is not implemented")

    except Exception as e:
        demisto.error(f"[Main] Failed to execute {command=}: {str(e)}. {traceback.format_exc()}")
        return_error(f"Failed to execute {command} command.\nError:\n{str(e)}")

    finally:
        demisto.debug(f"[Main] Generating diagnostic report after executing {command=}.")
        if client:
            client.log_optional_diagnostic_report()


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()

# endregion
