import demistomock as demisto
import traceback
import urllib3
from datetime import datetime, timedelta, timezone
from urllib.parse import urlparse, parse_qs
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from ContentClientApiModule import *  # noqa # pylint: disable=unused-wildcard-import
from pydantic import BaseModel, SecretStr  # pylint: disable=no-name-in-module

# Disable insecure warnings
urllib3.disable_warnings()  # pylint: disable=no-member

""" CONSTANTS """

VENDOR = "AdaptiveShield"
PRODUCT = "SSPM"
DEFAULT_MAX_FETCH = 1000
API_PAGE_LIMIT = 500
TIME_FIELD = "creation_date"

#TODO: remove
# dummy_res = {
#     "data": [
#         {
#             "id": "00001",
#             "creation_date":"2026-11-22T05:52:34Z",
#         },
#         {
#             "id": "111",
#             "creation_date":"2026-11-23T05:52:34Z",
#         },
#         {
#             "id": "222",
#             "creation_date":"2026-12-01T05:52:34Z",
#         },
#         {
#             "id": "333",
#             "creation_date":"2026-12-02T05:52:34Z",
#         },
#         {
#             "id": "444",
#             "creation_date":"2026-12-02T05:52:34Z",
#         },
#         {
#             "id": "555",
#             "creation_date":"2026-12-02T05:52:34Z",
#         }
#     ],
#     "total_size": 252,
#     "next_page_uri": "https://api.adaptive-shield.com/api/v1/accounts/ACCOUNT_ID/security_checks?offset=100&limit=100",
# }

# dummy_res2 = {
#     "data": [
#         {
#             "id": "666",
#             "creation_date":"2026-12-04T05:52:34Z",
#         },
#         {
#             "id": "777",
#             "creation_date":"2026-12-05T05:52:34Z",
#         },
#         {
#             "id": "888",
#             "creation_date":"2026-12-06T05:52:34Z",
#         },
#         {
#             "id": "999",
#             "creation_date":"2026-12-07T05:52:34Z",
#         },
#         {
#             "id": "1010",
#             "creation_date":"2026-12-08T05:52:34Z",
#         }
#     ],
#     "total_size": 252,
#     # "next_page_uri": "https://api.adaptive-shield.com/api/v1/accounts/{{accountId}}/security_checks?offset=100&limit=100",
# }




""" BASE CLASSES """


class ContentBaseModel(BaseModel):
    """Base Pydantic model for content models with flexible field population."""

    class Config:
        arbitrary_types_allowed = True
        populate_by_name = True


class BaseParams(ContentBaseModel):
    """Base parameters model with common integration configuration fields."""

    proxy: bool = False
    insecure: bool = False

    @property
    def verify(self) -> bool:
        return not self.insecure


class BaseExecutionConfig:
    """Centralized entrypoint for integration execution.

    Holds the currently-executed command, configuration parameters,
    command arguments, and fetch last run state.
    """

    def __init__(self):
        self._raw_command: str = demisto.command()
        self._raw_params: dict = demisto.params()
        self._raw_args: dict = demisto.args()
        self._raw_last_run: dict = demisto.getLastRun()

    @property
    def command(self) -> str:
        return self._raw_command

    @property
    def args(self) -> dict:
        return self._raw_args


""" PARAMETER & CREDENTIAL MODELS """


class Credentials(ContentBaseModel):
    """Credentials model for API authentication."""

    # username field omitted because `hiddenusername: true` in YML
    password: SecretStr


class AdaptiveShieldSSPMParams(BaseParams):
    """Validated integration parameters for Adaptive Shield SSPM Event Collector.

    Attributes:
        url: The Adaptive Shield API base URL.
        account_id: The Adaptive Shield account ID.
        credentials: API key credentials.
        max_fetch: Maximum number of events to fetch per run.
    """

    url: str = "https://api.adaptive-shield.com"
    account_id: str = ""
    credentials: Credentials
    max_fetch: int = DEFAULT_MAX_FETCH

    @property
    def api_key(self) -> str:
        return self.credentials.password.get_secret_value()


""" CLIENT CLASS """


class Client(ContentClient):
    """Client for Adaptive Shield SSPM API.

    Uses ContentClient from ContentClientApiModule for HTTP requests
    with built-in retry, rate limiting, and structured logging.

    Args:
        params: Validated integration parameters.
    """

    def __init__(self, params: AdaptiveShieldSSPMParams):
        self.account_id = params.account_id
        self.api_key = params.api_key
        super().__init__(
            base_url=params.url,
            verify=params.verify,
            proxy=params.proxy,
            headers={"Authorization": f"Token {self.api_key}", "Accept": "application/json"},
            client_name="AdaptiveShieldSSPM",
        )

    def get_security_checks(self, limit: int = API_PAGE_LIMIT, offset: int = 0) -> dict:
        """Fetch security checks from the Adaptive Shield API.

        Args:
            limit: Maximum number of results per page (default 100).
            offset: Offset for pagination.

        Returns:
            API response dict containing 'data', 'total_size', and optionally 'next_page_uri'.
        """
        params: dict[str, Any] = assign_params(
            limit=min(limit, API_PAGE_LIMIT),
            offset=offset,
        )

        demisto.debug(f"Fetching security checks with {params=}")

        #TODO: remove
        # if offset:
        #     return dummy_res2
        # return dummy_res

        response = self._http_request(
            method="GET",
            url_suffix=f"/api/v1/accounts/{self.account_id}/security_checks",
            params=params,
        )

        return response

    def get_security_checks_with_pagination(
        self,
        max_fetch: int,
        last_run_date: str | None = None,
        last_fetched_ids: list[str] | None = None,
        start_date: str | None = None,
        initial_offset: int = 0,
    ) -> tuple[list[dict], int]:
        """Fetch security checks with pagination support.

        Iterates through pages until max_fetch is reached or no more pages exist.
        Filters out already-fetched events based on last_run_date and last_fetched_ids.

        Args:
            max_fetch: Maximum total number of events to collect.
            last_run_date: ISO 8601 timestamp of the last fetched event's creation_date.
            last_fetched_ids: List of event IDs fetched at the last_run_date timestamp.
            start_date: ISO 8601 timestamp. Events before this date are skipped.
            initial_offset: Starting offset for pagination (from previous last_run).

        Returns:
            Tuple of (list of security check event dicts with '_time' field set, final offset).
        """
        all_events: list[dict] = []
        offset = initial_offset
        last_fetched_ids_set = set(last_fetched_ids or [])

        while len(all_events) < max_fetch:
            remaining = max_fetch - len(all_events)
            page_limit = min(remaining, API_PAGE_LIMIT)

            response = self.get_security_checks(limit=page_limit, offset=offset)
            items = response.get("data", [])

            if not items:
                demisto.debug("No more items returned from API")
                break

            for item in items:
                event_time = item.get(TIME_FIELD)
                event_id = item.get("id")

                # Skip events after start_date
                if start_date and event_time and event_time < start_date:
                    continue

                # Skip events older than or equal to last run date
                if last_run_date and event_time:
                    if event_time < last_run_date:
                        continue
                    # Skip events at the exact same timestamp that were already fetched
                    if event_time == last_run_date and event_id in last_fetched_ids_set:
                        continue

                # Set _time for XSIAM
                item["_time"] = event_time
                all_events.append(item)

                if len(all_events) >= max_fetch:
                    break

            # Check if there are more pages and extract pagination params from the URI
            next_page_uri = response.get("next_page_uri")
            if not next_page_uri:
                demisto.debug("No more pages available")
                break

            parsed = urlparse(next_page_uri)
            query_params = parse_qs(parsed.query)

            # Only advance the offset if the last item from the response was actually collected
            if all_events and items[-1].get('id') == all_events[-1].get('id'):
                offset = int(query_params.get("offset", [offset + len(items)])[0])
            else:
                demisto.debug("Last response item not in collected events, keeping current offset")

            page_limit = int(query_params.get("limit", [page_limit])[0])
            demisto.debug(f"Fetched {len(all_events)} events so far, next page: offset={offset}, limit={page_limit}")

        # Sort by creation_date ascending for consistent ordering
        all_events.sort(key=lambda e: e.get(TIME_FIELD, ""))

        demisto.debug(f"Total events collected: {len(all_events)}, final offset: {offset}")
        return all_events, offset


""" COMMAND FUNCTIONS """


def get_events_command(client: Client, args: dict) -> CommandResults:
    """Manual command to fetch and optionally push security check events.

    Args:
        client: The Adaptive Shield API client.
        args: Command arguments including 'should_push_events' and 'limit'.

    Returns:
        CommandResults with the fetched events.
    """
    limit = arg_to_number(args.get("limit", "10")) or 10
    should_push_events = argToBoolean(args.get("should_push_events", False))

    demisto.debug(f"Running adaptive-shield-sspm-get-events with {should_push_events=}, {limit=}")

    events, _ = client.get_security_checks_with_pagination(max_fetch=limit)

    results = CommandResults(
        outputs_prefix="AdaptiveShieldSSPM.SecurityCheck",
        outputs_key_field="id",
        outputs=events,
        readable_output=tableToMarkdown(
            "Adaptive Shield Security Check Events",
            events,
            headers=["id", "name", "status", "impact", "saas_name", "security_domain", "creation_date"],
            removeNull=True,
        ),
        raw_response=events,
    )

    if should_push_events:
        demisto.debug(f"Sending {len(events)} events to XSIAM")
        send_events_to_xsiam(events, vendor=VENDOR, product=PRODUCT)

    return results


def fetch_events_command(client: Client, max_fetch: int, last_run: dict) -> tuple[list[dict], dict]:
    """Fetch events for the XSIAM event collector.

    Args:
        client: The Adaptive Shield API client.
        max_fetch: Maximum number of events to fetch.
        last_run: The last run state dict with 'last_run_date' and 'last_fetched_ids'.

    Returns:
        Tuple of (events list, updated last_run dict).
    """
    last_run_date = last_run.get("last_run_date")
    last_fetched_ids = last_run.get("last_fetched_ids", [])
    last_offset = last_run.get("offset", 0)
    start_date = (datetime.now(tz=timezone.utc) - timedelta(minutes=1)).strftime("%Y-%m-%dT%H:%M:%SZ")

    demisto.debug(
        f"Fetching events with {last_run_date=}, last_fetched_ids count={len(last_fetched_ids)}, "
        f"{start_date=}, {last_offset=}"
    )

    events, final_offset = client.get_security_checks_with_pagination(
        max_fetch=max_fetch,
        last_run_date=last_run_date,
        last_fetched_ids=last_fetched_ids,
        start_date=start_date,
        initial_offset=last_offset,
    )

    if events:
        # Get the latest creation_date from the fetched events
        new_last_run_date = events[-1].get(TIME_FIELD, "")

        # Collect all IDs at the latest timestamp for deduplication
        ids_at_last_timestamp = [
            event.get("id")
            for event in events
            if event.get(TIME_FIELD) == new_last_run_date and event.get("id")
        ]

        last_run = {
            "last_run_date": new_last_run_date,
            "last_fetched_ids": ids_at_last_timestamp,
            "offset": final_offset,
        }
        demisto.debug(
            f"Updated last_run: date={new_last_run_date}, ids_count={len(ids_at_last_timestamp)}, offset={final_offset}"
        )
    else:
        demisto.debug("No new events found, keeping existing last_run")

    return events, last_run


def test_module_command(client: Client) -> str:
    """Test the connection to the Adaptive Shield API.

    Args:
        client: The Adaptive Shield API client.

    Returns:
        'ok' if the connection is successful.
    """
    client.get_security_checks(limit=1)
    return "ok"


""" EXECUTION CONFIGURATION """


class AdaptiveShieldSSPMExecutionConfig(BaseExecutionConfig):
    """Extends BaseExecutionConfig for the Adaptive Shield SSPM Event Collector.

    Provides validated access to integration parameters and command arguments.
    """

    @property
    def params(self) -> AdaptiveShieldSSPMParams:
        """Get validated integration parameters.

        Returns:
            AdaptiveShieldSSPMParams: Validated integration parameters.
        """
        return AdaptiveShieldSSPMParams(**self._raw_params)


""" MAIN FUNCTION """


def main():
    execution = AdaptiveShieldSSPMExecutionConfig()
    command = execution.command

    demisto.debug(f"Command being called is {command}")

    try:
        params = execution.params

        client = Client(params=params)

        match execution.command:
            case "test-module":
                result = test_module_command(client)
                return_results(result)

            case "adaptive-shield-sspm-get-events":
                results = get_events_command(client, execution.args)
                return_results(results)

            case "fetch-events":
                max_fetch = params.max_fetch
                last_run = execution._raw_last_run
                demisto.debug(f"Last run is: {last_run}")

                events, last_run = fetch_events_command(client, max_fetch, last_run)

                if not events:
                    demisto.info("No events found")
                else:
                    demisto.debug(f"Sending {len(events)} events to XSIAM")
                    send_events_to_xsiam(events, vendor=VENDOR, product=PRODUCT)

                demisto.setLastRun(last_run)
                demisto.debug(f"Last run set to: {last_run}")

            case _:
                raise NotImplementedError(f"Command {command} is not implemented")

    except Exception as e:
        demisto.error(f"{type(e).__name__} in {command}: {str(e)}\nTraceback:\n{traceback.format_exc()}")
        return_error(f"Failed to execute {command} command.\nError:\n{e}")


""" ENTRY POINT """

if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
