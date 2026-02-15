import demistomock as demisto
import traceback
import urllib3
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from ContentClientApiModule import *  # noqa # pylint: disable=unused-wildcard-import

# Disable insecure warnings
urllib3.disable_warnings()  # pylint: disable=no-member

""" CONSTANTS """

VENDOR = "AdaptiveShield"
PRODUCT = "SSPM"
DEFAULT_MAX_FETCH = 1000
API_PAGE_LIMIT = 100
TIME_FIELD = "creation_date"


""" CLIENT CLASS """


class Client(ContentClient):
    """Client for Adaptive Shield SSPM API.

    Uses ContentClient from ContentClientApiModule for HTTP requests
    with built-in retry, rate limiting, and structured logging.

    Args:
        base_url: The Adaptive Shield API base URL.
        account_id: The Adaptive Shield account ID.
        api_key: The API key for authentication.
        verify: Whether to verify SSL certificates.
        proxy: Whether to use system proxy settings.
    """

    def __init__(self, base_url: str, account_id: str, api_key: str, verify: bool, proxy: bool):
        self.account_id = account_id
        self.api_key = api_key
        super().__init__(
            base_url=base_url,
            verify=verify,
            proxy=proxy,
            headers={"Authorization": f"Token {api_key}", "Accept": "application/json"},
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
    ) -> list[dict]:
        """Fetch security checks with pagination support.

        Iterates through pages until max_fetch is reached or no more pages exist.
        Filters out already-fetched events based on last_run_date and last_fetched_ids.

        Args:
            max_fetch: Maximum total number of events to collect.
            last_run_date: ISO 8601 timestamp of the last fetched event's creation_date.
            last_fetched_ids: List of event IDs fetched at the last_run_date timestamp.

        Returns:
            List of security check event dicts with '_time' field set.
        """
        all_events: list[dict] = []
        offset = 0
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

            # Check if there are more pages
            next_page_uri = response.get("next_page_uri")
            if not next_page_uri or len(items) < page_limit:
                demisto.debug("No more pages available")
                break

            offset += len(items)
            demisto.debug(f"Fetched {len(all_events)} events so far, moving to offset {offset}")

        # Sort by creation_date ascending for consistent ordering
        all_events.sort(key=lambda e: e.get(TIME_FIELD, ""))

        demisto.debug(f"Total events collected: {len(all_events)}")
        return all_events


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

    events = client.get_security_checks_with_pagination(max_fetch=limit)

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

    demisto.debug(f"Fetching events with {last_run_date=}, last_fetched_ids count={len(last_fetched_ids)}")

    events = client.get_security_checks_with_pagination(
        max_fetch=max_fetch,
        last_run_date=last_run_date,
        last_fetched_ids=last_fetched_ids,
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
        }
        demisto.debug(f"Updated last_run: date={new_last_run_date}, ids_count={len(ids_at_last_timestamp)}")
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


""" MAIN FUNCTION """


def main():
    command = demisto.command()
    params = demisto.params()
    args = demisto.args()

    demisto.debug(f"Command being called is {command}")

    try:
        client = Client(
            base_url=params.get("url", "https://api.adaptive-shield.com"),
            account_id=params.get("account_id", ""),
            api_key=params.get("credentials", {}).get("password", ""),
            verify=not params.get("insecure", False),
            proxy=params.get("proxy", False),
        )

        if command == "test-module":
            result = test_module_command(client)
            return_results(result)

        elif command == "adaptive-shield-sspm-get-events":
            results = get_events_command(client, args)
            return_results(results)

        elif command == "fetch-events":
            max_fetch = arg_to_number(params.get("max_fetch")) or DEFAULT_MAX_FETCH
            last_run = demisto.getLastRun()
            demisto.debug(f"Last run is: {last_run}")

            events, last_run = fetch_events_command(client, max_fetch, last_run)

            if not events:
                demisto.info("No events found")
            else:
                demisto.debug(f"Sending {len(events)} events to XSIAM")
                send_events_to_xsiam(events, vendor=VENDOR, product=PRODUCT)

            demisto.setLastRun(last_run)
            demisto.debug(f"Last run set to: {last_run}")

        else:
            raise NotImplementedError(f"Command {command} is not implemented")

    except Exception as e:
        demisto.error(f"{type(e).__name__} in {command}: {str(e)}\nTraceback:\n{traceback.format_exc()}")
        return_error(f"Failed to execute {command} command.\nError:\n{e}")


""" ENTRY POINT """

if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
