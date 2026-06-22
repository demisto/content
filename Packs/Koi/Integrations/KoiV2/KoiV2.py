import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

from CommonServerUserPython import *  # noqa: F401

from typing import Any

import urllib3

# Disable insecure warnings
urllib3.disable_warnings()

""" CONSTANTS """

VENDOR = "koi"
PRODUCT = "security"
DATE_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
DEFAULT_MAX_EVENTS = 5000
DEFAULT_PAGE_SIZE = 100

""" CLIENT CLASS """


class Client(BaseClient):
    """Client to interact with the KOI v2 API.

    Extends BaseClient from CommonServerPython for HTTP handling.
    """

    def __init__(self, base_url: str, api_key: str, verify: bool, proxy: bool):
        headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        }
        super().__init__(base_url=base_url, verify=verify, proxy=proxy, headers=headers)

    def get_events(self, start_time: str, limit: int, page_size: int) -> list[dict[str, Any]]:
        """Retrieve events from the KOI API with pagination.

        Args:
            start_time: ISO 8601 timestamp to fetch events from.
            limit: Maximum number of events to return.
            page_size: Number of events to request per page.

        Returns:
            A list of event dictionaries.
        """
        events: list[dict[str, Any]] = []
        page = 1
        while len(events) < limit:
            params = {
                "from": start_time,
                "page": page,
                "page_size": min(page_size, limit - len(events)),
            }
            response = self._http_request(method="GET", url_suffix="/v2/events", params=params)
            page_events = response.get("events", [])
            if not page_events:
                break
            events.extend(page_events)
            page += 1
        return events[:limit]

    def get_allowlist(self) -> list[dict[str, Any]]:
        """Retrieve the allowlist entries from the KOI API.

        Returns:
            A list of allowlist item dictionaries.
        """
        response = self._http_request(method="GET", url_suffix="/v2/allowlist")
        return response.get("items", [])


""" HELPER FUNCTIONS """


def add_time_to_events(events: list[dict[str, Any]]) -> None:
    """Add the _time field to each event for XSIAM ingestion.

    Args:
        events: The list of events to enrich in place.
    """
    for event in events:
        created = event.get("created_time") or event.get("timestamp")
        if created:
            event["_time"] = created


""" COMMAND FUNCTIONS """


def test_module(client: Client) -> str:
    """Test connectivity to the KOI v2 API.

    Args:
        client: The KOI API client.

    Returns:
        'ok' if the connection succeeds.
    """
    client.get_allowlist()
    return "ok"


def get_events_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Retrieve events from KOI and optionally push them to XSIAM.

    Args:
        client: The KOI API client.
        args: Command arguments (limit, start_time, should_push_events).

    Returns:
        CommandResults with the retrieved events.
    """
    limit = arg_to_number(args.get("limit")) or DEFAULT_MAX_EVENTS
    start_time = args.get("start_time") or "1 hour"
    parsed_start = arg_to_datetime(start_time)
    start_time_str = parsed_start.strftime(DATE_FORMAT) if parsed_start else start_time
    should_push_events = argToBoolean(args.get("should_push_events", False))

    events = client.get_events(start_time=start_time_str, limit=limit, page_size=DEFAULT_PAGE_SIZE)
    add_time_to_events(events)

    if should_push_events:
        send_events_to_xsiam(events, vendor=VENDOR, product=PRODUCT)

    human_readable = tableToMarkdown(name="KOI v2 Events", t=events)
    return CommandResults(
        readable_output=human_readable,
        outputs_prefix="KoiV2.Event",
        outputs_key_field="id",
        outputs=events,
    )


def allowlist_get_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Retrieve the KOI allowlist.

    Args:
        client: The KOI API client.
        args: Command arguments (limit).

    Returns:
        CommandResults with the allowlist items.
    """
    limit = arg_to_number(args.get("limit")) or DEFAULT_MAX_EVENTS
    items = client.get_allowlist()[:limit]

    human_readable = tableToMarkdown(name="KOI v2 Allowlist", t=items)
    return CommandResults(
        readable_output=human_readable,
        outputs_prefix="KoiV2.Allowlist",
        outputs_key_field="item_id",
        outputs=items,
    )


""" MAIN FUNCTION """


def main() -> None:
    """Parse parameters, instantiate the client, and route commands."""
    params = demisto.params()
    args = demisto.args()
    command = demisto.command()

    base_url = params.get("url", "").rstrip("/")
    api_key = params.get("api_key", {}).get("password", "") if isinstance(params.get("api_key"), dict) else ""
    verify = not argToBoolean(params.get("insecure", False))
    proxy = argToBoolean(params.get("proxy", False))

    demisto.debug(f"Command being called is {command}")
    try:
        client = Client(base_url=base_url, api_key=api_key, verify=verify, proxy=proxy)

        if command == "test-module":
            return_results(test_module(client))
        elif command == "koi-v2-get-events":
            return_results(get_events_command(client, args))
        elif command == "koiv2-allowlist-get":
            return_results(allowlist_get_command(client, args))
        else:
            raise NotImplementedError(f"Command {command} is not implemented")

    except Exception as e:
        return_error(f"Failed to execute {command} command.\nError:\n{str(e)}")


""" ENTRY POINT """


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
