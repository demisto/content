import demistomock as demisto
from CommonServerPython import *
import urllib3

# Disable insecure warnings
urllib3.disable_warnings()

""" CONSTANTS """

DATE_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
VENDOR = "NetBox"
PRODUCT = "IRM"

LOG_TYPES = ["journal-entries", "object-changes"]
DEFAULT_LIMIT = "1000"
MAX_ERROR_MESSAGE_LENGTH = 1000

NETBOX_VERSION_4_1_AND_ABOVE = "v4.1 and above"
NETBOX_VERSION_BELOW_4_1 = "Below v4.1"
DEFAULT_NETBOX_VERSION = NETBOX_VERSION_4_1_AND_ABOVE

# API path (relative to '<server>/api') of each log type, per NetBox version.
# NetBox v4.1 moved the change logging resources (object-changes) from 'extras' to 'core':
# https://netboxlabs.com/docs/netbox/en/stable/release-notes/version-4.1/
LOG_TYPE_PATHS_BY_VERSION = {
    NETBOX_VERSION_4_1_AND_ABOVE: {
        "journal-entries": "extras/journal-entries",
        "object-changes": "core/object-changes",
    },
    NETBOX_VERSION_BELOW_4_1: {
        "journal-entries": "extras/journal-entries",
        "object-changes": "extras/object-changes",
    },
}

""" CLIENT CLASS """


class Client(BaseClient):
    """
    Client class to interact with the service API
    """

    def __init__(self, base_url: str, netbox_version: str = DEFAULT_NETBOX_VERSION, **kwargs):
        super().__init__(base_url=base_url, **kwargs)
        if netbox_version not in LOG_TYPE_PATHS_BY_VERSION:
            raise DemistoException(
                f"Invalid NetBox version '{netbox_version}'. Valid values are: {', '.join(LOG_TYPE_PATHS_BY_VERSION)}."
            )
        self.log_type_paths = LOG_TYPE_PATHS_BY_VERSION[netbox_version]
        demisto.debug(f"NetBox version: '{netbox_version}', using API paths: {self.log_type_paths}")

    def http_request(self, url_suffix=None, full_url=None, params=None):
        demisto.debug(f"Sending GET request. url_suffix: '{url_suffix}', full_url: '{full_url}', params: {params}")
        response = self._http_request(method="GET", url_suffix=url_suffix, full_url=full_url, params=params)
        demisto.debug(
            f"Received response with {len(response.get('results', []))} results, "
            f"count: {response.get('count')}, next: {response.get('next')}"
        )
        return response

    def search_events(self, log_type: str, limit: int, prev_id: int = 0, ordering: str = "") -> tuple[int, list[dict[str, Any]]]:
        """
        Searches for NetBox events of the given log type.
        Args:
            log_type: str, The log type to request (one of LOG_TYPES).
            limit: int, the limit of the results to return.
            prev_id: int, The id of the first event to fetch.
            ordering: str, The ordering of the results to return.
        Returns:
            int: The id of the next event to fetch.
            list: A list containing the events
        """
        demisto.debug(f"Searching '{log_type}' events. limit: {limit}, prev_id: {prev_id}, ordering: '{ordering}'")
        next_id = prev_id
        results: list[dict] = []

        next_page = True
        params = {
            "limit": limit,
            "ordering": ordering,
            "id__gte": next_id,
        }

        while next_page and len(results) < limit:
            full_url = next_page if type(next_page) is str else ""
            response = self.http_request(url_suffix=self.log_type_paths[log_type], full_url=full_url, params=params)

            results += response.get("results", [])

            next_page = response.get("next")
            params = {}

            if results:
                next_id = results[-1]["id"] + 1

        demisto.debug(f"Found {len(results)} '{log_type}' events (returning up to {limit}), next id: {next_id}")
        return next_id, results[:limit]

    def get_first_fetch_id(self, log_type: str, params: dict[str, Any]) -> int | None:
        """
        Sets the first fetch id for log type.
        Args:
            log_type: str, the log type to fetch.
            params: dict, the params to send to the API.
        Returns:
            int: The first id to fetch.
        """
        first_log = self.http_request(url_suffix=self.log_type_paths[log_type], params={"ordering": "id", "limit": 1} | params)

        if first_log.get("results"):
            next_run = first_log.get("results")[0].get("id")
        else:
            next_run = None

        demisto.debug(f"First fetch id for '{log_type}' with params {params}: {next_run}")
        return next_run


def truncate_error_message(message: str) -> str:
    """
    Truncates long error messages (e.g. a full HTML page returned by the server) to MAX_ERROR_MESSAGE_LENGTH.
    Args:
        message: str, the error message.
    Returns:
        str: The truncated error message.
    """
    if len(message) <= MAX_ERROR_MESSAGE_LENGTH:
        return message
    return f"{message[:MAX_ERROR_MESSAGE_LENGTH]}... (truncated)"


def add_time_key_to_events(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """
    Adds the _time key to the events.
    Args:
        events: list, the events to add the time key to.
    Returns:
        list: The events with the _time key.
    """
    for event in events:
        if event.get("created"):
            event["_time"] = event.get("created")
        elif event.get("time"):
            event["_time"] = event.get("time")

    return events


def test_module_command(client: Client) -> str:
    """
    Tests API connectivity and authentication'
    When 'ok' is returned it indicates the integration works like it is supposed to and connection to the service is
    successful.
    Raises exceptions if something goes wrong.
    Args:
        client (Client): NetBox client to use.
    Returns:
        str: 'ok' if test passed, anything else will raise an exception and will fail the test.
    """
    for log_type in LOG_TYPES:
        try:
            client.search_events(log_type=log_type, limit=1)

        except DemistoException as e:
            if "Forbidden" in str(e):
                return "Authorization Error: make sure API Key is correctly set"
            if e.res is not None and e.res.status_code == 404:
                return (
                    f"The '{log_type}' endpoint was not found (404). "
                    "Make sure the 'NetBox Version' parameter matches the version of the NetBox server."
                )
            raise

    return "ok"


def get_events_command(client: Client, limit: int) -> tuple[list[dict[str, Any]], CommandResults]:
    """
    Gets all the events from the NetBox API for each log type.
    Args:
        client (Client): NetBox client to use.
        limit: int, the limit of the results to return per log_type.
    Returns:
        list: A list containing the events
        CommandResults: A CommandResults object that contains the events in a table format.
    """
    events: list[dict] = []
    hr = ""
    for log_type in LOG_TYPES:
        _, events_ = client.search_events(log_type=log_type, limit=limit)
        if events_:
            hr += tableToMarkdown(name=f"{log_type} Events", t=events_)
            events += events_
        else:
            hr += f"No events found for {log_type}.\n"

    return events, CommandResults(readable_output=hr)


def fetch_events_command(
    client: Client, max_fetch: int, last_run: dict[str, int | None], first_fetch_time: str
) -> tuple[dict[str, int | None], list[dict[str, Any]]]:
    """
    Args:
        client (Client): NetBox client to use.
        max_fetch (int): The maximum number of events to fetch per log type.
        last_run (dict): A dict with a keys containing the first event id to fetch for each log type.
        first_fetch_time (str): In case of first fetch, fetch events from this date.
    Returns:
        dict: Next run dictionary containing the ids of the next events to fetch.
        list: List of events that will be created in XSIAM.
    """
    demisto.debug(f"Starting fetch. last_run: {last_run}, max_fetch: {max_fetch}, first_fetch_time: {first_fetch_time}")
    # In the first fetch, get the ids for the first fetch time
    params = {
        "journal-entries": {"created_after": first_fetch_time},
        "object-changes": {"time_after": first_fetch_time},
    }
    for log_type in LOG_TYPES:
        if last_run.get(log_type) is None:
            last_run[log_type] = client.get_first_fetch_id(log_type=log_type, params=params[log_type])

    next_run = last_run.copy()
    events = []

    for log_type in LOG_TYPES:
        prev_id = last_run[log_type]
        if prev_id is None:
            demisto.debug(f"No '{log_type}' events found since the first fetch time, skipping.")
            continue
        next_run[log_type], events_ = client.search_events(
            log_type=log_type,
            limit=max_fetch,
            ordering="id",
            prev_id=prev_id,
        )
        demisto.debug(f"Fetched {len(events_)} '{log_type}' events.")
        events += events_

    demisto.info(f"Fetched events with ids: {', '.join(f'{log_type}: {id_}' for log_type, id_ in last_run.items())}.")

    # Save the next_run as a dict with the last_fetch key to be stored
    demisto.info(f"Setting next run with ids: {', '.join(f'{log_type}: {id_}' for log_type, id_ in next_run.items())}.")
    return next_run, events


""" MAIN FUNCTION """


def main() -> None:  # pragma: no cover
    """
    main function, parses params and runs command functions
    """

    params = demisto.params()
    args = demisto.args()
    command = demisto.command()
    api_key = params.get("credentials", {}).get("password")
    base_url = urljoin(params.get("url"), "/api")
    netbox_version = params.get("netbox_version") or DEFAULT_NETBOX_VERSION
    verify_certificate = not params.get("insecure", False)
    proxy = params.get("proxy", False)

    # How much time before the first fetch to retrieve events
    first_fetch_time: datetime = arg_to_datetime(
        arg=params.get("first_fetch", "3 days"),
        arg_name="First fetch time",
        required=True,
    )  # type: ignore   # datetime.datetime(2022, 1, 1, 00, 00, 00, 0)
    first_fetch_time_strftime = first_fetch_time.strftime(DATE_FORMAT)  # 2022-01-01T00:00:00Z

    demisto.debug(f"Command being called is {command}")
    try:
        headers = {"Authorization": f"Token {api_key}"}
        client = Client(base_url=base_url, netbox_version=netbox_version, verify=verify_certificate, headers=headers, proxy=proxy)

        if command == "test-module":
            # This is the call made when pressing the integration Test button.
            result = test_module_command(client)
            return_results(result)

        elif command == "netbox-get-events":
            should_push_events = argToBoolean(args.get("should_push_events"))
            events, results = get_events_command(
                client,
                limit=arg_to_number(args.get("limit", DEFAULT_LIMIT)),  # type: ignore
            )
            return_results(results)

            if should_push_events:
                events = add_time_key_to_events(events)
                demisto.debug(f"Sending {len(events)} events to XSIAM.")
                send_events_to_xsiam(events, vendor=VENDOR, product=PRODUCT)

        elif command == "fetch-events":
            last_run = demisto.getLastRun()
            next_run, events = fetch_events_command(
                client=client,
                max_fetch=arg_to_number(params.get("max_fetch", DEFAULT_LIMIT)),  # type: ignore
                last_run=last_run,
                first_fetch_time=first_fetch_time_strftime,
            )

            events = add_time_key_to_events(events)
            demisto.debug(f"Sending {len(events)} events to XSIAM.")
            send_events_to_xsiam(events, vendor=VENDOR, product=PRODUCT)
            # saves next_run for the time fetch-events is invoked
            demisto.setLastRun(next_run)

    # Log exceptions and return errors
    except Exception as e:
        demisto.debug(f"Failed to execute {command} command. Full error: {str(e)}")
        return_error(f"Failed to execute {command} command.\nError:\n{truncate_error_message(str(e))}")


""" ENTRY POINT """

if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
