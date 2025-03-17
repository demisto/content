import demistomock as demisto
from CommonServerPython import *
import urllib3
from typing import Dict, List, Tuple

# Disable insecure warnings
urllib3.disable_warnings()

""" CONSTANTS """

DATE_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
VENDOR = "NetBox"
PRODUCT = "IRM"

LOG_TYPES = ["journal-entries", "object-changes"]
DEFAULT_LIMIT = "1000"

""" CLIENT CLASS """


class Client(BaseClient):
    """
    Client class to interact with the service API
    """

    def http_request(self, url_suffix=None, full_url=None, params=None):
        return self._http_request(
            method="GET", url_suffix=url_suffix, full_url=full_url, params=params
        )

    def search_events(
        self, url_suffix: str, limit: int, prev_id: int = 0, ordering: str = ""
    ) -> Tuple[int, List[Dict[str, Any]]]:
        """
        Searches for NetBox alerts using the '/<url_suffix>' API endpoint.
        Args:
            url_suffix: str, The API endpoint to request.
            limit: int, the limit of the results to return.
            prev_id: int, The id of the first event to fetch.
            ordering: str, The ordering of the results to return.
        Returns:
            int: The id of the next event to fetch.
            list: A list containing the events
        """
        next_id = prev_id
        results: List[Dict] = []

        next_page = True
        params = {
            "limit": limit,
            "ordering": ordering,
            "id__gte": next_id,
        }

        while next_page and len(results) < limit:
            full_url = next_page if type(next_page) is str else ""
            response = self.http_request(
                url_suffix=url_suffix, full_url=full_url, params=params
            )

            results += response.get("results", [])

            next_page = response.get("next")
            params = {}

            if results:
                next_id = results[-1]["id"] + 1

        return next_id, results[:limit]

    def get_first_fetch_id(self, url_suffix, params):
        """
        Sets the first fetch id for log type.
        Args:
            url_suffix: str, the log type to fetch.
            params: dict, the params to send to the API.
        Returns:
            int: The first id to fetch.
        """
        first_log = self.http_request(
            url_suffix=url_suffix, params={"ordering": "id", "limit": 1} | params
        )

        if first_log.get("results"):
            next_run = first_log.get("results")[0].get("id")
        else:
            next_run = None

        return next_run


def add_time_key_to_events(events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
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

    try:
        client.search_events(url_suffix=LOG_TYPES[0], limit=1)

    except Exception as e:
        if "Forbidden" in str(e):
            return "Authorization Error: make sure API Key is correctly set"
        else:
            raise e

    return "ok"


def get_events_command(
    client: Client, limit: int
) -> Tuple[List[Dict[str, Any]], CommandResults]:
    """
    Gets all the events from the NetBox API for each log type.
    Args:
        client (Client): NetBox client to use.
        limit: int, the limit of the results to return per log_type.
    Returns:
        list: A list containing the events
        CommandResults: A CommandResults object that contains the events in a table format.
    """
    events: List[Dict] = []
    hr = ""
    for log_type in LOG_TYPES:
        _, events_ = client.search_events(url_suffix=log_type, limit=limit)
        if events_:
            hr += tableToMarkdown(name=f"{log_type} Events", t=events_)
            events += events_
        else:
            hr = f"No events found for {log_type}."

    return events, CommandResults(readable_output=hr)


def fetch_events_command(
    client: Client, max_fetch: int, last_run: Dict[str, int], first_fetch_time: str
) -> Tuple[Dict[str, int], List[Dict[str, Any]]]:
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
    # In the first fetch, get the ids for the first fetch time
    params = {
        "journal-entries": {"created_after": first_fetch_time},
        "object-changes": {"time_after": first_fetch_time},
    }
    for log_type in LOG_TYPES:
        if last_run.get(log_type) is None:
            last_run[log_type] = client.get_first_fetch_id(
                url_suffix=log_type, params=params[log_type]
            )

    next_run = last_run.copy()
    events = []

    for log_type in LOG_TYPES:
        if last_run[log_type] is None:
            continue
        next_run[log_type], events_ = client.search_events(
            url_suffix=log_type,
            limit=max_fetch,
            ordering="id",
            prev_id=last_run[log_type],
        )
        events += events_

    demisto.info(
        f'Fetched events with ids: {", ".join(f"{log_type}: {id_}" for log_type, id_ in last_run.items())}.'
    )

    # Save the next_run as a dict with the last_fetch key to be stored
    demisto.info(
        f'Setting next run with ids: {", ".join(f"{log_type}: {id_}" for log_type, id_ in next_run.items())}.'
    )
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
    base_url = urljoin(params.get("url"), "/api/extras")
    verify_certificate = not params.get("insecure", False)
    proxy = params.get("proxy", False)

    # How much time before the first fetch to retrieve events
    first_fetch_time: datetime = arg_to_datetime(
        arg=params.get("first_fetch", "3 days"),
        arg_name="First fetch time",
        required=True,
    )  # type: ignore   # datetime.datetime(2022, 1, 1, 00, 00, 00, 0)
    first_fetch_time_strftime = first_fetch_time.strftime(
        DATE_FORMAT
    )  # 2022-01-01T00:00:00Z

    demisto.debug(f"Command being called is {command}")
    try:
        headers = {"Authorization": f"Token {api_key}"}
        client = Client(
            base_url=base_url, verify=verify_certificate, headers=headers, proxy=proxy
        )

        if command == "test-module":
            # This is the call made when pressing the integration Test button.
            result = test_module_command(client)
            return_results(result)

        elif command == "netbox-get-events":
            should_push_events = argToBoolean(args.get("should_push_events"))
            events, results = get_events_command(
                client, limit=arg_to_number(args.get("limit", DEFAULT_LIMIT))  # type: ignore
            )
            return_results(results)

            if should_push_events:
                events = add_time_key_to_events(events)
                send_events_to_xsiam(events, vendor=VENDOR, product=PRODUCT)

        elif command == 'fetch-events':
            last_run = demisto.getLastRun()
            next_run, events = fetch_events_command(
                client=client,
                max_fetch=arg_to_number(params.get("max_fetch", DEFAULT_LIMIT)),  # type: ignore
                last_run=last_run,
                first_fetch_time=first_fetch_time_strftime,
            )

            events = add_time_key_to_events(events)
            send_events_to_xsiam(events, vendor=VENDOR, product=PRODUCT)
            # saves next_run for the time fetch-events is invoked
            demisto.setLastRun(next_run)

    # Log exceptions and return errors
    except Exception as e:
        return_error(f"Failed to execute {command} command.\nError:\n{str(e)}")


""" ENTRY POINT """

if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
