import uuid
import demistomock as demisto
from CommonServerPython import *
import urllib3
from typing import Any

# Disable insecure warnings
urllib3.disable_warnings()

""" CONSTANTS """

DATE_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
VENDOR = "hello"
PRODUCT = "world"

""" CLIENT CLASS """


class Client(BaseClient):
    """Client class to interact with the service API

    This Client implements API calls, and does not contain any Demisto logic.
    Should only do requests and return data.
    It inherits from BaseClient defined in CommonServer Python.
    Most calls use _http_request() that handles proxy, SSL verification, etc.
    For this HelloWorld implementation, no special attributes defined
    """

    def search_events(
        self, api_key:str, limit: dict, from_date: str | None = None
    ) -> list[dict]:
        """
        Searches for HelloWorld alerts using the '/get_alerts' API endpoint.
        All the parameters are passed directly to the API as HTTP POST parameters in the request

        Args:
            limit: limit.
            from_date: get events from from_date.

        Returns:
            List[Dict]: the next event
        """
        # TODO: need to add support for selected event types\
        #        need to add support for limit and pagination
        demisto.debug("Starting to fetch events.")
        # use limit & from date arguments to query the API
        params = {
            "after": from_date,
            "key": api_key
        }
        try:
            raw_response = self._http_request(url_suffix="/access-logs", method="GET", params=params)
        except Exception as e:
            demisto.error(f"error when fetching events: {e}")
            
        
            
        return raw_response


def test_module(client: Client, params: dict[str, Any], first_fetch_time: str) -> str:
    """
    Tests API connectivity and authentication
    When 'ok' is returned it indicates the integration works like it is supposed to and connection to the service is
    successful.
    Raises exceptions if something goes wrong.

    Args:
        client (Client): HelloWorld client to use.
        params (Dict): Integration parameters.
        first_fetch_time(str): The first fetch time as configured in the integration params.

    Returns:
        str: 'ok' if test passed, anything else will raise an exception and will fail the test.
    """

    try:
        alert_status = params.get("alert_status", None)

        fetch_events(
            client=client,
            last_run={},
            first_fetch_time=first_fetch_time,
            alert_status=alert_status,
            max_events_per_fetch=1,
        )

    except Exception as e:
        if "Forbidden" in str(e):
            return "Authorization Error: make sure API Key is correctly set"
        else:
            raise e

    return "ok"


def get_events(client: Client, api_key: str, args: dict) -> tuple[List[Dict], CommandResults]:
    """Gets events from API

    Args:
        client (Client): The client
        alert_status (str): status of the alert to search for. Options are: 'ACTIVE' or 'CLOSED'.
        args (dict): Additional arguments

    Returns:
        dict: Next run dictionary containing the timestamp that will be used in ``last_run`` on the next fetch.
        list: List of events that will be created in XSIAM.
    """
    limit = args.get("limit", 50)
    from_date = args.get("from_date")
    events = client.search_events(
        api_key=api_key,
        limit=limit,
        from_date=from_date,
    )
    hr = tableToMarkdown(name="Test Event", t=events)
    return events, CommandResults(readable_output=hr)


def get_timestamp_format(value):
    timestamp: datetime
    if isinstance(value, int):
        return value
    if not isinstance(value, datetime):
        timestamp = dateparser.parse(value)  # type: ignore
    return int(time.mktime(timestamp.timetuple()))


def fetch_events(
    client: Client, last_run: dict[str, str], api_key:str, first_fetch_time, max_events_per_fetch: dict, event_types_to_fetch: list
) -> list[dict]:
    """
    Args:
        client (Client): HelloWorld client to use.
        last_run (dict): A dict with a key containing the latest event created time we got from last fetch.
        first_fetch_time (dict): If last_run is None (first time we are fetching), it contains the timestamp in
            milliseconds on when to start fetching events.
        max_events_per_fetch (dict): number of events per fetch
        event_types_to_fetch (list):
    Returns:
        dict: Next run dictionary containing the timestamp that will be used in ``last_run`` on the next fetch.
        list: List of events that will be created in XSIAM.
    """
    events = client.search_events(
        api_key = api_key,
        limit=max_events_per_fetch,
        from_date=first_fetch_time,
    )
    # demisto.debug(f"Fetched event with id: {prev_id + 1}.")

    # Save the next_run as a dict with the last_fetch key to be stored
    # next_run = {"prev_id": prev_id + 1}
    return events


""" MAIN FUNCTION """


def add_time_to_events(events: List[Dict] | None):
    """
    Adds the _time key to the events.
    Args:
        events: List[Dict] - list of events to add the _time key to.
    Returns:
        list: The events with the _time key.
    """
    if events:
        for event in events:
            create_time = arg_to_datetime(arg=event.get("created_time"))
            event["_time"] = create_time.strftime(DATE_FORMAT) if create_time else None


def main() -> None:  # pragma: no cover
    """
    main function, parses params and runs command functions
    """

    params = demisto.params()
    args = demisto.args()
    command = demisto.command()
    api_key = params.get("api_key", "")
    from_time = params.get("from", "")
    base_url = urljoin(params.get("url"), "/org/api-ua/v1/event-logs/")
    verify_certificate = not params.get("insecure", False)
    event_types_to_fetch = argToList(params.get("event_types_to_fetch", []))
    event_types_to_fetch = [event_type.strip() for event_type in event_types_to_fetch]
    # How much time before the first fetch to retrieve events
    first_fetch_time = get_timestamp_format(from_time)
    
    proxy = params.get("proxy", False)
    max_access_logs_events_per_fetch = params.get("max_access_logs_events_per_fetch", 3000)
    max_assets_logs_events_per_fetch = params.get("max_assets_logs_events_per_fetch", 3000)
    max_drkl_events_per_fetch = params.get("max_drkl_events_per_fetch", 3000)
    max_events_per_fetch = {
        "Access Logs": max_access_logs_events_per_fetch,
        "Assets Logs": max_assets_logs_events_per_fetch,
        "Digital Risk Keywords Logs": max_drkl_events_per_fetch,
    }

    demisto.debug(f"Command being called is {command}")
    try:
        client = Client(base_url=base_url, verify=verify_certificate, proxy=proxy)  # params api_key

        if command == "test-module":
            # This is the call made when pressing the integration Test button.
            result = test_module(client, params, first_fetch_time)
            return_results(result)

        elif command == "decyfir-event-collector-get-events":
            should_push_events = argToBoolean(args.pop("should_push_events"))
            events, results = get_events(client, api_key, demisto.args())
            return_results(results)
            if should_push_events:
                add_time_to_events(events)
                send_events_to_xsiam(events, vendor=VENDOR, product=PRODUCT)

        elif command == "fetch-events":
            last_run = demisto.getLastRun()
            next_run, events = fetch_events(
                client=client,
                last_run=last_run,
                api_key = api_key,
                first_fetch_time=first_fetch_time,
                event_types_to_fetch=event_types_to_fetch,
                max_events_per_fetch=max_events_per_fetch,
            )

            add_time_to_events(events)
            demisto.debug(f"Sending {len(events)} events to XSIAM.")
            send_events_to_xsiam(events, vendor=VENDOR, product=PRODUCT)
            demisto.debug("Sent events to XSIAM successfully")
            demisto.setLastRun(next_run)
            demisto.debug(f"Setting next run to {next_run}.")

    # Log exceptions and return errors
    except Exception as e:
        return_error(f"Failed to execute {command} command.\nError:\n{str(e)}")


""" ENTRY POINT """

if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
