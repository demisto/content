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
        self, prev_id: int, alert_status: None | str, limit: int, from_date: str | None = None, default_Protocol: str = "UDP"
    ) -> List[Dict]:  # noqa: E501
        """
        Searches for HelloWorld alerts using the '/get_alerts' API endpoint.
        All the parameters are passed directly to the API as HTTP POST parameters in the request

        Args:
            prev_id: previous id that was fetched.
            alert_status:
            limit: limit.
            from_date: get events from from_date.

        Returns:
            List[Dict]: the next event
        """
        # use limit & from date arguments to query the API
        return [
            {
                "id": prev_id + 1,
                "created_time": datetime.now().isoformat(),
                "description": f"This is test description {prev_id + 1}",
                "alert_status": alert_status,
                "protocol": default_Protocol,
                "t_port": prev_id + 1,
                "custom_details": {
                    "triggered_by_name": f"Name for id: {prev_id + 1}",
                    "triggered_by_uuid": str(uuid.uuid4()),
                    "type": "customType",
                    "requested_limit": limit,
                    "requested_From_date": from_date,
                },
            }
        ]


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


def get_events(client: Client, alert_status: str, args: dict) -> tuple[List[Dict], CommandResults]:
    limit = args.get("limit", 50)
    from_date = args.get("from_date")
    events = client.search_events(
        prev_id=0,
        alert_status=alert_status,
        limit=limit,
        from_date=from_date,
    )
    hr = tableToMarkdown(name="Test Event", t=events)
    return events, CommandResults(readable_output=hr)


def fetch_events(
    client: Client, last_run: dict[str, int], first_fetch_time, alert_status: str | None, max_events_per_fetch: int
) -> tuple[Dict, List[Dict]]:
    """
    Args:
        client (Client): HelloWorld client to use.
        last_run (dict): A dict with a key containing the latest event created time we got from last fetch.
        first_fetch_time: If last_run is None (first time we are fetching), it contains the timestamp in
            milliseconds on when to start fetching events.
        alert_status (str): status of the alert to search for. Options are: 'ACTIVE' or 'CLOSED'.
        max_events_per_fetch (int): number of events per fetch
    Returns:
        dict: Next run dictionary containing the timestamp that will be used in ``last_run`` on the next fetch.
        list: List of events that will be created in XSIAM.
    """
    prev_id = last_run.get("prev_id", None)
    if not prev_id:
        prev_id = 0

    events = client.search_events(
        prev_id=prev_id,
        alert_status=alert_status,
        limit=max_events_per_fetch,
        from_date=first_fetch_time,
    )
    demisto.debug(f"Fetched event with id: {prev_id + 1}.")

    # Save the next_run as a dict with the last_fetch key to be stored
    next_run = {"prev_id": prev_id + 1}
    demisto.debug(f"Setting next run {next_run}.")
    return next_run, events


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
    api_key = params.get("apikey", {}).get("password")
    base_url = urljoin(params.get("url"), "/api/v1")
    verify_certificate = not params.get("insecure", False)

    # How much time before the first fetch to retrieve events
    first_fetch_time = datetime.now().isoformat()
    proxy = params.get("proxy", False)
    alert_status = params.get("alert_status", None)
    max_events_per_fetch = params.get("max_events_per_fetch", 1000)

    demisto.debug(f"Command being called is {command}")
    try:
        headers = {"Authorization": f"Bearer {api_key}"}
        client = Client(base_url=base_url, verify=verify_certificate, headers=headers, proxy=proxy)

        if command == "test-module":
            # This is the call made when pressing the integration Test button.
            result = test_module(client, params, first_fetch_time)
            return_results(result)

        elif command == "hello-world-get-events":
            should_push_events = argToBoolean(args.pop("should_push_events"))
            events, results = get_events(client, alert_status, demisto.args())
            return_results(results)
            if should_push_events:
                add_time_to_events(events)
                send_events_to_xsiam(events, vendor=VENDOR, product=PRODUCT)

        elif command == "fetch-events":
            last_run = demisto.getLastRun()
            next_run, events = fetch_events(
                client=client,
                last_run=last_run,
                first_fetch_time=first_fetch_time,
                alert_status=alert_status,
                max_events_per_fetch=max_events_per_fetch,
            )

            add_time_to_events(events)
            send_events_to_xsiam(events, vendor=VENDOR, product=PRODUCT)
            demisto.setLastRun(next_run)

    # Log exceptions and return errors
    except Exception as e:
        return_error(f"Failed to execute {command} command.\nError:\n{str(e)}")


""" ENTRY POINT """

if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
