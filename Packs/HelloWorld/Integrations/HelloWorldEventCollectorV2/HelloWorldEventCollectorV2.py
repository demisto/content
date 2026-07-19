import uuid
from datetime import datetime, timezone

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from typing import Any

""" CONSTANTS """

DATE_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
VENDOR = "hello"
PRODUCT = "world"
DEFAULT_MAX_EVENTS_PER_FETCH = 1000
DEFAULT_GET_EVENTS_LIMIT = 50

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
        self,
        prev_id: int,
        alert_status: str | None,
        limit: int,
        from_date: str | None = None,
        default_protocol: str = "UDP",
    ) -> List[Dict]:
        """
        Searches for HelloWorld alerts using the '/get_alerts' API endpoint.
        All the parameters are passed directly to the API as HTTP POST parameters in the request.

        Args:
            prev_id (int): Previous id that was fetched.
            alert_status (str | None): Status of the alert to search for. Options are: 'ACTIVE' or 'CLOSED'.
            limit (int): Maximum number of events to return.
            from_date (str | None): Get events from this date onwards.
            default_protocol (str): The protocol to report for the mocked events.

        Returns:
            List[Dict]: The next event.
        """
        demisto.debug("Starting to fetch events.")
        # use limit & from date arguments to query the API
        return [
            {
                "id": prev_id + 1,
                "created_time": datetime.now(timezone.utc).isoformat(),
                "description": f"This is test description {prev_id + 1}",
                "alert_status": alert_status,
                "protocol": default_protocol,
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
    """Gets events from API

    Args:
        client (Client): The client.
        alert_status (str): Status of the alert to search for. Options are: 'ACTIVE' or 'CLOSED'.
        args (dict): Additional arguments (limit, from_date).

    Returns:
        tuple[List[Dict], CommandResults]:
            - The list of events fetched from the API.
            - The CommandResults object with the human readable output and outputs.
    """
    limit = arg_to_number(args.get("limit")) or DEFAULT_GET_EVENTS_LIMIT
    from_date = args.get("from_date")
    events = client.search_events(
        prev_id=0,
        alert_status=alert_status,
        limit=limit,
        from_date=from_date,
    )
    hr = tableToMarkdown(name="Test Event", t=events)
    return events, CommandResults(
        readable_output=hr,
        outputs_prefix="HelloWorld.Event",
        outputs_key_field="id",
        outputs=events,
    )


def fetch_events(
    client: Client,
    last_run: dict[str, int],
    first_fetch_time: str,
    alert_status: str | None,
    max_events_per_fetch: int,
) -> tuple[Dict, List[Dict]]:
    """
    Args:
        client (Client): HelloWorld client to use.
        last_run (dict): A dict with a key containing the latest event created time we got from last fetch.
        first_fetch_time (str): If last_run is empty (first time we are fetching), it contains the timestamp in
            milliseconds on when to start fetching events.
        alert_status (str | None): Status of the alert to search for. Options are: 'ACTIVE' or 'CLOSED'.
        max_events_per_fetch (int): Number of events per fetch.

    Returns:
        dict: Next run dictionary containing the last id that will be used in ``last_run`` on the next fetch.
        list: List of events that will be created in XSIAM.
    """
    prev_id = last_run.get("prev_id") or 0

    events = client.search_events(
        prev_id=prev_id,
        alert_status=alert_status,
        limit=max_events_per_fetch,
        from_date=first_fetch_time,
    )
    demisto.debug(f"Fetched event with id: {prev_id + 1}.")

    # Save the next_run as a dict with the prev_id key to be stored
    next_run = {"prev_id": prev_id + 1}
    return next_run, events


""" HELPER FUNCTIONS """


def add_time_to_events(events: List[Dict] | None) -> None:
    """
    Adds the _time key to the events in place.

    Args:
        events (List[Dict] | None): List of events to add the _time key to. The list is modified in place.

    Returns:
        None: The events are modified in place.
    """
    if events:
        for event in events:
            create_time = arg_to_datetime(arg=event.get("created_time"))
            event["_time"] = create_time.strftime(DATE_FORMAT) if create_time else None


""" MAIN FUNCTION """


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

    # The first fetch starts from the current time.
    first_fetch_time = datetime.now(timezone.utc).isoformat()
    proxy = params.get("proxy", False)
    alert_status = params.get("alert_status", "")
    max_events_per_fetch = arg_to_number(params.get("max_events_per_fetch")) or DEFAULT_MAX_EVENTS_PER_FETCH

    demisto.debug(f"Command being called is {command}")
    try:
        headers = {"Authorization": f"Bearer {api_key}"}
        client = Client(base_url=base_url, verify=verify_certificate, headers=headers, proxy=proxy)

        if command == "test-module":
            # This is the call made when pressing the integration Test button.
            result = test_module(client, params, first_fetch_time)
            return_results(result)

        elif command == "hello-world-get-events":
            should_push_events = argToBoolean(args.get("should_push_events", False))
            events, results = get_events(client, args.get("status", alert_status), args)
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
            demisto.debug(f"Sending {len(events)} events to XSIAM.")
            send_events_to_xsiam(events, vendor=VENDOR, product=PRODUCT)
            demisto.debug("Sent events to XSIAM successfully")
            demisto.setLastRun(next_run)
            demisto.debug(f"Setting next run to {next_run}.")

    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())
        return_error(f"Failed to execute {command} command.\nError:\n{str(e)}")


""" ENTRY POINT """

if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
