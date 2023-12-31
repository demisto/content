import demistomock as demisto
from CommonServerPython import *
from AkamaiGuardicoreApiModule import *


""" CONSTANTS """

MAX_FETCH = 1000
VENDOR = "akamai"
PRODUCT = "guardicore"


""" CLIENT CLASS """


class Client(AkamaiGuardicoreClient):
    """
    Client for Akamai Guardicore Event Collector
    """

    def get_events(self, start_time, end_time, limit, offset) -> dict[str, Any]:
        """
        Get events from Guardicore API using the incidents endpoint.
        """
        params = {
            "from_time": start_time,
            "to_time": end_time,
            "limit": limit,
            "offset": offset,
            "sort": "start_time",
        }
        return self.http_request(method="GET", url_suffix="/incidents", params=params)


""" HELPER FUNCTIONS """


def add_time_to_events(events: list[dict]) -> None:
    """Adds the _time key to the events.

    Args:
        events: list[dict] - list of events to add the _time key to.

    Returns:
        None
    """
    if events:
        [
            event.update({"_time": timestamp_to_datestring(event["start_time"])})
            for event in events
            if "start_time" in event
        ]


def delete_id_key_from_events(events: list[dict]) -> None:
    """Deletes the _id key from the events.

    Args:
        events: list[dict] - list of events to deletes the _id key.

    Returns:
        None
    """
    [event.pop("_id", None) for event in events]


def handle_events_labels(events: list[dict]) -> None:
    """Add the labels to the "destination asset" and "source asset".

    Args:
        events: list[dict] - list of events to handle the labels.

    Returns:
        None
    """
    for event in events:
        destination_asset: dict = event["destination_asset"]
        destination_asset_labels = destination_asset["labels"] = {}

        source_asset: dict = event["source_asset"]
        source_asset_labels = source_asset["labels"] = {}

        labels: list[dict] = event.pop("labels", [])
        for label in labels:
            for asset_id in label.get("asset_ids", []):
                if asset_id == destination_asset.get("vm_id"):
                    destination_asset_labels[label["key"]] = label["value"]

                if asset_id == source_asset.get("vm_id"):
                    source_asset_labels[label["key"]] = label["value"]


def format_events(events: list[dict]) -> None:
    delete_id_key_from_events(events)
    handle_events_labels(events)


def create_last_run(
    events: list[dict], start_time: int, last_events_ids: list[int]
) -> dict:
    if events:
        start_time = events[-1]["start_time"]
        # Since the API returns an event if its start_time is equal to from_time or to_time,
        # it is necessary to save the ids of the events that occurred in the last second
        # to avoid duplication in the next API call.
        # The API refers only to seconds and not to milliseconds, so we divide the time by 1000.
        last_events_ids = [
            event["id"]
            for event in events
            if event["start_time"] // 1000 == start_time // 1000
        ]
    # If no events are returned, we will still use the same start_time,
    # since sometimes it takes time for the events to return in the API.
    return {"from_ts": start_time, "last_events_ids": last_events_ids}


""" COMMAND FUNCTIONS """


def test_module(client: Client) -> str:
    """
    Tests API connectivity and authentication'
    When 'ok' is returned it indicates the integration works like it is supposed to and connection to the service is
    successful.
    Raises exceptions if something goes wrong.
    Args:
        client (Client): Gurdicore client to use.
    Returns:
        str: 'ok' if test passed, anything else will raise an exception and will fail the test.
    """
    args = {"from_date": "1 day", "limit": 1}
    get_events(client, args)

    return "ok"


def get_events(client: Client, args: dict):
    """
    Gets events from Guardicore API.
    """
    start_time = date_to_timestamp(
        arg_to_datetime(args.get("from_date", "1 minute ago"))
    )
    end_time = (
        date_to_timestamp(arg_to_datetime(args.get("to_time")))
        if "to_time" in args
        else int(datetime.now().timestamp() * 1000)
    )
    limit = arg_to_number(args.get("limit")) or MAX_FETCH
    limit = min(limit, MAX_FETCH)
    offset = int(args.get("offset", 0))
    response = client.get_events(start_time, end_time, limit, offset)
    events = response["objects"]
    format_events(events)
    hr = tableToMarkdown(name=f"Found {len(events)} events", t=events)
    return events, CommandResults(readable_output=hr, raw_response=events)


def fetch_events(
    client: Client, params: dict, last_run: dict
) -> tuple[List[dict], dict]:
    """
    Fetches events from Guardicore API.
    """
    start_time = date_to_timestamp(
        arg_to_datetime(last_run.get("from_ts", "1 minute ago"))
    )
    end_time = int(datetime.now().timestamp() * 1000)
    demisto.debug(
        f"Getting events from: {timestamp_to_datestring(start_time)}, till: {timestamp_to_datestring(end_time)}"
    )
    offset = arg_to_number(last_run.get("offset")) or 0
    limit = arg_to_number(params.get("max_events_per_fetch")) or MAX_FETCH
    limit = min(limit, MAX_FETCH)

    response = client.get_events(start_time, end_time, limit, offset)
    events: list = response["objects"]
    format_events(events)
    last_events_ids = last_run.get("last_events_ids", [])
    if last_events_ids:
        events = [event for event in events if event["id"] not in last_events_ids]
    demisto.debug(f"Fetched {len(events)} events.")

    last_run = create_last_run(events, start_time, last_events_ids)

    return events, last_run


""" MAIN FUNCTION """


def main() -> None:  # pragma: no cover
    """
    main function, parses params and runs command functions
    """

    params = demisto.params()
    args = demisto.args()
    command = demisto.command()
    username = params.get("credentials", {}).get("identifier")
    password = params.get("credentials", {}).get("password")
    base_url = urljoin(params.get("url"), "/api/v3.0")
    verify_certificate = not params.get("insecure", False)
    proxy = params.get("proxy", False)

    demisto.debug(f"Command being called is {command}")
    try:
        client = Client(
            username=username,
            password=password,
            base_url=base_url,
            proxy=proxy,
            verify=verify_certificate,
        )

        if command == "test-module":
            # This is the call made when pressing the integration Test button.
            result = test_module(client)
            return_results(result)

        if command == f"{PRODUCT}-get-events":
            should_push_events = argToBoolean(args.get("should_push_events", False))
            events, results = get_events(client, args)
            return_results(results)
            if should_push_events:
                add_time_to_events(events)
                send_events_to_xsiam(events, vendor=VENDOR, product=PRODUCT)

        elif command == "fetch-events":
            last_run = demisto.getLastRun() or {}
            events, new_last_run = fetch_events(client, params, last_run)
            add_time_to_events(events)

            send_events_to_xsiam(events, vendor=VENDOR, product=PRODUCT)
            demisto.debug(f"Set new last run with: {new_last_run}")
            demisto.setLastRun(new_last_run)

    # Log exceptions and return errors
    except Exception as e:
        return_error(f"Failed to execute {command} command.\nError:\n{str(e)}")


""" ENTRY POINT """

if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
