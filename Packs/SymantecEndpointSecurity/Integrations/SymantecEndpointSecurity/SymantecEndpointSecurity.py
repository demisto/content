import demistomock as demisto
from urllib3 import disable_warnings
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa
from datetime import datetime
from time import time as get_current_time_in_seconds

disable_warnings()


# CONSTANTS
VENDOR = "symantec"
PRODUCT = "endpoint_security"
DEFAULT_CONNECTION_TIMEOUT = 30
MAX_CHUNK_SIZE_TO_READ = 1024 * 1024 * 150  # 150 MB


class UnauthorizedToken(Exception):
    """
    Exception raised when the authentication token is unauthorized.
    """

    ...


class NextPointingNotAvailable(Exception):
    """
    Exception raised when the next pointing is not available.
    """

    ...


class Client(BaseClient):
    def __init__(
        self,
        base_url: str,
        token: str,
        stream_id: str,
        channel_id: str,
        verify: bool,
        proxy: bool,
        fetch_interval: int,
    ) -> None:

        self.headers: dict[str, str] = {}
        self.token = token
        self.stream_id = stream_id
        self.channel_id = channel_id
        self.fetch_interval = fetch_interval

        super().__init__(
            base_url=base_url,
            verify=verify,
            proxy=proxy,
            timeout=180,
        )

        self.get_token()

    def get_token(self):
        """
        Retrieves an access token using the `token` provided in the params.
        """
        get_token_headers: dict[str, str] = {
            "accept": "application/json",
            "content-type": "application/x-www-form-urlencoded",
            "Authorization": f"Basic {self.token}",
        }
        try:
            res = self._http_request(
                "POST",
                url_suffix="/v1/oauth2/tokens",
                headers=get_token_headers,
                data={},
            )
        except Exception as e:
            demisto.info(f"Failure in get_token method, Error: {e}")
            raise e
        try:
            self.headers = {
                "Authorization": f'Bearer {res["access_token"]}',
                "Accept": "application/x-ndjson",
                "Content-Type": "application/json",
                "Accept-Encoding": "gzip",
            }
        except KeyError:
            raise DemistoException(
                f"The key 'access_token' does not exist in response, Response from API: {res}"
            )

    def test_module(self):
        self._http_request(
            "POST",
            url_suffix=f"/v1/event-export/stream/{self.stream_id}/{self.channel_id}",
            headers=self.headers,
            params={"connectionTimeout": DEFAULT_CONNECTION_TIMEOUT},
            json_data={},
            stream=True,
        )

    def get_events(self, payload: dict[str, str]):
        """
        API call in streaming to fetch events
        """
        return self._http_request(
            method="POST",
            url_suffix=f"/v1/event-export/stream/{self.stream_id}/{self.channel_id}",
            json_data=payload,
            params={"connectionTimeout": DEFAULT_CONNECTION_TIMEOUT},
            resp_type="text",
            headers=self.headers,
        )


def normalize_date_format(date_str: str) -> str:
    """
    Normalize the given date string by removing microseconds.

    Args:
        date_str (str): The input date string to be normalized.

    Returns:
        str: The normalized date string without microseconds.
    """
    try:
        # Parse the original date string with milliseconds
        original_date = datetime.strptime(date_str, "%Y-%m-%dT%H:%M:%S.%fZ")
    except Exception:
        if "." in date_str:
            date_str = f"{date_str.split('.')[0]}Z"
        return date_str

    # Convert back to the desired format without milliseconds
    new_date_str = original_date.strftime("%Y-%m-%dT%H:%M:%SZ")

    return new_date_str


def update_new_integration_context(
    filtered_events: list[dict[str, str]],
    next_hash: str,
    include_last_fetch_events: bool,
    last_integration_context: dict[str, str],
):
    """
    Update the integration context.

    Args:
        filtered_events (list[dict[str, str]]): A list of filtered events.
        next_hash (str): The hash for the next fetch operation.
        include_last_fetch_events (bool): Flag to include last fetched events in the integration context.
        last_integration_context (dict[str, str]): The previous integration context.
    """
    events_suspected_duplicates = (
        extract_events_suspected_duplicates(filtered_events) if filtered_events else []
    )
    latest_event_time = (
        normalize_date_format(max(filtered_events, key=parse_event_time)["time"])
        if filtered_events
        else last_integration_context.get("latest_event_time", "")
    )

    # If the latest event time matches the previous one,
    # extend the suspected duplicates list with events from the previous context,
    # to control deduplication across multiple fetches.
    if latest_event_time == last_integration_context.get("latest_event_time", ""):
        events_suspected_duplicates.extend(
            last_integration_context.get("events_suspected_duplicates", [])
        )

    integration_context = {
        "latest_event_time": latest_event_time,
        "events_suspected_duplicates": events_suspected_duplicates,
        "next_fetch": {"next": next_hash} if next_hash else {},
        "last_fetch_events": filtered_events if include_last_fetch_events else [],
    }

    set_integration_context(integration_context)


def push_events(events: list[dict]):
    """
    Push events to XSIAM.
    """
    send_events_to_xsiam(events=events, vendor=VENDOR, product=PRODUCT)
    demisto.info(f"{len(events)} events were pushed to XSIAM")


def parse_event_time(event) -> datetime:
    """
    Parse the event time from the given event dict to datetime object.
    """
    return datetime.strptime(normalize_date_format(event["time"]), "%Y-%m-%dT%H:%M:%SZ")


def extract_events_suspected_duplicates(events: list[dict]) -> list[str]:
    """
    Extract event IDs of potentially duplicate events.

    This function identifies events with the latest timestamp and considers them as
    potential duplicates. It returns a list of their unique identifiers (UUIDs).
    """

    # Find the maximum event time
    latest_event_time = normalize_date_format(max(events, key=parse_event_time)["time"])

    # Filter all JSONs with the maximum event time
    filtered_events = filter(
        lambda x: normalize_date_format(x["time"]) == latest_event_time, events
    )

    # Extract the event_ids from the filtered events
    events_suspected_duplicates = [x["uuid"] for x in filtered_events]
    return events_suspected_duplicates


def is_duplicate(
    event_id: str,
    event_time: datetime,
    latest_event_time: datetime,
    events_suspected_duplicates: set,
) -> bool:
    """
    Determine if an event is a duplicate based on its time and ID.

    This function checks if an event is considered a duplicate by comparing its
    timestamp with the latest event time and checking if its ID is in the set of
    suspected duplicates.

    Args:
        event_id (str): The unique identifier of the event.
        event_time (datetime): The timestamp of the event.
        latest_event_time (datetime): The timestamp of the last event from the last fetch.
        events_suspected_duplicates (set): A set of event IDs suspected to be duplicates.

    Returns:
        bool: True if the event is a duplicate, False otherwise.
    """
    if event_time < latest_event_time:
        return True
    elif event_time == latest_event_time and event_id in events_suspected_duplicates:
        return True
    return False


def filter_duplicate_events(events: list[dict[str, str]]) -> list[dict[str, str]]:
    """
    Filter out duplicate events from the given list of events.

    Args:
        events (list[dict[str, str]]): A list of event dictionaries, each containing 'uuid' and 'time' keys.

    Returns:
        list[dict[str, str]]: A list of event dictionaries without fear of duplication.
    """
    integration_context = get_integration_context()
    events_suspected_duplicates = set(
        integration_context.get("events_suspected_duplicates", [])
    )
    latest_event_time = (
        integration_context.get("latest_event_time", "2000-01-01T00:00:00.000Z")
        or "2000-01-01T00:00:00.000Z"
    )  # TODO default value
    latest_event_time = datetime.strptime(
        normalize_date_format(latest_event_time), "%Y-%m-%dT%H:%M:%SZ"
    )

    return [
        event
        for event in events
        if not is_duplicate(
            event["uuid"],
            datetime.strptime(
                normalize_date_format(event["time"]), "%Y-%m-%dT%H:%M:%SZ"
            ),
            latest_event_time,
            events_suspected_duplicates,
        )
    ]


def prepare_raw_res_and_load_json(raw_res: str) -> dict:
    raw_res = raw_res.replace("}\n{", ",")
    if not raw_res.startswith("["):
        raw_res = f"[{raw_res}]"
    return json.loads(raw_res)


def get_events_command(client: Client, integration_context: dict):
    events: list[dict] = []
    next_fetch: dict[str, str] = integration_context.get("next_fetch", {})
    try:
        raw_res = client.get_events(payload=next_fetch)
        json_res = prepare_raw_res_and_load_json(raw_res)
    except DemistoException as e:
        if e.res is not None and e.res.status_code == 401:
            demisto.info(
                "Unauthorized access token, trying to obtain a new access token"
            )
            raise UnauthorizedToken
        elif e.res is not None and e.res.status_code == 410:
            raise NextPointingNotAvailable
        raise e

    try:
        demisto.info(f"Number of json in response - len of json res = {len(json_res)}")
    except Exception as e:
        demisto.info(f"Number of json in response - Error: {e}")

    for chunk in json_res:
        events.extend(chunk["events"])
    next_hash = json_res[0].get("next", "") if json_res else ""
    demisto.info(f"Next hash - {next_hash=}")

    if not events:
        demisto.info("Not events returned")
        return

    events_debug = []
    for event in events:
        events_debug.append(
            {
                "uuid": event["uuid"],
                "time": event["time"],
                "log_time": event["log_time"],
            }
        )
    demisto.info(f"uuid time log_time - {events_debug=}")

    demisto.info(f"filtering, len of events {len(events)}")
    filtered_events = filter_duplicate_events(events)
    demisto.info("filtering passed successfully")

    filtered_events.extend(integration_context.get("last_fetch_events", []))

    demisto.info(f"start pushing to XSIAM, len of events {len(filtered_events)}")
    try:
        push_events(filtered_events)
    except Exception as e:
        update_new_integration_context(
            filtered_events=filtered_events,
            next_hash=next_hash,
            include_last_fetch_events=True,
            last_integration_context=integration_context,
        )
        demisto.info(
            f"pushing dev - Failed to push events to XSIAM, The integration_context updated. Error: {e}"
        )
        raise e

    demisto.info("pushing dev - pushing passed successfully")

    demisto.info("updating context dev - start updating integration context")
    update_new_integration_context(
        filtered_events=filtered_events,
        next_hash=next_hash,
        include_last_fetch_events=False,
        last_integration_context=integration_context,
    )


def perform_long_running_loop(client: Client):
    while True:
        # Used to calculate the duration of the fetch run.
        start_run = get_current_time_in_seconds()
        try:
            integration_context = get_integration_context()
            demisto.info(f"Starting new fetch with {integration_context=}")
            get_events_command(client, integration_context=integration_context)

        except UnauthorizedToken:
            try:
                time.sleep(60)
                client.get_token()
            except Exception as e:
                demisto.info("Failed to obtain a new access token")
                time.sleep(60)
                raise e
            continue
        except NextPointingNotAvailable:
            demisto.info("The next hash not available, pop it from integration context")
            integration_context.pop("next_fetch")
            set_integration_context(integration_context)
            continue
        except Exception as e:
            demisto.info(f"Failed to fetch logs from API. Error: {e}")
            raise e

        # Used to calculate the duration of the fetch run.
        end_run = get_current_time_in_seconds()
        # Calculation of the fetch runtime against `client.fetch_interval`
        # If the runtime is less than the `client.fetch_interval` time
        # then it will go to sleep for the time difference
        # between the `client.fetch_interval` and the fetch runtime
        # Otherwise, the next fetch will occur immediately
        if (fetch_sleep := client.fetch_interval - (end_run - start_run)) > 0:
            time.sleep(fetch_sleep)


def test_module(client: Client) -> str:
    try:
        client.test_module()
    except DemistoException as e:
        if e.res is not None and e.res.status_code == 403:
            raise DemistoException(
                f"Authorization Error: make sure the Token is correctly set, Error: {e}"
            )
        else:
            demisto.info(f"Failure in test_module function, Error: {e}")
            raise e
    return "ok"


def main() -> None:  # pragma: no cover
    params = demisto.params()

    host = params["host"]
    token = params["token"]["password"]
    stream_id = params["stream_id"]
    channel_id = params["channel_id"]
    verify = not argToBoolean(params.get("insecure", False))
    proxy = argToBoolean(params.get("proxy", False))
    fetch_interval: int = arg_to_number(params.get("fetch_interval", 60), required=True)  # type: ignore

    command = demisto.command()
    try:
        client = Client(
            base_url=host,
            token=token,
            stream_id=stream_id,
            channel_id=channel_id,
            verify=verify,
            proxy=proxy,
            fetch_interval=fetch_interval,
        )

        if command == "test-module":
            return_results(test_module(client))
        if command == "long-running-execution":
            demisto.info("Starting long running execution")
            perform_long_running_loop(client)
        else:
            raise NotImplementedError(f"Command {command} is not implemented.")

    except Exception as e:
        return_error(
            f"Failed to execute {command} command. Error in Symantec Endpoint Security Integration [{e}]."
        )


""" ENTRY POINT """

if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
