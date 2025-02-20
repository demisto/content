from requests import Response
import demistomock as demisto
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa
from datetime import datetime
import dateparser
import time


# CONSTANTS
VENDOR = "symantec"
PRODUCT = "endpoint_security"
DEFAULT_CONNECTION_TIMEOUT = 30
MAX_CHUNK_SIZE_TO_READ = 1024 * 1024 * 150  # 150 MB
DATE_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
DELIMITER = "\n"

"""
Sleep time between fetch attempts when an error occurs in the retrieval process,
primarily used to avoid overloading with consecutive API calls
if an error is received from the API.
"""
FETCH_INTERVAL = 60


class UnauthorizedToken(Exception):
    """
    Exception raised when the authentication token is unauthorized.
    """


class NextPointingNotAvailable(Exception):
    """
    Exception raised when the next pointing is not available.
    """


class EmptyResponse(Exception):
    """
    Exception raised when the response from the API is None
    """


class NoEventsReceived(Exception):
    """
    Exception raised when no events received
    """


class Client(BaseClient):
    def __init__(
        self,
        base_url: str,
        token: str,
        stream_id: str,
        channel_id: str,
        verify: bool,
        proxy: bool,
    ) -> None:

        self.headers: dict[str, str] = {}
        self.token = token
        self.stream_id = stream_id
        self.channel_id = channel_id

        super().__init__(
            base_url=base_url,
            verify=verify,
            proxy=proxy,
            timeout=180,
        )

        self._update_access_token_in_headers()

    def _update_access_token_in_headers(self):
        """
        Retrieves an access token using the `token` provided in the params, and updates `self.headers`.
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
            raise DemistoException("Failed getting an access token") from e

        if "access_token" not in res:
            raise DemistoException(
                f"The key 'access_token' does not exist in response, Response from API: {res}",
                res=res,
            )
        self.headers = {
            "Authorization": f'Bearer {res["access_token"]}',
            "Accept": "application/x-ndjson",
            "Content-Type": "application/json",
            "Accept-Encoding": "gzip",
        }

    def get_events(self, payload: dict[str, str]) -> Response:
        """
        API call in streaming to fetch events
        """
        return self._http_request(
            method="POST",
            url_suffix=f"/v1/event-export/stream/{self.stream_id}/{self.channel_id}",
            json_data=payload,
            params={"connectionTimeout": DEFAULT_CONNECTION_TIMEOUT},
            resp_type="response",
            headers=self.headers,
            stream=True,
            ok_codes=[200, 201, 204]
        )


def sleep_if_necessary(last_run_duration: float) -> None:
    """
    Manages the fetch interval by sleeping if necessary.

    This function calculates the fetch runtime against FETCH_INTERVAL.
    If the runtime is less than the FETCH_INTERVAL time, it will sleep
    for the time difference between FETCH_INTERVAL and the fetch runtime.
    Otherwise, the next fetch will occur immediately.
    """
    fetch_sleep = FETCH_INTERVAL - last_run_duration
    if fetch_sleep > 0:
        demisto.debug(f"Sleeping for {fetch_sleep} seconds")
        time.sleep(fetch_sleep)
        return

    demisto.debug("Not sleeping, next fetch will take place immediately")


def normalize_date_format(date_str: str) -> str:
    """
    Normalize the given date string by removing milliseconds.

    Args:
        date_str (str): The input date string to be normalized.

    Returns:
        str: The normalized date string without milliseconds.
    """
    # Parse the original date string with milliseconds
    if not (timestamp := dateparser.parse(date_str)):
        raise DemistoException(f"Failed to parse date string: {date_str}")

    # Convert back to the desired format without milliseconds
    return timestamp.strftime(DATE_FORMAT)


def calculate_next_fetch(
    filtered_events: list[dict[str, str]],
    next_hash: str,
    include_last_fetch_events: bool,
    last_integration_context: dict[str, str],
) -> None:
    """
    Calculate and update the integration context for the next fetch operation.

    - Extracts the time of the latest event
    - Extracts all event IDs with time matching the latest event time
    - If the latest event time matches the latest time from the previous fetch,
      extend the suspected duplicate IDs from the previous fetch.
    - If a push to XSIAM fails, store all events in the `integration_context`
      to be pushed in the next fetch.
    - Update the integration_context

    Args:
        filtered_events (list[dict[str, str]]): A list of filtered events.
        next_hash (str): The hash for the next fetch operation.
        include_last_fetch_events (bool): Flag to include last fetched events in the integration context.
        last_integration_context (dict[str, str]): The previous integration context.
    """

    if filtered_events:
        events_suspected_duplicates = extract_events_suspected_duplicates(
            filtered_events
        )

        # Determine the latest event time: Extract the last time of the filtered event,
        latest_event_time = normalize_date_format(
            max(filtered_events, key=parse_event_time)["log_time"]
        )
    else:
        events_suspected_duplicates = []
        latest_event_time = last_integration_context.get("latest_event_time", "")

    if latest_event_time == last_integration_context.get("latest_event_time", ""):
        # If the latest event time matches the previous one,
        # extend the suspected duplicates list with events from the previous context,
        # to control deduplication across multiple fetches.
        demisto.debug(
            "The latest event time equals the latest event time from the previous fetch,"
            " adding the suspect duplicates from last time"
        )
        events_suspected_duplicates.extend(
            last_integration_context.get("events_suspected_duplicates", [])
        )

    integration_context = {
        "latest_event_time": latest_event_time,
        "events_suspected_duplicates": events_suspected_duplicates,
        "next_fetch": {"next": next_hash} if next_hash else {},
        "last_fetch_events": filtered_events if include_last_fetch_events else [],
    }

    demisto.debug(f"Updating integration context with new data: {integration_context}")
    set_integration_context(integration_context)


def push_events(events: list[dict]):
    """
    Push events to XSIAM.
    """
    demisto.debug(f"Pushing {len(events)} to XSIAM")
    send_events_to_xsiam(events=events, vendor=VENDOR, product=PRODUCT)
    demisto.debug(f"Pushed {len(events)} to XSIAM successfully")


def parse_event_time(event) -> datetime:
    """
    Parse the event time from the given event dict to datetime object.
    """
    return datetime.strptime(normalize_date_format(event["log_time"]), DATE_FORMAT)


def extract_events_suspected_duplicates(events: list[dict]) -> list[str]:
    """
    Extract event IDs of potentially duplicate events.

    This function identifies events with the latest timestamp and considers them as
    potential duplicates. It returns a list of their unique identifiers (UUIDs).
    """

    # Find the maximum event time
    latest_event_time = normalize_date_format(
        max(events, key=parse_event_time)["log_time"]
    )

    # Filter all JSONs with the maximum event time
    filtered_events = filter(
        lambda event: normalize_date_format(event["log_time"]) == latest_event_time,
        events,
    )

    # Extract the event_ids from the filtered events
    return [event["uuid"] for event in filtered_events]


def is_duplicate(
    event_id: str,
    event_time: datetime,
    latest_event_time: datetime,
    events_suspected_duplicates: set[str],
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
        bool: whether the event's time is earlier than the latest, OR
              (its time is identical to the latest AND
              its id is in the list of suspected duplicates)
    """
    if event_time < latest_event_time:
        return True
    elif event_time == latest_event_time and event_id in events_suspected_duplicates:
        return True
    return False


def filter_duplicate_events(
    events: list[dict[str, str]], integration_context: dict
) -> list[dict[str, str]]:
    """
    Filter out duplicate events from the given list of events.

    Args:
        events (list[dict[str, str]]): A list of event dicts, each containing 'uuid' and 'log_time' keys.

    Returns:
        list[dict[str, str]]: A list of event dicts without fear of duplication.
    """
    events_suspected_duplicates = set(
        integration_context.get("events_suspected_duplicates", [])
    )
    latest_event_time = integration_context.get(
        "latest_event_time"
    ) or datetime.min.strftime(DATE_FORMAT)

    latest_event_time = datetime.strptime(
        normalize_date_format(latest_event_time), DATE_FORMAT
    )

    filtered_events: list[dict[str, str]] = []

    for event in events:
        if not is_duplicate(
            event["uuid"],
            datetime.strptime(normalize_date_format(event["log_time"]), DATE_FORMAT),
            latest_event_time,
            events_suspected_duplicates,
        ):
            event["_time"] = event["time"]
            filtered_events.append(event)

    return filtered_events


def extract_events(res: Response) -> tuple[list[dict], str]:
    events: list[dict] = []
    next_hash: str = ""

    if res is None:
        raise EmptyResponse

    if res.status_code == 204:
        raise NoEventsReceived

    for line in res.iter_lines(chunk_size=MAX_CHUNK_SIZE_TO_READ, delimiter=DELIMITER):
        if not line:
            # Consecutive delimeter can cause empty line.
            continue
        json_res = json.loads(line.decode('utf-8'))
        events.extend(json_res.get("events", []))
        next_hash = json_res.get("next", "") if json_res else ""

    return events, next_hash


def get_events_command(client: Client, integration_context: dict) -> None:
    next_fetch: dict[str, str] = integration_context.get("next_fetch", {})

    try:
        res = client.get_events(payload=next_fetch)
        events, next_hash = extract_events(res)
    except DemistoException as e:
        if e.res is not None:
            if e.res.status_code == 401:
                demisto.info(
                    "Unauthorized access token, trying to obtain a new access token"
                )
                raise UnauthorizedToken
            if e.res.status_code == 410:
                raise NextPointingNotAvailable
        raise

    if not events:
        demisto.info("No events received")
        return

    try:
        uuids = [event["uuid"] for event in events]
        demisto.info(f"UUIDs = {uuids}")
    except Exception as e:
        demisto.info(f"Failed to printing the uuids of the events, Error: {e}")

    demisto.debug(f"Starting event filtering. Initial number of events: {len(events)}")
    filtered_events = filter_duplicate_events(events, integration_context)
    demisto.debug(
        f"Filtering completed. Total number of events: {len(filtered_events)}"
    )

    filtered_events.extend(integration_context.get("last_fetch_events", []))
    demisto.debug(
        f"Total number of events after merging with last fetch events: {len(filtered_events)}"
    )

    try:
        push_events(filtered_events)
    except Exception as e:
        # If the push of events to XSIAM fails,
        # the current fetch's events are stored in `integration_context`,
        # ensuring they are pushed in the next fetch operation.
        calculate_next_fetch(
            filtered_events=filtered_events,
            next_hash=next_hash,
            include_last_fetch_events=True,
            last_integration_context=integration_context,
        )
        raise DemistoException(
            "Failed to push events to XSIAM, The integration_context updated"
        ) from e

    calculate_next_fetch(
        filtered_events=filtered_events,
        next_hash=next_hash,
        include_last_fetch_events=False,
        last_integration_context=integration_context,
    )


def perform_long_running_loop(client: Client):
    """
    Manages the fetch process.
    Due to a limitation on Symantec's side,
    the integration is configured as long-running
    since API calls can take over 5 minutes.

    Fetch process:
        - In every iteration except the first,
          fetch is performed with the `next_fetch` argument,
          which acts as a pointer for Symantec.
        - When an error is encountered from Symantec,
          it is handled based on the error type, and before the next iteration,
          the process enters a brief sleep period defined by `FETCH_INTERVAL`
          to avoid overloading with API calls.
    """
    while True:
        # Used to calculate the duration of the fetch run.
        start_timestamp = time.time()
        try:
            integration_context = get_integration_context()
            demisto.info(f"Starting new fetch with {integration_context=}")
            get_events_command(client, integration_context=integration_context)

        except UnauthorizedToken:
            try:
                client._update_access_token_in_headers()
            except Exception as e:
                raise DemistoException("Failed obtaining a new access token") from e

        except NextPointingNotAvailable:
            demisto.debug(
                "Next is pointing to older event which is not available for streaming. "
                "Clearing next_fetch, The integration's dedup mechanism will make sure we don't insert duplicate events. "
                "We will eventually get a different pointer and fetching will overcome this edge case"
            )
            integration_context.pop("next_fetch")
            set_integration_context(integration_context)

        except EmptyResponse:
            demisto.info(
                "Didn't receive any response from streaming endpoint."
            )

        except NoEventsReceived:
            next_fetch_param = integration_context.get("next_fetch", {})
            demisto.info(
                f"No Events stream for {next_fetch_param=}"
            )

        except Exception as e:
            raise DemistoException(f"Failed to fetch logs from API {e}")

        # Used to calculate the duration of the fetch run.
        end_timestamp = time.time()

        sleep_if_necessary(end_timestamp - start_timestamp)


def test_module() -> str:
    """
    The test is performed by obtaining the `access_token` during `Client`'s initialization.
    avoiding the use of `test_module` with get_events due to the one-minute timeout
    set for the `test_module` command by the our server.
    """
    return "ok"


def main() -> None:  # pragma: no cover
    params = demisto.params()

    host = params["host"]
    token = params["token"]["password"]
    stream_id = params["stream_id"]
    channel_id = params["channel_id"]
    verify = not argToBoolean(params.get("insecure", False))
    proxy = argToBoolean(params.get("proxy", False))

    command = demisto.command()
    try:
        client = Client(
            base_url=host,
            token=token,
            stream_id=stream_id,
            channel_id=channel_id,
            verify=verify,
            proxy=proxy,
        )

        if command == "test-module":
            return_results(test_module())
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
