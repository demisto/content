import base64
from urllib.parse import quote

import demistomock as demisto
import urllib3
from CommonServerPython import *

MIN_FETCH = 1
MAX_FETCH = 10_000
MAX_EVENTS_API_CALL = 500  # As a limitation of the API, we can only retrieve 500 events at a time
# Disable insecure warnings
urllib3.disable_warnings()

""" CONSTANTS """

DATE_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
DATE_FORMAT_FOR_TOKEN = "%m/%d/%Y, %H:%M:%S"
VENDOR = "Druva"
PRODUCT = "Druva"

""" CLIENT CLASS """


class Client(BaseClient):
    def __init__(self, base_url: str, client_id: str, secret_key: str, max_fetch: int, verify: bool, proxy: bool):
        super().__init__(base_url=base_url, verify=verify, proxy=proxy)
        self.credentials = f"{client_id}:{secret_key}"
        self.max_fetch = max_fetch
        self._max_fetch_validation()
        self.login()

    def login(self):
        """
        In this method, the validity of the Access Token is checked, since the Access Token has a 30 minutes validity period.
        Refreshes the token as needed.
        """
        now = datetime.utcnow()

        if (cache := get_integration_context()) and (token := cache.get("Token")):
            expiration_time = datetime.strptime(cache["expiration_time"], DATE_FORMAT_FOR_TOKEN)

            # check if token is still valid, and use the old one. otherwise regenerate a new one
            if (seconds_left := (expiration_time - now).total_seconds()) > 0:
                demisto.debug(f"No need to regenerate the token, it is still valid for {seconds_left} more seconds")
                self._set_headers(token)
                return

        demisto.debug("IntegrationContext token cache is empty or token has expired, regenerating a new token")
        raw_token, expires_in_seconds = self._refresh_access_token()
        self._set_headers(raw_token)

        set_integration_context(
            {
                "Token": raw_token,
                "expiration_time": (
                    now + timedelta(seconds=(expires_in_seconds - 60))  # decreasing 60s from token expiry for safety
                ).strftime(DATE_FORMAT_FOR_TOKEN),
            }
        )

    def _refresh_access_token(self) -> tuple[str, int]:
        """
        Since the validity of the Access Token is 30 minutes, this method refreshes it and returns the new token json.
        returns:
            - the token
            - the expiration in seconds
        """
        credentials = base64.b64encode(self.credentials.encode()).decode("utf-8")

        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
            "Authorization": f"Basic {credentials}",
        }
        data = {"grant_type": "client_credentials", "scope": "read"}

        try:
            response_json = self._http_request(method="POST", url_suffix="/token", headers=headers, data=data)
        except Exception as e:
            # 400 - "invalid_grant" - reason: invalid Server URL, Client ID or Secret Key.
            if "invalid_grant" in str(e):
                raise DemistoException(
                    "Error in test-module: Make sure Server URL, Client ID and Secret Key are correctly entered."
                ) from e
            raise
        return response_json["access_token"], response_json["expires_in"]

    def search_events(self, tracker: Optional[str] = None, event_type: str = "InSync events") -> dict:
        """
        Searches for Druva events.

        Args:
            tracker: pointer to the last event we got last time (for InSync events) or pageToken (for Cybersecurity events)
            event_type: type of events to fetch ("InSync events" or "Cybersecurity events")

        Returns:
            dict: List of events with tracker/nextPageToken
        """
        demisto.debug(f"This is the tracker/pageToken before encoding: {tracker=}")
        demisto.debug(f"Fetching event type: {event_type}")

        headers = (self._headers or {}) | {"accept": "application/json"}  # self._headers won't really be None, just for mypy

        # Determine the endpoint and parameters based on event type
        if event_type == "Cybersecurity events":
            # Cybersecurity events use v3 API with pageToken
            # Note: When pageToken is provided, no other query parameters are allowed
            if tracker:
                encoded_tracker = quote(tracker, safe="!~*'()")
                demisto.debug(f"after encoding pageToken: {encoded_tracker=}")
                url_suffix = f"/platform/eventmanagement/v3/events?pageToken={encoded_tracker}"
            else:
                url_suffix = "/platform/eventmanagement/v3/events?pageSize=500"
            param_name = "pageToken"
        else:
            # InSync events use v2 API with tracker
            url_suffix = "/insync/eventmanagement/v2/events"
            param_name = "tracker"

            # Add tracker parameter if provided
            if tracker:
                encoded_tracker = quote(tracker, safe="!~*'()")
                demisto.debug(f"after encoding {param_name}: {encoded_tracker=}")
                url_suffix += f"?{param_name}={encoded_tracker}"

        try:
            response = self._http_request(
                method="GET",
                url_suffix=url_suffix,
                headers=headers,
            )
        except Exception as e:
            # 403 - "User is not authorized to access this resource with an explicit deny" - reason: tracker is expired
            # 400 - "Invalid tracker"
            raise DemistoException(f"Error in search-events: {e!s}") from e

        # Normalize response: Cybersecurity events use 'nextPageToken', InSync events use 'tracker'
        if event_type == "Cybersecurity events" and "nextPageToken" in response:
            response["tracker"] = response.get("nextPageToken")

        return response

    def _set_headers(self, token: str):
        """
        This method is called during the client's building or when a new token is generated since the old one has expired.
        """
        self._headers = {"Authorization": f"Bearer {token}"}

    def _max_fetch_validation(self):
        if self.max_fetch > MAX_FETCH or self.max_fetch < MIN_FETCH:
            raise DemistoException(f"The maximum number of events per fetch should be between 1 - {MAX_FETCH}")


def test_module(client: Client, event_types: list[str]) -> str:
    """
    Tests API connectivity and authentication
    When 'ok' is returned it indicates the integration works like it is supposed to and connection to the service is
    successful.
    Raises exceptions if something goes wrong.

    Args:
        client (Client): Druva client to use.
        event_types (list[str]): List of event types to test.
    Returns:
        str: 'ok' if test passed, anything else will raise an exception and will fail the test.
    """
    # Test with the first configured event type
    event_type = event_types[0] if event_types else "InSync events"
    get_events(client=client, event_type=event_type)
    return "ok"


def get_events(client: Client, event_type: str, tracker: Optional[str] = None) -> tuple[list[dict], str]:
    """
    Gets events from Druva API in one batch (max 500), if a tracker is given, the API returns events starting from its timestamp.
    There will be no changes to the tracker if no events occur.
    Args:
        client: Druva client to use.
        event_type: The type of events to fetch ("InSync events" or "Cybersecurity events").
        tracker: A string received in a previous run, marking the point in time from which we want to fetch.

    Returns:
        Druva's events and tracker
    """

    response = client.search_events(tracker, event_type)

    return response["events"], response["tracker"]


def fetch_events(
    client: Client, last_run: dict[str, str], max_fetch: int, event_types: list[str]
) -> tuple[list[dict], dict[str, str]]:
    """
    Args:
        client (Client): Druva client to use.
        last_run (dict): A dict with a key containing a pointer to the latest event created time we got from last fetch.
        max_fetch (int): The maximum number of events per fetch (applied per event type).
        event_types (list[str]): List of event types to fetch.
    Returns:
        last_run (dict): A dict containing the next tracker (a pointer to the next event).
        events (list): List of events that will be created in XSIAM.
    """
    demisto.debug(f"Last Run: {last_run}")
    demisto.debug(f"Event Types: {event_types}")
    final_events: list[dict] = []

    # Fetch events for each selected event type
    for event_type in event_types:
        demisto.debug(f"Fetching events for type: {event_type} (max {max_fetch} events per type)")
        done_fetching: bool = False
        type_events: list[dict] = []

        while not done_fetching:
            # Backward compatibility: Migrate from old format {"tracker": "..."} to new format {"tracker_<event_type>": "..."}
            # Only "InSync events" (original type) inherits the old tracker; new types start fresh
            if "tracker" in last_run and f"tracker_{event_type}" not in last_run:
                tracker = last_run.get("tracker") if event_type == "InSync events" else None
            else:
                tracker = last_run.get(f"tracker_{event_type}")
            # when fetching events, in case of "Invalid tracker", we catch the exception and restore the same tracker
            try:
                events, new_tracker = get_events(client, event_type, tracker)
            except Exception as e:
                if "Invalid tracker" in str(e):
                    demisto.debug(
                        "The tracker is invalid, catching the error and continuing with the same tracker for the next time."
                    )
                    events, new_tracker = [], tracker  # type:ignore[assignment]
                else:
                    raise e

            # It means there are no more events to retrieve when there are fewer than 500 events
            done_fetching = len(events) < MAX_EVENTS_API_CALL

            # Save the next_run as a dict with the last_fetch key to be stored
            last_run[f"tracker_{event_type}"] = new_tracker or ""

            # Add source_log_type to events before extending
            add_time_and_source_to_events(events, event_type)
            type_events.extend(events)

            # Check if we've reached the per-type max_fetch limit
            if len(type_events) >= max_fetch:
                demisto.debug(f"Reached max_fetch limit of {max_fetch} for {event_type}. Stopping fetch for this type.")
                done_fetching = True

        final_events.extend(type_events)

    return final_events, last_run


""" MAIN FUNCTION """


def add_time_and_source_to_events(events: list[dict], event_type: str):
    """
    Adds the _time and source_log_type keys to the events.
    Args:
        events: list[dict] - list of events to add the fields to.
        event_type: str - type of events ("InSync events" or "Cybersecurity events").
    """
    if events:
        # Determine source_log_type based on event_type
        source_log_type = "cybersecurity_events" if event_type == "Cybersecurity events" else "insync_events"

        for event in events:
            # Handle both timestamp formats: "timestamp" (InSync events) and "timeStamp" (Cybersecurity events)
            timestamp_value = event.get("timestamp") or event.get("timeStamp")
            create_time = arg_to_datetime(timestamp_value)
            event["_time"] = create_time.strftime(DATE_FORMAT)  # type: ignore[union-attr]
            event["source_log_type"] = source_log_type


def main() -> None:  # pragma: no cover
    """
    main function, parses params and runs command functions
    """

    params = demisto.params()
    args = demisto.args()
    command = demisto.command()
    proxy = params.get("proxy", False)
    verify_certificate = not params.get("insecure", False)
    max_fetch = arg_to_number(params.get("max_fetch")) or MAX_FETCH
    event_types_param = argToList(params.get("event_types")) or ["InSync events"]

    demisto.debug(f"Command being called is {command}")
    try:
        client = Client(
            base_url=params["url"],
            client_id=params["credentials"]["identifier"],
            secret_key=params["credentials"]["password"],
            max_fetch=max_fetch,
            verify=verify_certificate,
            proxy=proxy,
        )

        if command == "test-module":
            # This is the call made when pressing the integration Test button.
            return_results(test_module(client, event_types_param))

        elif command == "druva-get-events":
            event_types_arg = argToList(args.get("event_types")) or ["InSync events"]
            all_events: list[dict] = []
            trackers: dict[str, str] = {}
            readable_parts: list[str] = []

            # Fetch events for each selected event type
            for event_type in event_types_arg:
                demisto.debug(f"Fetching events for type: {event_type}")
                events, tracker = get_events(client, event_type, args.get("tracker"))

                # Add time and source_log_type to events
                add_time_and_source_to_events(events, event_type)
                all_events.extend(events)
                trackers[f"tracker_{event_type}"] = tracker

                # Add a separate table for each event type
                readable_parts.append(tableToMarkdown(f"{event_type} ({len(events)} events):", events))

            # Convert trackers dict to list of dicts for table display
            tracker_list = [
                {"Event Type": key.replace("tracker_", ""), "Tracker/PageToken": value} for key, value in trackers.items()
            ]
            readable_parts.append(tableToMarkdown("Next Trackers/PageTokens:", tracker_list))

            return_results(
                CommandResults(
                    readable_output="\n".join(readable_parts),
                    outputs=trackers,
                    outputs_prefix=f"{VENDOR}.tracker",
                    outputs_key_field="tracker",
                    replace_existing=True,
                )
            )
            if argToBoolean(args.get("should_push_events", False)):
                send_events_to_xsiam(all_events, vendor=VENDOR, product=PRODUCT)

        elif command == "fetch-events":
            events, next_run = fetch_events(
                client=client, last_run=demisto.getLastRun(), max_fetch=max_fetch, event_types=event_types_param
            )

            send_events_to_xsiam(events, vendor=VENDOR, product=PRODUCT)

            demisto.debug(f"fetched {len(events or [])} events. Setting {next_run=}.")
            demisto.setLastRun(next_run)

    # Log exceptions and return errors
    except Exception as e:
        return_error(f"Failed to execute {command} command.\nError:\n{e!s}")


""" ENTRY POINT """

if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
