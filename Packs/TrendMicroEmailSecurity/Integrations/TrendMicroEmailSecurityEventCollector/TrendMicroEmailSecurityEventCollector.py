from enum import Enum
import demistomock as demisto
from urllib3 import disable_warnings
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa
import base64

disable_warnings()

""" CONSTANTS """

VENDOR = "trend_micro"
PRODUCT = "email_security"
DATE_FORMAT_EVENT = "%Y-%m-%dT%H:%M:%SZ"
ALL_FIELDS = {
    "action",
    "mailID",
    "sender",
    "genTime",
    "logType",
    "subject",
    "tlsInfo",
    "senderIP",
    "direction",
    "eventType",
    "messageID",
    "recipient",
    "domainName",
    "headerFrom",
    "policyName",
    "eventSubtype",
    "policyAction",
    "deliveredTo",
    "attachments",
    "recipients",
    "headerTo",
    "details",
    "timestamp",
    "size",
    "deliveryTime",
    "reason",
    "embeddedUrls",
}


class EventType(str, Enum):
    ACCEPTED_TRAFFIC = "accepted_traffic"
    BLOCKED_TRAFFIC = "blocked_traffic"
    POLICY_LOGS = "policy_logs"


URL_SUFFIX = {
    EventType.ACCEPTED_TRAFFIC: "/api/v1/log/mailtrackinglog",
    EventType.BLOCKED_TRAFFIC: "/api/v1/log/mailtrackinglog",
    EventType.POLICY_LOGS: "/api/v1/log/policyeventlog",
}


""" CLIENT CLASS """


class NoContentException(Exception):
    """
    Error definition for API response with status code 204
    Makes it possible to identify a specific exception
    that arises from the API and to handle this case correctly
    see `handle_error_no_content` method
    """


class Client(BaseClient):
    """Client class to interact with the service API

    :param base_url (str): server url.
    :param username (str): the account username.
    :param api_key (str): the account api_key.
    :param verify (bool): specifies whether to verify the SSL certificate or not.
    :param proxy (bool): specifies if to use XSOAR proxy settings.
    """

    def __init__(
        self, base_url: str, username: str, api_key: str, verify: bool, proxy: bool
    ):
        authorization_encoded = self._encode_authorization(username, api_key)
        headers = {"Authorization": f"Basic {authorization_encoded}"}

        super().__init__(base_url=base_url, verify=verify, proxy=proxy, headers=headers)

    def _encode_authorization(self, username: str, api_key: str) -> str:
        authorization_bytes = f"{username}:{api_key}".encode()
        return base64.b64encode(authorization_bytes).decode()

    def get_logs(self, event_type: EventType, params: dict):
        return self._http_request(
            "GET",
            url_suffix=URL_SUFFIX[event_type],
            params=params,
            error_handler=self.handle_error_no_content,
            ok_codes=(200, 201, 202, 203),
        )

    def handle_error_no_content(self, res) -> None:
        if res.status_code == 204:
            raise NoContentException("No content")
        self.client_error_handler(res)


""" HELPER FUNCTIONS """


def add_missing_fields_to_event(event: dict):
    for field in tuple(ALL_FIELDS.difference(event.keys())):
        event[field] = None


def convert_datetime_to_without_milliseconds(time_: str) -> str:
    return parse_date_string(time_).strftime(DATE_FORMAT_EVENT)


class Deduplicate:
    def __init__(self, last_ids_fetched: list[str], event_type: EventType) -> None:
        self.is_fetch_time_advanced: bool = False
        self.new_event_ids_suspected: list[str] = []
        self.last_event_ids_suspected: list[str] = last_ids_fetched
        self.event_type: EventType = event_type

    def get_last_time_event(self, events: list[dict]) -> str:
        """
        Extract the latest time from the events list
        """

        latest_time_event = max(
            events,
            key=lambda event: datetime.strptime(
                event["genTime"],
                DATE_FORMAT_EVENT,
            ),
        )
        return latest_time_event["genTime"]

    def update_suspected_duplicate_events_list(self, event: dict, start: str):
        """
        Adds the ID of the event as long as genTime is equal to start
        """
        if not self.is_fetch_time_advanced and (event["genTime"] == start):
            self.new_event_ids_suspected.append(self.generate_id_for_event(event))
        else:
            self.is_fetch_time_advanced = True
            self.new_event_ids_suspected = []

    def get_events_with_duplication_risk(
        self, events: list[dict], latest_time: str
    ) -> list[dict]:
        """
        Returns all events whose genTime is equal to the latest time
        from the list of events returned from the API
        """
        return list(
            filter(
                lambda event: event["genTime"] == latest_time,
                events,
            )
        )

    def generate_id_for_event(self, event: dict) -> str:
        """
        Generate an ID from mailID value for mail tracking type or from messageID for policy type.
        """
        if self.event_type == EventType.POLICY_LOGS:
            return event["messageID"]
        else:
            return event["mailID"]

    def get_event_ids_with_duplication_risk(
        self, events: list[dict], latest_time: str
    ) -> list[str]:
        """
        Generate IDs for each of the events that are at risk as a duplicate
        to save it in the last_run object
        """
        events_with_duplication_risk = self.get_events_with_duplication_risk(
            events, latest_time
        )
        return [
            self.generate_id_for_event(event) for event in events_with_duplication_risk
        ]

    def is_duplicate(self, event: dict, time_from: str) -> bool:
        """
        checks if the event is duplicate
        """
        if event["genTime"] != time_from:
            return False
        if self.generate_id_for_event(event) not in self.last_event_ids_suspected:
            return False

        demisto.debug(f"Encountered an event object that was fetched before, id={self.generate_id_for_event(event)}")
        return True


def calculate_last_run(
    events: list[dict],
    last_run: dict,
    start: str,
    event_type: EventType,
    deduplicate: Deduplicate,
) -> dict:
    """
    Managing the `last_run` object

    - When no events are returned from the API
      the `last_run` object is not updated and remains as it is.

    - When events are returned from the API
      - Updates the from_time according to the latest time from the list of events.
      - Saves the list of event IDs that are suspected of being duplicates.
        and remove it if no returned from the API.
    """
    if not events:
        demisto.debug(f"No Events, No update the last_run for {event_type.value} type")
    else:
        # Time of one of the events that returned later than the `start`
        if deduplicate.is_fetch_time_advanced:
            latest_time = deduplicate.get_last_time_event(events)
            last_run[f"time_{event_type.value}_from"] = latest_time
            last_run[
                f"fetched_event_ids_of_{event_type.value}"
            ] = deduplicate.get_event_ids_with_duplication_risk(events, latest_time)

        # All returned events have a time equal to `start`
        else:
            last_run[f"time_{event_type.value}_from"] = start
            last_run[
                f"fetched_event_ids_of_{event_type.value}"
            ] = deduplicate.new_event_ids_suspected
        demisto.debug(f"Events found, {last_run=}")

    return last_run


def remove_sensitive_from_events(event: dict) -> dict:
    """
    removes file names and subject that could be sensitive data
    """
    if event.get("subject", None):
        event["subject"] = "hidden data"

    if (attachments := event.get("attachments")) and isinstance(attachments, list):
        for attachment in attachments:
            if isinstance(attachment, dict) and attachment.get("fileName", None):
                attachment["fileName"] = "hidden data"

    return event


def fetch_by_event_type(
    client: Client,
    start: str,
    end: str,
    limit: int,
    ids_fetched_by_type: list[str],
    event_type: EventType,
    hide_sensitive: bool,
) -> tuple[list[dict], Deduplicate]:
    """
    Fetch the event logs by type.
    The fetch loop continues as long as it does not encounter one of the following:
        - The size of the event list is equal to the limit
        - Calling the api returned No content
        - The nextToken did not return from the api call

    Args:
        client (Client): The client for api calls.
        start (str), end (str): Start and end time period to retrieve logs.
        limit (int): Maximum number of log items to return.
        token (str | None): Token for retrieve the next set of log items.
        ids_fetched_by_type (set[str] | None): ****
        event_type (EventType): The type of event log to return.
        hide_sensitive (bool): ****

    Returns:
        tuple[list[dict], Deduplicate]: List of the logs returned from trend micro, Deduplicate obj
    """

    params = assign_params(
        start=start,
        end=end,
        type=event_type.value,
    )

    deduplicate_management = Deduplicate(ids_fetched_by_type, event_type)
    next_token: str | None = None
    events_res: list[dict] = []
    while len(events_res) < limit:
        params["limit"] = min(limit - len(events_res), 500)

        try:
            res = client.get_logs(event_type, params)
        except NoContentException:
            next_token = None
            demisto.debug(
                f"No {event_type.value} content returned from api, {start=}, {end=}"
            )
            break

        if res.get("logs"):
            # Iterate over each event log, update their `type` and `_time` fields
            for event in res["logs"]:
                # Maintains a uniform format for all events
                # used to check duplicates and save the `genTime` in the `last_run`
                event["genTime"] = convert_datetime_to_without_milliseconds(
                    event["genTime"]
                )
                deduplicate_management.update_suspected_duplicate_events_list(
                    event, start
                )
                if (
                    # The event is only collected if it has not been collected before
                    # Checks whether there is a list of suspected duplicate events,
                    # If there is, then checks that the current event is not in the list of suspicious duplicate events.
                    not deduplicate_management.last_event_ids_suspected
                    or not deduplicate_management.is_duplicate(event, start)
                ):
                    event.update(
                        {"_time": event.get("timestamp"), "logType": event_type.value}
                    )
                    if hide_sensitive:
                        remove_sensitive_from_events(event)

                    add_missing_fields_to_event(event)
                    events_res.append(event)

        else:  # no logs
            demisto.debug(f"No logs were returned for {event_type.value} type")
            next_token = None
            break

        if next_token := res.get("nextToken"):
            params["token"] = urllib.parse.unquote(next_token)
        else:
            next_token = None
            demisto.debug(f"No `nextToken` for {event_type.value=}")
            break

    demisto.debug(f"Done fetching {event_type.value}, got {len(events_res)} events")
    return events_res, deduplicate_management


def parse_start_time(start_time: str = None) -> str:
    """
    set the start time of the first time of the fetch
    """
    if first_fetch := arg_to_datetime(start_time or "1 hours"):
        return first_fetch.strftime(DATE_FORMAT_EVENT)

    # this will not happen because a default value is supplied, here just to keep mypy silent
    raise ValueError("Failed to convert `str` to `datetime` object")


""" COMMAND FUNCTIONS """


def test_module(client: Client):
    """
    Testing we have a valid connection to trend_micro.
    """
    try:
        client.get_logs(
            EventType.POLICY_LOGS,
            {
                "limit": 1,
                "start": parse_start_time("6 hours"),
                "end": datetime.now().strftime(DATE_FORMAT_EVENT),
            },
        )
        demisto.debug("test module: got logs")
    except NoContentException:
        # This type of error is raised when events are not returned, but the API call was successful,
        # therefore `ok` will be returned
        demisto.debug("test module: got no logs, but connection is successful")

    return "ok"


def fetch_events_command(
    client: Client,
    args: dict[str, str],
    first_fetch: str,
    last_run: dict,
) -> tuple[list[dict], dict]:
    """
    Args:
        client (Client): The client for api calls.
        args (dict[str, str]): The args.
        first_fetch (str): The first fetch time.
        last_run (dict): The last run dict.

    Returns:
        tuple[list[dict], dict]: List of all event logs of all types,
                                 The updated `last_run` obj.
    """
    hide_sensitive = argToBoolean(args.get("hide_sensitive", True))
    time_to = datetime.now()
    limit: int = arg_to_number(args.get("max_fetch", "5000"))  # type: ignore[assignment]

    events: list[dict] = []
    new_last_run: dict[str, str] = {}
    for event_type in EventType:
        time_from = last_run.get(f"time_{event_type.value}_from") or first_fetch
        ids_fetched_by_type = last_run.get(
            f"fetched_event_ids_of_{event_type.value}", []
        )

        events_by_type, deduplicate_management = fetch_by_event_type(
            client=client,
            start=time_from,
            end=time_to.strftime(DATE_FORMAT_EVENT),
            limit=limit,
            ids_fetched_by_type=ids_fetched_by_type,
            event_type=event_type,
            hide_sensitive=hide_sensitive,
        )

        events.extend(events_by_type)

        last_run_for_type = calculate_last_run(
            events=events_by_type,
            last_run=last_run,
            start=time_from,
            event_type=event_type,
            deduplicate=deduplicate_management,
        )
        new_last_run.update(last_run_for_type)
    demisto.debug(f"Done fetching, got {len(events)} events.")

    return events, new_last_run


def main() -> None:  # pragma: no cover
    params = demisto.params()
    args = demisto.args()

    base_url = params["url"].strip("/")
    username = params["credentials"]["identifier"]
    api_key = params["credentials"]["password"]
    verify = not params.get("insecure", False)
    proxy = params.get("proxy", False)
    first_fetch = parse_start_time()

    should_push_events = argToBoolean(args.get("should_push_events", False))

    command = demisto.command()
    try:
        client = Client(
            base_url=base_url,
            username=username,
            api_key=api_key,
            verify=verify,
            proxy=proxy,
        )

        if command == "test-module":
            should_update_last_run = False
            return_results(test_module(client))

        elif command == "trend-micro-get-events":
            should_update_last_run = False
            since = parse_start_time(args.get("since") or "1 days")
            events, _ = fetch_events_command(client, args, since, last_run={})

            # By default return as an md table
            # when the argument `should_push_events` is set to true
            # will also be returned as events
            return_results(
                CommandResults(readable_output=tableToMarkdown("Events:", events))
            )

        elif command == "fetch-events":
            should_push_events = True
            should_update_last_run = True
            last_run = demisto.getLastRun()
            events, last_run = fetch_events_command(
                client, params, first_fetch, last_run=last_run
            )

        else:
            raise NotImplementedError(f"Command {command} is not implemented.")

        if should_push_events:
            send_events_to_xsiam(events=events, vendor=VENDOR, product=PRODUCT)
            demisto.debug(f"{len(events)} events were pushed to XSIAM")

            if should_update_last_run:
                demisto.setLastRun(last_run)
                demisto.debug(f"set {last_run=}")

    except Exception as e:
        return_error(
            f"Failed to execute {command} command. Error in TrendMicro EmailSecurity Event Collector Integration [{e}]."
        )


""" ENTRY POINT """

if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
