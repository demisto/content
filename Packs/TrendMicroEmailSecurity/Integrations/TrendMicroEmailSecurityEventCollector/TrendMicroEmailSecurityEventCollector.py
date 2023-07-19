from enum import Enum
import demistomock as demisto
import urllib3
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa
import base64

# Disable insecure warnings
urllib3.disable_warnings()  # pylint: disable=no-member

""" CONSTANTS """

VENDOR = "trend_micro"
PRODUCT = "email_security"
DATE_FORMAT = "%Y-%m-%dT%H:%M:%S.%fZ"
DATE_FORMAT_EVENT = "%Y-%m-%dT%H:%M:%SZ"


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

    ...


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


def get_last_time_event(events: list[dict]) -> str:
    latest_time_event = max(
        events,
        key=lambda event: datetime.strptime(
            event["genTime"].strip("Z").split(".")[0] + "Z", DATE_FORMAT_EVENT
        ),
    )
    return latest_time_event["genTime"]


def get_events_with_duplication_risk(
    events: list[dict], latest_time: str
) -> list[dict]:
    return list(filter(lambda event: event["genTime"] == latest_time, events))


def generate_id_for_event(event: dict) -> str:
    return (
        (event.get("messageID", "") or "")
        + (event.get("subject", "") or "")
        + (str(event.get("size", "")) or "")
    )


def get_event_ids_with_duplication_risk(
    events: list[dict], latest_time: str
) -> list[str]:
    """
    Generate an ids for all events to save it in the last_run object
    """
    events_with_duplication_risk = get_events_with_duplication_risk(events, latest_time)
    return [generate_id_for_event(event) for event in events_with_duplication_risk]


def deduplicate(
    events: list[dict], ids_fetched_by_type: list[str] | None, time_from: str
) -> list[dict]:
    if not ids_fetched_by_type:
        return events
    filtered_events: list[dict] = []
    for event in events:
        if event["genTime"] != time_from:
            filtered_events.append(event)
            continue
        if generate_id_for_event(event) not in ids_fetched_by_type:
            filtered_events.append(event)
    demisto.info(f"filtered Events {filtered_events=}")
    return filtered_events


def managing_set_last_run(
    events: list[dict],
    last_run: dict,
    time_to: datetime,
    event_type: EventType,
    next_token: str | None,
) -> dict:
    """
    updating the last_run
    1. No events returned
        - set the time_from to be time_to
        - remove the next_token
        - remove fetched_event_ids
    2. events returned
        - set the time_from to be the latest time from all the events
        - set the next_token to be the nextToken that returned from the API
        - set the fetched_event_ids to be all ids of events that pose a risk of duplication

    Args:
        events (list[dict]): Events returned from the API for the current event type
        last_run (dict): last_run obj
        time_to (datetime): The last time point from the time range on which the api was called
        event_type (EventType): The type of event
        next_token (str | None): Token for the next fetch

    Returns:
        dict: last_run obj updated
    """
    if not events:
        last_run[f"time_{event_type.value}_from"] = time_to.strftime(DATE_FORMAT_EVENT)
        last_run.pop(f"next_token_{event_type.value}", None)
        last_run.pop(f"fetched_event_ids_of_{event_type.value}", None)
        demisto.info(f"No Events{last_run=}")
    else:
        latest_time = get_last_time_event(events)
        last_run[f"time_{event_type.value}_from"] = latest_time
        if next_token:
            last_run[f"next_token_{event_type.value}"] = next_token
        else:
            last_run.pop(f"next_token_{event_type.value}", None)
        last_run[
            f"fetched_event_ids_of_{event_type.value}"
        ] = get_event_ids_with_duplication_risk(events, latest_time)
        demisto.info(f"There is Events{last_run=}")

    return last_run


def order_first_fetch(first_fetch: str) -> str:
    """
    Checks the first_fetch which is not older than 3 days
    """
    first_fetch: Optional[datetime] = arg_to_datetime(first_fetch)
    max_time_ago: Optional[datetime] = arg_to_datetime("4321 minutes")
    if first_fetch and max_time_ago:
        if first_fetch <= max_time_ago:
            raise ValueError(
                "The request retrieves logs created within 72 hours at most before sending the request\n"
                "Please put in the First Fetch Time parameter a value that is at most 72 hours / 3 days"
            )
        return first_fetch.strftime(DATE_FORMAT)
    raise ValueError("No provided `max_fetch` parameter")


def remove_sensitive_from_events(event: dict) -> dict:
    event.pop("subject", None)

    if (attachments := event.get("attachments")) and isinstance(attachments, list):
        for attachment in attachments:
            if isinstance(attachment, dict):
                attachment.pop("fileName", None)

    return event


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
                "start": order_first_fetch("2 days"),
                "end": datetime.now().strftime(DATE_FORMAT_EVENT),
            },
        )
    except NoContentException:
        # This type of error is raised when events are not returned, but the API call was successful,
        # therefore `ok` will be returned
        pass

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
        ids_fetched_by_type = last_run.get(f"fetched_event_ids_of_{event_type.value}")

        events_by_type, next_token = fetch_by_event_type(
            client=client,
            start=time_from,
            end=time_to.strftime(DATE_FORMAT_EVENT),
            limit=limit,
            token=last_run.get(f"next_token_{event_type.value}"),
            ids_fetched_by_type=ids_fetched_by_type,
            event_type=event_type,
            hide_sensitive=hide_sensitive,
        )

        events.extend(events_by_type)

        last_run_for_type = managing_set_last_run(
            events=events_by_type,
            last_run=last_run,
            time_to=time_to,
            next_token=next_token,
            event_type=event_type,
        )
        new_last_run.update(last_run_for_type)
    demisto.debug(f"Done fetching, got {len(events)} events.")

    return events, new_last_run


def fetch_by_event_type(
    client: Client,
    start: str,
    end: str,
    limit: int,
    token: str | None,
    ids_fetched_by_type: list[str] | None,
    event_type: EventType,
    hide_sensitive: bool,
) -> tuple[list[dict], str | None]:
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
        tuple[list[dict], str | None]: List of the logs returned from trend micro,
                                       The token that returned for the next fetch.
    """
    if token:
        token = urllib.parse.unquote(token)

    params = assign_params(
        start=start,
        end=end,
        token=token,
        type=event_type.value,
    )

    next_token: str | None = None
    events_res: list[dict] = []
    while len(events_res) < limit:
        params["limit"] = min(limit - len(events_res), 500)
        demisto.info(f"{len(events_res)}")
        try:
            res = client.get_logs(event_type, params)
        except NoContentException:
            next_token = None
            demisto.debug(
                f"No content returned from api, {start=}, {end=}, {token=}, {event_type.value=}"
            )
            break

        if res.get("logs"):
            # Iterate over each event log, update their `type` and `_time` fields
            for event in res.get("logs"):
                event.update(
                    {"_time": event.get("timestamp"), "logType": event_type.value}
                )
                if hide_sensitive:
                    remove_sensitive_from_events(event)

            events_res.extend(deduplicate(res.get("logs"), ids_fetched_by_type, start))

        else:  # no logs
            next_token = None
            break

        if next_token := res.get("nextToken"):
            params["token"] = urllib.parse.unquote(next_token)
        else:
            next_token = None
            demisto.debug(f"No `nextToken` for {event_type.value=}")
            break

    demisto.debug(f"Done fetching {event_type.value=}, got {len(events_res)} events")
    return events_res, next_token


def main() -> None:  # pragma: no cover
    params = demisto.params()
    args = demisto.args()

    base_url = params["url"].strip("/")
    username = params["credentials"]["identifier"]
    api_key = params["credentials"]["password"]
    verify = not params.get("insecure", False)
    proxy = params.get("proxy", False)
    first_fetch = order_first_fetch(params.get("first_fetch") or "1 days")

    should_push_events = argToBoolean(args.get("should_push_events", False))
    last_run = demisto.getLastRun()

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
            return_results(test_module(client))

        elif command == "trend-micro-get-events":
            should_update_last_run = False
            since = order_first_fetch(params.get("since") or "3 days")
            events, _ = fetch_events_command(client, args, since, last_run={})
            return_results(
                CommandResults(readable_output=tableToMarkdown("Events:", events))
            )

        elif command == "fetch-events":
            should_push_events = True
            should_update_last_run = True
            events, last_run = fetch_events_command(
                client, params, first_fetch, last_run=last_run
            )

        if should_push_events:
            send_events_to_xsiam(events=events, vendor=VENDOR, product=PRODUCT)
            demisto.debug("The events were pushed to XSIAM")

            if should_update_last_run:
                demisto.setLastRun(last_run)
                demisto.debug(f"set {last_run=}")

        else:
            raise NotImplementedError(f"Command {command} is not implemented.")

    except Exception as e:
        return_error(
            f"Failed to execute {command} command. Error in TrendMicro EmailSecurity Event Collector Integration [{e}]."
        )


""" ENTRY POINT """

if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
