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
URL_SUFFIX = {
    "accepted_traffic": "/api/v1/log/mailtrackinglog",
    "blocked_traffic": "/api/v1/log/mailtrackinglog",
    "policy_logs": "/api/v1/log/policyeventlog",
}
EVENT_TYPES = ("accepted_traffic", "blocked_traffic", "policy_logs")

""" CLIENT CLASS """


class NoContentException(Exception):
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
        authorization_encoded = self.generate_authorization_encoded(username, api_key)
        headers = {"Authorization": f"Basic {authorization_encoded}"}

        super().__init__(base_url=base_url, verify=verify, proxy=proxy, headers=headers)

    def generate_authorization_encoded(self, username: str, api_key: str) -> str:
        authorization_bytes = f"{username}:{api_key}".encode()
        return base64.b64encode(authorization_bytes).decode()

    def get_logs_request(self, event_type: str, params: dict):
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


def managing_set_last_run(
    client: Client,
    len_events: int,
    limit: int,
    last_run: dict,
    time_from: str,
    time_to: datetime,
    event_type: str,
    next_token: str | None,
) -> dict:
    """
    The function handles the following four possible cases:

    1. When `next_token` did not return (there are no more logs in the current time range)
    2. When the number of logs retrieved is less than the limit (there are no more logs in the current time range)
    3. When the number of retrieved logs is equal to the limit and the `next_token` is returned, in this case there are two cases:
        1. In the next api call, no logs are returned (there are no more logs in the current time range)
        2. In the next api call, log returns.

    - When there are no more logs in the current time range,
      the `time_from` for the specific `event_type` is set to `time_to` + 1 second
      and the `next_token` for the event_type is removed.

    - In the case where there are another logs in the current time range,
      the `genTime` of the log from the next api call is set to be the `time_from`
      for the specific `event_type` for the next call and the `next_token` for the specific `event_type`
      is set to be the `next_token` from the function's arguments.

    """

    # the flag using detect if there are more logs in current time range
    no_more_events_in_current_range_time = False

    # In both cases there are no more logs in current range time
    if len_events < limit or not next_token:
        no_more_events_in_current_range_time = True

    else:
        # order the parameters for the api call with limit 1 and the `next_token`,
        # the API call is consumed due ensure there is more logs in current range time
        params = assign_params(
            start=time_from,
            end=time_to.strftime(DATE_FORMAT_EVENT),
            limit=1,
            token=urllib.parse.unquote(next_token),
            type=event_type,
        )

        try:
            event = client.get_logs_request(event_type, params)
        except NoContentException:
            # there are no more logs in current range time
            no_more_events_in_current_range_time = True

    if no_more_events_in_current_range_time:
        # save the time_from for a specific `event_type` for the next fetch
        # the `start` time of the next fetch is time_to + 1 second
        last_run[f"time_{event_type}_from"] = (time_to + timedelta(seconds=1)).strftime(
            DATE_FORMAT_EVENT
        )

        # removing the `next_token` for a specific `event_type` from the `last_run`
        last_run.pop(f"next_token_{event_type}", None)
        return last_run

    # In case returned log from the API call
    last_run[f"time_{event_type}_from"] = event.get("logs")[0]["genTime"]
    last_run[f"next_token_{event_type}"] = next_token

    return last_run


def order_first_fetch(first_fetch: str) -> str:
    """
    Checks the first_fetch which is not older than 3 days
    """
    if arg_to_datetime(first_fetch) <= arg_to_datetime("4321 minutes"):  # type: ignore[operator]
        raise ValueError(
            "The request retrieves logs created within 72 hours at most before sending the request\n"
            "Please put in the First Fetch Time parameter a value that is at most 72 hours / 3 days"
        )
    return arg_to_datetime(first_fetch).strftime(DATE_FORMAT)  # type: ignore[union-attr]


def remove_sensitive_from_events(event: dict) -> dict:
    if "subject" in event:
        del event['subject']

    if (attachments := event.get("attachments")) and isinstance(attachments, list):
        attachments = [{k: v for k, v in attachment.items() if k != "fileName"} for attachment in attachments]
        event.update({"attachments": attachments})

    return event


""" COMMAND FUNCTIONS """


def test_module(client: Client):
    """
    Testing we have a valid connection to trend_micro.
    """
    first_fetch = order_first_fetch("2 days")
    try:
        client.get_logs_request(
            "policy_logs",
            {
                "limit": 1,
                "start": first_fetch,
                "end": datetime.now().strftime(DATE_FORMAT_EVENT),
            },
        )
    except NoContentException:
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
    limit: int = arg_to_number(args.get("max_fetch", "1000"))  # type: ignore[assignment]

    events: list[dict] = []
    new_last_run: dict[str, str] = {}
    for event_type in EVENT_TYPES:
        time_from = last_run.get(f"time_{event_type}_from") or first_fetch

        events_by_type, next_token = fetch_by_event_type(
            client=client,
            start=time_from,
            end=time_to.strftime(DATE_FORMAT_EVENT),
            limit=limit,
            token=last_run.get(f"next_token_{event_type}"),
            event_type=event_type,
            hide_sensitive=hide_sensitive,
        )

        events.extend(events_by_type)
        last_run_for_type = managing_set_last_run(
            client=client,
            len_events=len(events_by_type),
            limit=limit,
            last_run=last_run,
            time_from=time_from,
            time_to=time_to,
            next_token=next_token,
            event_type=event_type,
        )
        new_last_run.update(last_run_for_type)
    demisto.debug(
        f"The fetch process has ended, the amount of logs for this {len(events)}"
    )

    return events, new_last_run


def fetch_by_event_type(
    client: Client,
    start: str,
    end: str,
    limit: int,
    token: str | None,
    event_type: str,
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
        event_type (str): The type of event log to return.

    Returns:
        tuple[list[dict], str | None]: List of the logs returned from trend micro,
                                       The token that returned for the next fetch.
    """
    if token:
        # The unquoting  is must for the api call
        token = urllib.parse.unquote(token)

    params = assign_params(
        start=start,
        end=end,
        token=token,
        type=event_type,
    )

    next_token: str | None = None
    events_res: list[dict] = []
    while len(events_res) < limit:
        params["limit"] = min(limit - len(events_res), 500)

        try:
            res = client.get_logs_request(event_type, params)
        except NoContentException:
            next_token = None
            demisto.debug(f"No content returned from api, {params=}")
            break

        if res.get("logs"):
            # Iterate over each event log, update their `type` and `_time` fields
            for event in res.get("logs"):
                event.update({"_time": event.get("timestamp"), "logType": event_type})
                if hide_sensitive:
                    remove_sensitive_from_events(event)

            events_res.extend(res.get("logs"))
        else:
            next_token = None
            break

        if next_token := res.get("nextToken"):
            params["token"] = urllib.parse.unquote(next_token)
        else:
            next_token = None
            demisto.debug(f"No returned `nextToken` for the {event_type} type")
            break

    demisto.debug(
        f"The fetch process of the type {event_type} has ended,"
        f" the amount of logs for this type: {len(events_res)}"
    )
    return events_res, next_token


def main() -> None:  # pragma: no cover
    params = demisto.params()
    args = demisto.args()

    base_url = params["url"].strip("/")
    username = params.get("credentials")["identifier"]
    api_key = params.get("credentials")["password"]
    verify = argToBoolean(params.get("verify", "false"))
    proxy = argToBoolean(params.get("proxy", "false"))
    first_fetch = order_first_fetch(params.get("first_fetch") or "3 days")

    should_push_events = argToBoolean(args.get("should_push_events", False))
    last_run = demisto.getLastRun()

    command = demisto.command()
    demisto.info(f"Command being called is {command}")
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
        elif command in ("trend-micro-get-events", "fetch-events"):
            if command == "trend-micro-get-events":
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
                    demisto.debug("The last_run updated")

        else:
            raise NotImplementedError(f"Command {command} is not implemented.")

    except Exception as e:
        return_error(
            f"Failed to execute {command} command. Error in TrendMicro EmailSecurity Event Collector Integration [{e}]."
        )


""" ENTRY POINT """

if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
