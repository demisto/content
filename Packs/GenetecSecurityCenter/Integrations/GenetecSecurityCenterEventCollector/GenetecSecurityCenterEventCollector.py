import demistomock as demisto
from urllib3 import disable_warnings
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa
from requests.auth import HTTPBasicAuth

disable_warnings()

""" CONSTANTS """

VENDOR = "Genetec"
PRODUCT = "Security center"
DATE_FORMAT_EVENT = "%Y-%m-%dT%H:%M:%S"
AUDIT_TRAIL_ENDPOINT = "/WebSdk/report/AuditTrail"


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

    :param base_url (str): The server URL.
    :param username (str): The account username.
    :param password (str): The account password.
    :param app_id (str): The app ID.
    :param max_fetch (str): The maximum number of events to fetch per interval.
    :param verify (bool): specifies whether to verify the SSL certificate or not.
    :param proxy (bool): specifies if to use XSOAR proxy settings.
    """

    def __init__(
        self, base_url: str, username: str, password: str, verify: bool, proxy: bool, max_fetch: str, app_id: str
    ):
        self._auth = self._encode_authorization(username, password, app_id)
        self.limit = max_fetch

        super().__init__(base_url=base_url, verify=verify, proxy=proxy)

    def _encode_authorization(self, username: str, password: str, app_id: str):
        updated_username = f"{username};{app_id}"
        return HTTPBasicAuth(updated_username, password)


""" COMMAND FUNCTIONS """


def test_module(client: Client):
    """
    Testing we have a valid connection to trend_micro.
    """
    return "ok"


def fetch_events_command(
    client: Client,
    args: dict[str, str],
    last_run: dict,
) -> tuple[list[dict], dict]:
    """
    Args:
        client (Client): The client for api calls.
        args (dict[str, str]): The args.
        last_run (dict): The last run dict.

    Returns:
        tuple[list[dict], dict]: List of all event logs of all types,
                                 The updated `last_run` obj.
    """
    time_now: datetime = datetime.now()
    start_time: datetime
    if not last_run:
        start_time = time_now - timedelta(minutes=1)
    else:
        start_time = last_run.get("start_time", time_now - timedelta(minutes=1))
    time_range = f"TimeRange.SetTimeRange({start_time.strftime(DATE_FORMAT_EVENT)},{time_now.strftime(DATE_FORMAT_EVENT)})"
    limit: str = args.get("max_fetch", "1000") or client.limit
    demisto.info(f"fetching events with the following time_range: {time_range}")
    url_suffix = f"{AUDIT_TRAIL_ENDPOINT}?q={time_range},MaximumResultCount={limit}"
    events: list[dict] = client._http_request('GET', url_suffix=url_suffix)
    demisto.info(f"got the following events: {events}")
    new_last_run = {"start_time": events[-1].get("ModificationTimeStamp")}
    demisto.debug(f"Done fetching, got {len(events)} events.")
    demisto.debug(f"New last run is {new_last_run}")

    return events, new_last_run


def test_func(client: Client):
    url_suffix = f"{AUDIT_TRAIL_ENDPOINT}?q=TimeRange.SetTimeRange(2016-12-15T21:17:00,2023-12-15T21:18:00),MaximumResultCount=10"
    events: list[dict] = client._http_request('GET', url_suffix=url_suffix)
    print(f"got the following events: {events}")
    new_last_run = {"start_time": events[-1].get("ModificationTimeStamp")}
    print(f"Done fetching, got {len(events)} events.")
    print(f"New last run is {new_last_run}")

    return events, new_last_run


def main() -> None:  # pragma: no cover
    params = demisto.params()
    args = demisto.args()

    base_url = params["url"].strip("/")
    username = params["credentials"]["identifier"]
    password = params["credentials"]["password"]
    app_id = params["app_id"]
    max_fetch = params.get("max_fetch", "1000")
    verify = not params.get("insecure", False)
    proxy = params.get("proxy", False)

    should_push_events = argToBoolean(args.get("should_push_events", False))

    command = demisto.command()
    try:
        client = Client(
            base_url=base_url,
            username=username,
            password=password,
            max_fetch=max_fetch,
            app_id=app_id,
            verify=verify,
            proxy=proxy,
        )

        if command == "test-module":
            return_results(test_module(client))

        elif command == "genetec-security-center-get-events":
            events, _ = test_func(client)
            return_results(
                CommandResults(readable_output=tableToMarkdown("Events:", events))
            )

        elif command == "fetch-events":
            should_push_events = True
            should_update_last_run = True
            last_run = demisto.getLastRun()
            events, last_run = fetch_events_command(
                client, params, last_run=last_run
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
