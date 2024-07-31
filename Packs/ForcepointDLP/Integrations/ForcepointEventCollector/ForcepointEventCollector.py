from collections import defaultdict

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

import urllib3

# Disable insecure warnings
urllib3.disable_warnings()


""" CONSTANTS """

VENDOR = "forcepoint"
PRODUCT = "forcepoint_dlp"
DEFAULT_MAX_FETCH = 10000
API_DEFAULT_LIMIT = 10000
MAX_GET_IDS_CHUNK_SIZE = 1000
DEFAULT_TEST_MODULE_SINCE_TIME = "3 days"
DATEPARSER_SETTINGS = {
    "RETURN_AS_TIMEZONE_AWARE": True,
    "TIMEZONE": "UTC",
}
DATE_TIME_FORMAT = "%d/%m/%Y %H:%M:%S"


""" CLIENT CLASS """


def to_str_time(t: datetime) -> str:
    return t.strftime(DATE_TIME_FORMAT)


def from_str_time(s: str) -> datetime:
    return datetime.strptime(s, DATE_TIME_FORMAT)


class Client(BaseClient):
    """Client class to interact with the service API

    This Client implements API calls to the Saas Security platform, and does not contain any XSOAR logic.
    Handles the token retrieval.

    :param base_url (str): Saas Security server url.
    :param username (str): Username.
    :param password (str): Password.
    :param verify (bool): specifies whether to verify the SSL certificate or not.
    :param proxy (bool): specifies if to use XSOAR proxy settings.
    """

    def __init__(self, base_url: str, username: str, password: str, verify: bool, proxy: bool, utc_now: datetime,
                 api_limit=API_DEFAULT_LIMIT,
                 **kwargs):
        self.username = username
        self.password = password
        self.api_limit = api_limit
        self.utc_now = utc_now

        super().__init__(base_url=base_url, verify=verify, proxy=proxy, **kwargs)

    def http_request(self, *args, **kwargs):
        """
        Overrides Base client request function, retrieves and adds to headers access token before sending the request.
        """
        token = self.get_access_token()
        headers = {
            'Authorization': f'Bearer {token}',
            'Content-Type': 'application/json',
        }
        return super()._http_request(*args, headers=headers, **kwargs)  # type: ignore[misc]

    def get_access_token(self) -> str:
        """
       Obtains access and refresh token from server.
       Access token is used and stored in the integration context until expiration time.
       After expiration, new refresh token and access token are obtained and stored in the
       integration context.

        Returns:
            str: the access token.
       """
        integration_context = get_integration_context()
        access_token = integration_context.get('access_token')
        token_initiate_time = integration_context.get('token_initiate_time')
        token_expiration_seconds = integration_context.get('token_expiration_seconds')

        if access_token and Client.is_token_valid(
            token_initiate_time=float(token_initiate_time),
            token_expiration_seconds=float(token_expiration_seconds)
        ):
            return access_token

        # There's no token or it is expired
        access_token, token_expiration_seconds = self.get_token_request()
        integration_context = {
            'access_token': access_token,
            'token_expiration_seconds': token_expiration_seconds,
            'token_initiate_time': time.time()
        }
        demisto.info("successfully updated access token")
        set_integration_context(context=integration_context)

        return access_token

    def get_token_request(self) -> tuple[str, str]:
        """
        Sends request to retrieve token.

       Returns:
           tuple[str, str]: token and its expiration date
        """
        headers = {
            'username': self.username,
            'password': self.password,
        }
        token_response = self._http_request('POST', url_suffix='/auth/refresh-token', headers=headers)
        return token_response.get('access_token'), token_response.get('access_token_expires_in')

    def get_incidents(self, from_date, to_date) -> Any:
        return self.http_request(
            method="POST",
            json_data={
                "type": "INCIDENTS",
                "from_date": to_str_time(from_date),
                "to_date": to_str_time(to_date),
            },
            url_suffix="/incidents",
        )

    @staticmethod
    def is_token_valid(token_initiate_time: float, token_expiration_seconds: float) -> bool:
        """
        Check whether a token has expired. A token is considered expired if it reached its expiration date in
        seconds minus a minute.

        for example ---> time.time() = 300, token_initiate_time = 240, token_expiration_seconds = 120

        300.0001 - 240 < 120 - 60

        Args:
            token_initiate_time (float): the time in which the token was initiated in seconds.
            token_expiration_seconds (float): the time in which the token should be expired in seconds.

        Returns:
            bool: True if token has expired, False if not.
        """
        return time.time() - token_initiate_time < token_expiration_seconds - 60


""" HELPER FUNCTIONS """


""" COMMAND FUNCTIONS """


def get_events_command(
    client: Client,
    args: dict[str, Any]
) -> tuple[CommandResults, List[dict[str, Any]]]:
    limit: int = arg_to_number(args.get('limit')) or DEFAULT_MAX_FETCH
    since_time = arg_to_datetime(args.get('since_time'), settings=DATEPARSER_SETTINGS)
    assert isinstance(since_time, datetime)
    events, _, _ = fetch_events_command_sub(client, limit, datetime.utcnow(), since_time)

    result = CommandResults(
        readable_output=tableToMarkdown("Incidents", events),
        raw_response=events,
    )
    return result, events


def fetch_events_command_sub(
    client: Client,
    max_fetch: int,
    to_time: datetime,
    last_fetch_time: datetime,
    last_run_ids: list[int] | None = None,
) -> tuple[list[dict[str, Any]], list[int], str]:
    """
    Fetches Forcepoint DLP incidents as events to XSIAM.
    Note: each report of incident will be considered as an event.
    """
    from_time = last_fetch_time
    events = []
    last_run_ids = set(last_run_ids or set())
    new_last_run_ids: dict[str, set] = defaultdict(set)
    incidents_response = client.get_incidents(from_time, to_time)
    incidents = incidents_response["incidents"]
    for incident in incidents:
        if incident["id"] not in last_run_ids:
            incident["_collector_source"] = "API"
            events.append(incident)
            new_last_run_ids[incident["event_time"]].add(incident["id"])
            if len(events) == max_fetch:
                break

    if not events and incidents:
        # Anti-starvation protection, we've exhausted all events for this second, but they're all duplicated.
        # This means that we've more events in the minimal epoch, that we're able to get in a single fetch,
        # and we'll ignore any additional events in this particular second.
        next_fetch_time: str = to_str_time(from_time + timedelta(seconds=1))
        demisto.info(f"Moving the fetch to the next second:{next_fetch_time}. Any additional events in this "
                     f"second will be lost!")
        return [], [], next_fetch_time

    # We've got events for this time span, so start from that to_time in the next fetch,
    # otherwise use the to_time - 1 second (as we might have more events for this second)
    next_fetch_time = events[-1]["event_time"] if events else to_str_time(to_time - timedelta(seconds=1))

    return events, list(new_last_run_ids[next_fetch_time]), next_fetch_time


def test_module_command(client: Client, first_fetch: datetime) -> str:
    fetch_events_command_sub(client, 1, datetime.utcnow(), first_fetch)
    return "ok"


def fetch_events(client, first_fetch, max_fetch):
    events = []
    forward = demisto.getLastRun().get("forward") or {
        "last_fetch": to_str_time(datetime.utcnow() + timedelta(seconds=1)),
        "last_events_ids": [],
    }

    from_time = from_str_time(forward["last_fetch"])
    to_time = client.utc_now
    demisto.info(f"looking for backward events from:{from_time} to:{to_time}")
    forward_events, last_events_ids, next_fetch_time = fetch_events_command_sub(client, max_fetch, to_time,
                                                                                from_time,
                                                                                forward["last_events_ids"])
    forward = {
        "last_fetch": next_fetch_time,
        "last_events_ids": last_events_ids,
    }
    events.extend(forward_events)

    send_events_to_xsiam(events, VENDOR, PRODUCT)  # noqa
    demisto.setLastRun({
        "forward": forward,
    })


def main():  # pragma: no cover
    command = demisto.command()
    params = demisto.params()
    args = demisto.args()
    demisto.debug(f"Command being called is {command}")
    username: str = params.get('credentials', {}).get('identifier', '')
    password: str = params.get('credentials', {}).get('password', '')

    try:
        first_fetch = arg_to_datetime(params.get("first_fetch"), settings=DATEPARSER_SETTINGS) \
            if params.get("first_fetch") else None
        max_fetch = arg_to_number(params.get("max_fetch")) or DEFAULT_MAX_FETCH

        client = Client(
            base_url=urljoin(params["url"], "/dlp/rest/v1"),
            verify=not params.get("insecure", False),
            proxy=params.get("proxy", False),
            username=username,
            password=password,
            utc_now=datetime.utcnow(),
        )
        if command == "test-module":
            test_module_first_fetch: datetime = arg_to_datetime(
                DEFAULT_TEST_MODULE_SINCE_TIME, settings=DATEPARSER_SETTINGS)  # type: ignore[assignment]
            return_results(test_module_command(client, test_module_first_fetch))

        elif command == "forcepoint-dlp-get-events":
            results, events = get_events_command(client, args)
            return_results(results)
            if argToBoolean(args.get("should_push_events")):
                send_events_to_xsiam(events, VENDOR, PRODUCT)  # noqa

        elif command == "fetch-events":
            fetch_events(client, first_fetch, max_fetch)

    # Log exceptions
    except Exception as e:
        return_error(f"Failed to execute {demisto.command()} command. Error: {str(e)}")


if __name__ in ("__main__", "__builtin__", "builtins"):  # pragma: no cover
    main()
