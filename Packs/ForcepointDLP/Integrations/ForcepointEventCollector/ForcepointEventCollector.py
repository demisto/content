
import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

import urllib3

# Disable insecure warnings
urllib3.disable_warnings()


""" CONSTANTS """

VENDOR = "forcepoint-dlp"
PRODUCT = "forcepoint-dlp"
DEFAULT_FIRST_FETCH = "3 days"
DEFAULT_MAX_FETCH = 10000
API_DEFAULT_LIMIT = 10000
MAX_GET_IDS_CHUNK_SIZE = 1000
DATEPARSER_SETTINGS = {
    "RETURN_AS_TIMEZONE_AWARE": True,
    "TIMEZONE": "UTC",
}


""" CLIENT CLASS """


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
                 api_limit = API_DEFAULT_LIMIT,
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

        if access_token and not Client.is_token_expired(
            token_initiate_time=float(token_initiate_time),
            token_expiration_seconds=float(token_expiration_seconds)
        ):
            return access_token

        # there's no token or it is expired
        access_token, token_expiration_seconds = self.get_token_request()
        integration_context = {
            'access_token': access_token,
            'token_expiration_seconds': token_expiration_seconds,
            'token_initiate_time': time.time()
        }
        demisto.debug(f'updating access token - {integration_context}')
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
        return token_response.get('access_token'), token_response.get('access_expires_in')

    def get_incidents(self, from_date, to_date) -> Any:
        return self._http_request(
            method="POST",
            json_data={
                "type": "INCIDENTS",
                "from_date": from_date,
                "to_date": to_date,
            },
            url_suffix="/incidents",
        )

    def get_incident_ids(self, incident_ids: list[int]) -> dict[str, Any]:
        return self._http_request(
            method="POST",
            json_data={
                "ids": incident_ids,
                "type": "INCIDENTS",
            },
            url_suffix="/incidents/",
        )

    @staticmethod
    def is_token_expired(token_initiate_time: float, token_expiration_seconds: float) -> bool:
        """
        Check whether a token has expired. a token considered expired if it has been reached to its expiration date in
        seconds minus a minute.

        for example ---> time.time() = 300, token_initiate_time = 240, token_expiration_seconds = 120

        300.0001 - 240 < 120 - 60

        Args:
            token_initiate_time (float): the time in which the token was initiated in seconds.
            token_expiration_seconds (float): the time in which the token should be expired in seconds.

        Returns:
            bool: True if token has expired, False if not.
        """
        return time.time() - token_initiate_time >= token_expiration_seconds - 60


""" HELPER FUNCTIONS """


""" COMMAND FUNCTIONS """


def get_events_command(
    client: Client,
    args: dict[str, Any]
) -> tuple[CommandResults, List[dict[str, Any]]]:
    # limit: int = arg_to_number(args.get('limit')) or DEFAULT_MAX_FETCH
    # since_time = arg_to_datetime(args.get('since_time') or DEFAULT_FIRST_FETCH, settings=DATEPARSER_SETTINGS)
    # assert isinstance(since_time, datetime)
    # events, _ = fetch_events_command(client, since_time, limit)
    #
    # result = CommandResults(
    #     readable_output=tableToMarkdown("Open Incidents", events),
    #     raw_response=events,
    # )
    # return result, events
    pass  # FIXME

def filter_incidents_by_type(events, event_type="INCIDENTS"):
    return list(filter(lambda event: event["type"] == event_type, events))

def chunks(l, n):
    # looping till length l
    for i in range(0, len(l), n):
        yield l[i:i + n]

def fetch_events_command(
    client: Client,
    first_fetch: datetime,
    max_fetch: int,
    last_fetch_time: datetime | None,
    last_id: int | None = None,
    until_time: datetime | None = None,
    time_interval: int = 60,  # Time interval 60 seconds.
) -> tuple[list[dict[str, Any]], int, datetime]:
    """
    Fetches Forcepoint DLP incidents as events to XSIAM.
    Note: each report of incident will be considered as an event.
    """
    events = []
    reached_until_time = False
    from_time = last_fetch_time or first_fetch
    to_time = from_time + timedelta(seconds=time_interval)
    until_time = until_time or client.utc_now
    while not len(events) >= max_fetch and not reached_until_time:

        incidents_response = client.get_incidents(from_time, to_time)
        incidents = incidents_response["incidents"]
        if incidents:
            if incidents_response["total_count"] > client.api_limit and time_interval > 1:
                # recurse in smaller time interval.
                recurse_until_time = min(to_time, client.utc_now)
                recuse_time_interval = time_interval // 60
                recurse_events, last_id, recuse_last_fetch_time = fetch_events_command(client,
                                                                                       first_fetch=first_fetch,
                                                                                       max_fetch=max_fetch - len(events),
                                                                                       last_fetch_time=from_time,
                                                                                       last_id=last_id,
                                                                                       until_time=recurse_until_time,
                                                                                       time_interval=recuse_time_interval)
                events.extend(recurse_events)
                events = events[:max_fetch]
                if len(events) == max_fetch:
                    return events, last_id, recuse_last_fetch_time
            else:
                min_incident_id = incidents[0]["id"]
                # Get incidents in chunks from Get Incidents
                if last_id is not None:
                    for event_ids_chunk in chunks(range(last_id, min_incident_id - 1), MAX_GET_IDS_CHUNK_SIZE):
                        chunk_incidents_response = client.get_incident_ids(event_ids_chunk)
                        events.extend(filter_incidents_by_type(chunk_incidents_response["incidents"]))
                        events = events[:max_fetch]
                        if len(events) == max_fetch:
                            break

                # Append current batch.
                events.extend(incidents)
                events = events[:max_fetch]

                last_id = events[-1]["id"]

        reached_until_time = to_time == until_time
        from_time = to_time
        to_time = min(from_time + timedelta(seconds=time_interval), until_time)

    return events, last_id, from_time


def test_module_command(client: Client, first_fetch: datetime) -> str:
    fetch_events_command(client, first_fetch, max_fetch=1)
    return "ok"


def main():
    command = demisto.command()
    params = demisto.params()
    args = demisto.args()
    demisto.debug(f"Command being called is {command}")
    username: str = params.get('credentials', {}).get('identifier', '')
    password: str = params.get('credentials', {}).get('password', '')

    try:
        first_fetch = arg_to_datetime(params.get("first_fetch") or DEFAULT_FIRST_FETCH, settings=DATEPARSER_SETTINGS)
        assert isinstance(first_fetch, datetime)
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
            return_results(test_module_command(client, first_fetch))

        elif command == "forcepoint-dlp-get-events":
            results, events = get_events_command(client, args)
            return_results(results)
            if argToBoolean(args.get("should_push_events")):
                send_events_to_xsiam(events, VENDOR, PRODUCT)

        elif command == "fetch-events":
            # def fetch_events_command(
            #     client: Client,
            #     first_fetch: datetime,
            #     max_fetch: int,
            #     utc_now: datetime,
            #     last_fetch_time: datetime,
            #     last_id: int | None = None,
            #     events: list[dict[str, Any]] | None = None,
            #     time_interval: int = 60,  # Time interval 60 seconds.
            # ) -> tuple[List[dict[str, Any]], int, datetime]:
            events = []
            last_id, last_fetch_time = fetch_events_command(
                client=client,
                first_fetch=first_fetch,
                max_fetch=max_fetch,
                last_fetch_time=demisto.getLastRun().get("last_fetch_time"),
                last_id=demisto.getLastRun().get("last_id"),
                events=events,
            )
            send_events_to_xsiam(events, VENDOR, PRODUCT)
            demisto.setLastRun({"last_id": last_id, "last_fetch_time": last_fetch_time})

    # Log exceptions
    except Exception as e:
        return_error(f"Failed to execute {demisto.command()} command. Error: {str(e)}")


if __name__ in ("__main__", "__builtin__", "builtins"):  # pragma: no cover
    main()
