
import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

import copy
import urllib3
from typing import Dict, Tuple

# Disable insecure warnings
urllib3.disable_warnings()


""" CONSTANTS """

VENDOR = "forcepoint-dlp"
PRODUCT = "forcepoint-dlp"
DEFAULT_FIRST_FETCH = "3 days"
DEFAULT_MAX_FETCH = 10000
DEFAULT_LIMIT = 10
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

    def __init__(self, base_url: str, username: str, password: str, verify: bool, proxy: bool, **kwargs):
        self.username = username
        self.password = password

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

    def get_token_request(self) -> Tuple[str, str]:
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

    def get_events_request(self, size: int = DEFAULT_MAX_FETCH):
        return self.http_request(
            'GET',
            url_suffix='/incidents',
            resp_type='response',
            ok_codes=[200, 204],
            params={"size": size}
        )

    def get_open_incident_ids(self) -> List[int]:
        return self._http_request(
            method="POST",
            json_data={
                "type": "INCIDENTS",
            },
            url_suffix="/incidents",
        ).get("incidents") or []

    def get_incident(self, incident_id: int) -> Dict[str, Any]:
        return self._http_request(
            method="POST",
            json_data={
                "ids": [incident_id],
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


def get_incident_ids_by_time(
    client: Client,
    incident_ids: List[int],
    start_time: datetime,
    start_idx: int = 0,
    end_idx: Optional[int] = None,
) -> List[int]:
    """Uses binary search to determine the incident ID to start fetching from.
    This method will be called only in the first fetch.

    Args:
        client (Client): The client object
        incident_ids (List[int]): List of all incident IDs
        start_time (datetime): Time to start the fetch from
        start_idx (int): Start index for the binary search
        end_idx (int): End index for the binary search

    Returns:
        List[int]: The list of all incident IDs to fetch.
    """
    if end_idx is None:
        end_idx = len(incident_ids) - 1

    current_idx = (start_idx + end_idx) // 2

    incident = client.get_incident(incident_ids[current_idx])
    incident_time = arg_to_datetime(incident.get("first_reported_date", ""), settings=DATEPARSER_SETTINGS)
    assert isinstance(incident_time, datetime)

    if incident_time > start_time:
        if current_idx == start_idx:
            return incident_ids[start_idx:]
        return get_incident_ids_by_time(
            client,
            incident_ids,
            start_time,
            start_idx=start_idx,
            end_idx=current_idx - 1,
        )
    if incident_time < start_time:
        if current_idx == start_idx:
            return incident_ids[end_idx:]
        return get_incident_ids_by_time(
            client,
            incident_ids,
            start_time,
            start_idx=current_idx + 1,
            end_idx=end_idx,
        )
    return incident_ids[current_idx:]


def get_open_incident_ids_to_fetch(
    client: Client,
    first_fetch: datetime,
    last_id: Optional[int],
) -> List[int]:
    all_open_incident_ids: List[int] = client.get_open_incident_ids()
    if not all_open_incident_ids:
        return []
    if isinstance(last_id, int):
        # We filter out only events with ID greater than the last_id
        return list(filter(lambda i: i > last_id, all_open_incident_ids))  # type: ignore
    return get_incident_ids_by_time(
        client,
        all_open_incident_ids,
        start_time=first_fetch,
    )


def incident_to_events(incident: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Creates an event for each report in the current incident.
        Returns the list of events.
    """
    def report_to_event(report_data: Dict[str, Any]) -> Dict[str, Any]:
        """Transforms a single report data of the incident to an event.
        """
        event = copy.deepcopy(incident)
        event["_time"] = event["first_reported_date"]
        del event["reports"]
        return event | report_data

    return [report_to_event(event) for event in incident.get("reports", [])]


""" COMMAND FUNCTIONS """


def get_events_command(
    client: Client,
    args: Dict[str, Any]
) -> Tuple[CommandResults, List[Dict[str, Any]]]:
    limit: int = arg_to_number(args.get('limit')) or DEFAULT_LIMIT
    since_time = arg_to_datetime(args.get('since_time') or DEFAULT_FIRST_FETCH, settings=DATEPARSER_SETTINGS)
    assert isinstance(since_time, datetime)
    events, _ = fetch_events_command(client, since_time, limit)

    result = CommandResults(
        readable_output=tableToMarkdown("Open Incidents", events),
        raw_response=events,
    )
    return result, events


def fetch_events_command(
    client: Client,
    first_fetch: datetime,
    max_fetch: int,
    last_id: Optional[int] = None,
) -> Tuple[List[Dict[str, Any]], int]:
    """Fetches Forcepoint DLP incidents as events to XSIAM.
    Note: each report of incident will be considered as an event.

    Args:
        client (Client): The client object.
        first_fetch (datetime): First fetch time.
        max_fetch (int): Maximum number of events to fetch.
        last_id (Optional[int]): The ID of the most recent incident ingested in previous runs. Defaults to None.

    Returns:
        Tuple[List[Dict[str, Any]], int]:
            - A list of new events.
            - ID of the most recent incident ingested in the current run.
    """
    events: List[Dict[str, Any]] = []
    incident_ids: List[int] = get_open_incident_ids_to_fetch(
        client=client,
        first_fetch=first_fetch,
        last_id=last_id,
    )
    last_id = last_id or -1
    for i in incident_ids:
        incident = client.get_incident(i)
        events.extend(incident_to_events(incident))
        last_id = max(i, last_id)
        if len(events) >= max_fetch:
            break

    return events, last_id


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
        )
        if command == "test-module":
            return_results(test_module_command(client, first_fetch))

        elif command == "forcepoint-dlp-get-events":
            results, events = get_events_command(client, args)
            return_results(results)
            if argToBoolean(args.get("should_push_events")):
                send_events_to_xsiam(events, VENDOR, PRODUCT)

        elif command == "fetch-events":
            events, last_id = fetch_events_command(
                client=client,
                first_fetch=first_fetch,
                max_fetch=max_fetch,
                last_id=demisto.getLastRun().get("last_id"),
            )
            send_events_to_xsiam(events, VENDOR, PRODUCT)
            demisto.setLastRun({"last_id": last_id})

    # Log exceptions
    except Exception as e:
        return_error(f"Failed to execute {demisto.command()} command. Error: {str(e)}")


if __name__ in ("__main__", "__builtin__", "builtins"):  # pragma: no cover
    main()
