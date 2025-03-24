import demistomock as demisto
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa

import urllib3

# Disable insecure warnings
urllib3.disable_warnings()


""" CONSTANTS """

DATE_FORMAT = "%Y-%m-%dT%H:%M:%SZ"  # ISO8601 format with UTC, default in XSOAR

MAX_FETCH_LIMIT = 1000
VENDOR = "WithSecure"
PRODUCT = "Endpoint Protection"

""" CLIENT CLASS """


class Client(BaseClient):
    """Client class to interact with the service API"""

    def __init__(self, base_url, verify, proxy, client_id, client_secret):
        super().__init__(base_url=base_url, verify=verify, proxy=proxy)
        self.client_id = client_id
        self.client_secret = client_secret

    def authenticate(self) -> tuple[str, int]:
        """Get the access token from the WithSecure API.

        Returns:
            tuple[str,int]: The token and its expiration time in seconds received from the API.
        """

        response = self._http_request(
            method="POST",
            url_suffix="as/token.oauth2",
            auth=(self.client_id, self.client_secret),
            data={"grant_type": "client_credentials"},
            error_handler=access_token_error_handler,
        )

        return response.get("access_token"), response.get("expires_in")

    def get_access_token(self):
        """Return the token stored in integration context or returned from the API call.

        If the token has expired or is not present in the integration context
        (in the first case), it calls the Authentication function, which
        generates a new token and stores it in the integration context.

        Returns:
            str: Authentication token.
        """
        integration_context = get_integration_context()
        token = integration_context.get("access_token")
        valid_until = integration_context.get("valid_until")
        time_now = int(time.time())

        # If token exists and is valid, then return it.
        if (token and valid_until) and (time_now < valid_until):
            return token

        # Otherwise, generate a new token and store it.
        token, expires_in = self.authenticate()
        integration_context = {
            "access_token": token,
            "valid_until": time_now + expires_in,
        }
        set_integration_context(integration_context)

        return token

    def get_events_api_call(self, fetch_from: str, limit: int, next_anchor: str = None):
        params = {"serverTimestampStart": fetch_from, "limit": limit, "order": "asc"}
        if next_anchor:
            params["anchor"] = next_anchor
        return self._http_request(
            method="GET",
            url_suffix="security-events/v1/security-events",
            headers={"Authorization": f"Bearer {self.get_access_token()}"},
            params=params,
        )


""" HELPER FUNCTIONS """


def access_token_error_handler(response: requests.Response):
    """
    Error Handler for WithSecure access_token
    Args:
        response (response): WithSecure Token url response
    Raise:
         DemistoException
    """
    if response.status_code == 401:
        raise DemistoException(
            "Authorization Error: The provided credentials for WithSecure are "
            "invalid. Please provide a valid Client ID and Client Secret."
        )
    elif response.status_code >= 400:
        raise DemistoException("Error: something went wrong, please try again.")


def parse_date(dt: str) -> str:
    date_time = dateparser.parse(dt, settings={"TIMEZONE": "UTC"})
    return date_time.strftime(DATE_FORMAT)  # type: ignore


def parse_events(events: list, last_fetch: str, last_event_id: str) -> tuple[str, str, list]:
    last_fetch_timestamp = date_to_timestamp(last_fetch, DATE_FORMAT)
    last_event_timestamp = last_fetch_timestamp
    last_event_time = last_fetch
    new_event_id = last_event_id
    parsed_events: list = []
    for event in events:
        event_time = date_to_timestamp(parse_date(event.get("serverTimestamp")), DATE_FORMAT)
        ev_id = event.get("id")
        # the event was already fetched
        if last_fetch_timestamp == event_time and last_event_id == ev_id:
            continue
        event["_time"] = parse_date(event.get("clientTimestamp"))
        if last_event_timestamp < event_time:
            last_event_timestamp = event_time
            last_event_time = event.get("serverTimestamp")
            new_event_id = ev_id

        parsed_events.append(event)

    return parse_date(last_event_time), new_event_id, parsed_events


def get_events(client: Client, fetch_from: str, limit: int) -> list:
    events: list = []
    next_anchor = "first"
    while next_anchor and len(events) < limit:
        req_limit = min(MAX_FETCH_LIMIT, limit - len(events))
        res = client.get_events_api_call(fetch_from, req_limit, next_anchor if next_anchor != "first" else None)
        events.extend(res.get("items"))
        next_anchor = res.get("nextAnchor")

    return events


def fetch_events(client: Client, fetch_from: str, limit: int, next_anchor):
    events: list = []
    req_limit = min(limit, MAX_FETCH_LIMIT)
    res = client.get_events_api_call(fetch_from, req_limit, next_anchor if next_anchor else None)
    events.extend(res.get("items"))
    next_anchor = res.get("nextAnchor")

    return events, next_anchor


""" COMMAND FUNCTIONS """


def test_module(client: Client) -> str:
    """Tests API connectivity and authentication'

    Returning 'ok' indicates that the integration works like it is supposed to.
    Connection to the service is successful.
    Raises exceptions if something goes wrong.

    :type client: ``Client``
    :param Client: client to use

    :return: 'ok' if test passed, anything else will fail the test.
    :rtype: ``str``
    """

    client.get_access_token()
    return "ok"


def get_events_command(client: Client, args: dict) -> tuple[list, CommandResults]:
    """
    Gets all the events from the WithSecure API for each log type.
    Args:
        client (Client): client to use.
        args: dict, demisto args.
    Returns:
        list: A list containing the events
        CommandResults: A CommandResults object that contains the events in a table format.
    """
    fetch_from = parse_date(args.get("fetch_from") or demisto.params().get("first_fetch", "3 days"))
    limit = arg_to_number(args.get("limit")) or MAX_FETCH_LIMIT
    events = get_events(client, fetch_from, limit)

    events = events[:limit]
    hr = tableToMarkdown(name="With Secure Events", t=events)
    return events, CommandResults(readable_output=hr)


def fetch_events_command(client: Client, first_fetch: str, limit: int) -> tuple[list, dict]:
    """
    This function retrieves new alerts every interval (default is 1 minute).
    It has to implement the logic of making sure that events are fetched only once and no events are missed.
    By default it's invoked by XSIAM every minute. It will use last_run to save the timestamp of the last event it
    processed. If last_run is not provided, it should use the integration parameter first_fetch_time to determine when
    to start fetching the first time.

    Args:
        client (Client): WithSecure client to use.
        first_fetch (str): Timestamp to start fetch from
        limit (int): Maximum numbers of events per fetch.
    Returns:
        list: List of events that will be created in XSIAM.
        dict: The lastRun object for the next fetch run
    """
    last_run = demisto.getLastRun()
    fetch_from = last_run.get("fetch_from") or first_fetch
    next_anchor = last_run.get("next_anchor")
    event_id = last_run.get("event_id", "")
    events, next_anchor = fetch_events(client, fetch_from, limit, next_anchor)

    last_fetch, event_id, parsed_events = parse_events(events[:limit], fetch_from, event_id)
    next_run = {"fetch_from": last_fetch, "next_anchor": next_anchor, "event_id": event_id}

    return parsed_events, next_run


""" MAIN FUNCTION """


def main() -> None:
    """main function, parses params and runs command functions

    :return:
    :rtype:
    """

    params = demisto.params()
    args = demisto.args()
    base_url = params.get("url")
    client_id = params.get("credentials", {}).get("identifier")
    client_secret = params.get("credentials", {}).get("password")
    first_fetch = parse_date(params.get("first_fetch", "3 months"))
    limit = arg_to_number(params.get("limit", 1000))

    verify_ssl = not params.get("insecure", False)

    proxy = params.get("proxy", False)
    command = demisto.command()
    demisto.debug(f"Command being called is {command}")
    try:
        client = Client(base_url=base_url, verify=verify_ssl, client_id=client_id, client_secret=client_secret, proxy=proxy)

        if demisto.command() == "test-module":
            return_results(test_module(client))

        elif command == "with-secure-get-events":
            _, result = get_events_command(client, args)
            return_results(result)

        elif command == "fetch-events":
            events, next_run = fetch_events_command(client, first_fetch, limit)  # type: ignore
            send_events_to_xsiam(events, vendor=VENDOR, product=PRODUCT)
            demisto.setLastRun(next_run)

    except Exception as e:
        return_error(f"Failed to execute {demisto.command()} command.\nError:\n{str(e)}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
