import demistomock as demisto
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa

import urllib3
from typing import Any, Dict, Tuple, List, Optional

# Disable insecure warnings
urllib3.disable_warnings()


''' CONSTANTS '''

DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'  # ISO8601 format with UTC, default in XSOAR
LOG_TYPES = ["UserCreated", "UserDeleted", "JoinCompany", "EditUserProperties", "EditOwnProfile", "EditUserPermissions",
             "StartedSession", "IncomingSession", "EndedSession", "JoinedSession", "LeftSession",
             "ParticipantJoinedSession", "ParticipantLeftSession", "ChangedDisabledRemoteInput", "ReceivedDisabledLocalInput",
             "ChangedShowBlackScreen", "ReceivedShowBlackScreen", "SwitchedSides", "StartedRecording", "EndedRecording",
             "PausedRecording", "ResumedRecording", "SentFile", "ReceivedFile", "CreateCustomHost", "UpdateCustomHost",
             "DeleteCustomHost", "PolicyAdded", "PolicyUpdated", "PolicyDeleted", "ScriptTokenAdded", "ScriptTokenDeleted",
             "ScriptTokenUpdated", "GroupAdded", "GroupUpdated", "GroupDeleted", "GroupShared", "EmailConfirmed"]
DEFAULT_LIMIT = "300"
VENDOR = "teamviewer"
PRODUCT = "teamviewer"

''' CLIENT CLASS '''


class Client(BaseClient):
    """
    Client class to interact with the service API
    """
    def __init__(self, base_url, verify, proxy, headers):
        super().__init__(base_url=base_url, verify=verify, proxy=proxy, headers=headers)

    def http_request(self, params=None, body=None):
        return self._http_request(
            method="POST", headers=self._headers, params=params, data=body)


''' HELPER FUNCTIONS '''


def search_events(client: Client, limit: int, body: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
    """
    Searches for T alerts.
    Args:
        continuation_token:  Optional[ByteString],
        url_suffix: str, The API endpoint to request.
        limit: int, the limit of the results to return.
        body: dict, contains the time parameters.
    Returns:
        list: A list containing the events
    """
    results: List[Dict] = []
    token_next_page = None
    next_page = True
    params: Dict[str, Any] = {}
    while next_page and len(results) < limit:
        response = client.http_request(params=params, body=body)
        results += response.get("AuditEvents", [])
        next_page = response.get("ContinuationToken")
        if token_next_page := response.get("ContinuationToken"):
            params['ContinuationToken'] = token_next_page
        else:
            next_page = False
    return results[:limit]


''' COMMAND FUNCTIONS '''


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

    message: str = ''
    try:
        # TODO: ADD HERE some code to test connectivity and authentication to your service.
        # This  should validate all the inputs given in the integration configuration panel,
        # either manually or by using an API that uses them.
        message = 'ok'
    except DemistoException as e:
        if 'Forbidden' in str(e) or 'Authorization' in str(e):  # TODO: make sure you capture authentication errors
            message = 'Authorization Error: make sure API Key is correctly set'
        else:
            raise e
    return message


def get_events_command(
    client: Client, limit: int
) -> Tuple[List[Dict[str, Any]], CommandResults]:
    """
    Gets all the events from the teamviewer API for each log type.
    Args:
        client (Client): teamviewer client to use.
        limit: int, the limit of the results to return per log_type.
    Returns:
        list: A list containing the events
        CommandResults: A CommandResults object that contains the events in a table format.
    """
    events: List[Dict] = []
    hr = ""
    events = search_events(client=client, limit=limit)
    hr = tableToMarkdown(name='Events', t=events) if events else 'No events found.'
    return events, CommandResults(readable_output=hr)


def fetch_events_command(
    client: Client, max_fetch: int, last_run: Dict[str, int], first_fetch_time: str
) -> Tuple[Dict[str, int], List[Dict[str, Any]]]:
    """
    Args:
        client (Client): TeamViewer client to use.
        max_fetch (int): The maximum number of events to fetch per log type.
        last_run (dict): A dict with a keys containing the first event id to fetch for each log type.
        first_fetch_time (str): In case of first fetch, fetch events from this date.
    Returns:
        dict: Next run dictionary containing the ids of the next events to fetch.
        list: List of events that will be created in XSIAM.
    """
    # In the first fetch, get the ids for the first fetch time
    last_fetch = last_run.get('last_fetch')
    last_fetch = first_fetch_time if last_fetch is None else int(last_fetch)
    # latest_created_time = cast(int, last_fetch)
    import datetime
    formatted_time = datetime.datetime.utcnow().strftime(DATE_FORMAT)
    body = {
        "StartDate": first_fetch_time,
        "EndDate": formatted_time
    }
    next_run = last_run.copy()
    events = search_events(client=client, limit=max_fetch, body=body)
    return next_run, events


def add_time_key_to_events(events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Adds the _time key to the events.
    Args:
        events: list, the events to add the time key to.
    Returns:
        list: The events with the _time key.
    """
    for event in events:
        if event.get("Timestamp"):
            event["_time"] = event.get("Timestamp")
    return events


''' MAIN FUNCTION '''


def main() -> None:
    """
    main function, parses params and runs command functions
    """
    params = demisto.params()
    args = demisto.args()
    command = demisto.command()
    api_key = params.get("credentials", {}).get("Script Token")
    base_url = urljoin(params.get("url"), "/api/v1/EventLogging")
    verify_certificate = not params.get("insecure", True)
    proxy = params.get("proxy", False)

    # How much time before the first fetch to retrieve events
    first_fetch_time: datetime = arg_to_datetime(
        arg=params.get("first_fetch", "3 days"),
        arg_name="First fetch time",
        required=True,
    )  # type: ignore   # datetime.datetime(2022, 1, 1, 00, 00, 00, 0)
    first_fetch_time_strftime = first_fetch_time.strftime(
        DATE_FORMAT
    )  # 2022-01-01T00:00:00Z

    demisto.debug(f"Command being called is {command}")
    try:
        headers = {"Authorization": f"Bearer {api_key}"}
        client = Client(
            base_url=base_url, verify=verify_certificate, headers=headers, proxy=proxy
        )

        if command == "test-module":
            # This is the call made when pressing the integration Test button.
            result = test_module(client)
            return_results(result)

        elif command in ("teamviewer-get-events", "fetch-events"):
            if command == "teamviewer-get-events":
                should_push_events = argToBoolean(args.get("should_push_events"))
                events, results = get_events_command(
                    client, limit=arg_to_number(args.get("limit", DEFAULT_LIMIT))  # type: ignore
                )
                return_results(results)

            else:  # command == 'fetch-events':
                should_push_events = True
                demisto.debug('before last run')
                last_run = demisto.getLastRun()
                next_run, events = fetch_events_command(
                    client=client,
                    max_fetch=arg_to_number(params.get("max_fetch", DEFAULT_LIMIT)),  # type: ignore
                    last_run=last_run,
                    first_fetch_time=first_fetch_time_strftime,
                )
                # saves next_run for the time fetch-events is invoked
                demisto.debug('after fetch events command')
                demisto.setLastRun(next_run)

            if should_push_events:
                events = add_time_key_to_events(events)
                send_events_to_xsiam(events, vendor=VENDOR, product=PRODUCT)

    # Log exceptions and return errors
    except Exception as e:
        return_error(f"Failed to execute {command} command.\nError:\n{str(e)}")


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
