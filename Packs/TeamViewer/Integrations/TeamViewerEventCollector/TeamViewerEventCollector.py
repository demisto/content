import demistomock as demisto
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa

import urllib3
from typing import Dict, Any

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
    def http_request(self, url_suffix=None, full_url=None, params=None):
        return self._http_request(
            method="POST", url_suffix=url_suffix, full_url=full_url, params=params
        )

    def search_events(
        self, url_suffix: str, limit: int, prev_id: int = 0, ordering: str = ""
    ) -> tuple[int, List[Dict[str, Any]]]:
        """
        Searches for T alerts using the '/<url_suffix>' API endpoint.
        Args:
            url_suffix: str, The API endpoint to request.
            limit: int, the limit of the results to return.
            prev_id: int, The id of the first event to fetch.
            ordering: str, The ordering of the results to return.
        Returns:
            int: The id of the next event to fetch.
            list: A list containing the events
        """
        next_id = prev_id
        results: List[Dict] = []

        next_page = True
        params = {
            "limit": limit,
            "ordering": ordering,
            "id__gte": next_id,
        }

        while next_page and len(results) < limit:
            full_url = next_page if type(next_page) == str else ""
            response = self.http_request(
                url_suffix=url_suffix, full_url=full_url, params=params
            )

            results += response.get("results", [])

            next_page = response.get("next")
            params = {}

            if results:
                next_id = results[-1]["id"] + 1

        return next_id, results[:limit]


''' HELPER FUNCTIONS '''

# TODO: ADD HERE ANY HELPER FUNCTION YOU MIGHT NEED (if any)

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
) -> tuple[List[Dict[str, Any]], CommandResults]:
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
    for log_type in LOG_TYPES:
        _, events_ = client.search_events(url_suffix=log_type, limit=limit)
        if events_:
            hr += tableToMarkdown(name=f"{log_type} Events", t=events_)
            events += events_
        else:
            hr = f"No events found for {log_type}."

    return events, CommandResults(readable_output=hr)


''' MAIN FUNCTION '''


def main() -> None:
    """
    main function, parses params and runs command functions
    """
    params = demisto.params()
    args = demisto.args()
    command = demisto.command()
    api_key = params.get("credentials", {}).get("password")
    base_url = urljoin(params.get("url"))
    verify_certificate = not params.get("insecure", False)
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
        headers = {"Authorization": f"Token {api_key}"}
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
                last_run = demisto.getLastRun()
                next_run, events = fetch_events_command(
                    client=client,
                    max_fetch=arg_to_number(params.get("max_fetch", DEFAULT_LIMIT)),  # type: ignore
                    last_run=last_run,
                    first_fetch_time=first_fetch_time_strftime,
                )
                # saves next_run for the time fetch-events is invoked
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
