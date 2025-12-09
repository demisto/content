import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


""" IMPORTS """

import json
import re

import urllib3

# Disable insecure warnings
urllib3.disable_warnings()


""" CONSTANTS """

API_ROUTE = "/api/v1"
MSISAC_FETCH_WINDOW_DEFAULT = 1
XSOAR_INCIDENT_DATE_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
MSISAC_CREATED_TIME_FORMAT = "%Y-%m-%dT%H:%M:%S%z"
ALERT_ID_REGEX = "^(?:alert-)?\\d+$"


""" CLIENT CLASS """


class Client(BaseClient):
    """
    This client class for MS-ISAC definies two API endpoints
    Query events in a set amount of days /albert/{days}
    Retrieve event details /albertlogs/{event_id}
    """

    def error_handler(self, res: requests.Response):
        """Generic handler for API call error
        Constructs and throws a proper error for the API call response.

        :type response: ``requests.Response``
        :param response: Response from API after the request for which to check the status.
        """
        err_msg = f"Error in API call [{res.status_code}] - {res.reason}"
        demisto.debug(
            f"""
            ---Start Error Details---
            Error API Endpoint:
            {res.url}
            Error Content:
            {str(res._content)}
            ---End Error Details---
            """
        )
        raise DemistoException(err_msg, res=res)

    def get_event(self, event_id: str) -> Dict[str, Any]:
        """
        Returns the details of an MS-ISAC event
        This is a legacy endpoint that only returns results prior to 6/30/25

        :type event_id: ``str``
        :param event_id: id of the event

        :return: dict containing the alert as returned from the API
        :rtype: ``Dict[str, Any]``
        """
        # We need to specify 404 as an OK code so that we can handle "no results found" as an output instead of an error
        # The API returns 404 if the specified event ID was not found
        return self._http_request(
            method="GET", url_suffix=f"/albertlogs/{event_id}", timeout=100, ok_codes=(200, 404), error_handler=self.error_handler
        )

    def retrieve_events(self, days: int) -> Dict[str, Any]:
        """
        Returns a list of MS-ISAC events in a given amount of days
        This is a legacy endpoint that only returns results prior to 6/30/25

        :type days: ``str``
        :param days: The number of days to search. This will be one or greater

        :return: dict containing the alert as returned from the API
        :rtype: ``Dict[str, Any]``
        """
        return self._http_request(method="GET", url_suffix=f"/albert/{days}", timeout=100, error_handler=self.error_handler)

    def get_alert(self, alert_id: str) -> Dict[str, Any]:
        """
        Returns the details of an MS-ISAC alert
        This will only return results after 7/1/2025

        :type alert_id: ``str``
        :param alert_id: id of the event

        :return: dict containing the alert as returned from the API
        :rtype: ``Dict[str, Any]``
        """
        # We are using retries and status_list_to_retry to get around MSISAC API rate limiting.
        # This is necessary for fetching, or bulk alert searching operations.
        return self._http_request(
            method="GET", url_suffix=f"/alert/{alert_id}", timeout=100, retries=5, status_list_to_retry=[503]
        )

    def retrieve_cases(self, timestamp: str) -> list[dict[str, Any]]:
        """
        Returns a list of MS-ISAC cases since the given timestamp
        This will only return results after 7/1/2025

        :type timestamp: ``str``
        :param timestamp: Return cases since the timestamp given. API docs shows formatting as "2025-07-01T00:00:00".
                          If this parameter is not given, will default to searching back 72 hours

        :return: list containing the cases as returned from the API
        :rtype: ``list[dict[str, any]]``
        """
        return self._http_request(method="GET", url_suffix=f"/cases/{timestamp}", timeout=100)


""" HELPER FUNCTIONS """


@logger
def format_stream_data(event: dict[str, list]) -> list[dict]:
    """Formats the stream data that is returned by get_event().

    Args:
        event: The raw albert event data returned by get_event().

    Returns:
        A list containing a single index that is a dict containing the unpacked stream data.

    """
    # the json_data in the payload is the most verbose and should be our final output
    # However there are several keys that are not present in json_data we still want/need in the markdown and context
    stream = []
    for event_data in event["data"]:
        stream_data = json.loads(event_data["json_data"])
        stream_data["time"] = event_data["time"]
        stream_data["streamdataascii"] = event_data["streamdataascii"]
        stream_data["streamdatahex"] = event_data["streamdatahex"]
        stream_data["logical_sensor_id"] = event_data["logical_sensor_id"]
        stream_data["streamdatalen"] = event_data["streamdatalen"]
        # Not all responses have the http stream data so we need to make sure we're not referencing non-existant entries
        http = stream_data.get("http", None)
        if http:
            # The data we have in here we want at the root to more easily reference in context paths
            for entry in stream_data["http"]:
                stream_data[entry] = stream_data["http"][entry]
            del stream_data["http"]
        # Same deal as http, we want this refereanceable in context
        for data in stream_data["flow"]:
            stream_data[data] = stream_data["flow"][data]
        del stream_data["flow"]
        stream.append(stream_data)

    return stream


""" COMMAND FUNCTIONS """


def test_module(client: Client) -> str:
    """
    Tests API connectivity and authentication'

    Returning 'ok' indicates that the integration works like it is supposed to.
    Connection to the service is successful.
    Raises exceptions if something goes wrong.

    :type client: ``Client``
    :param Client: Client to use

    :return: 'ok' if test passed, anything else will fail the test.
    :rtype: ``str``
    """

    client.retrieve_cases(timestamp="")
    return "ok"


def get_event_command(client: Client, args: Dict[str, Any]):
    """msisac-get-event command: Returns an MS-ISAC event with detailed stream information

    :type client: ``Client``
    :param Client: Client to use

    :type args: ``Dict[str, Any]``
    :param args:
        all command arguments, usually passed from ``demisto.args()``.
        ``args['event_id']`` alert ID to return

    :return:
        A ``CommandResults`` object that is then passed to ``return_results``

    :rtype: ``CommandResults``
    """

    event_id = args.get("event_id", None)
    if not event_id:
        raise ValueError("event_id not specified")

    # event is our raw-response
    event = client.get_event(event_id=event_id)
    output = {"EventID": event_id, "Stream": None}

    # If there is no event ID found the API returns a 404 error
    # Have 404 as on 'ok' response in the base class, and use this JSON path to provide output
    if "error" in event and event["error"]["message"] == "Event does not exist":
        # If there are ever more errors to parse we can expand this conditional
        return CommandResults(
            readable_output=f"There was no MS-ISAC event retrieved with Event ID {event_id}.\n",
            raw_response=event,
            outputs_prefix="MSISAC.Event",
            outputs_key_field="event_id",
            outputs=output,
        )

    output["Stream"] = format_stream_data(event)

    return CommandResults(
        readable_output=tableToMarkdown(f"MS-ISAC Event Details for {event_id}", output["Stream"]),
        raw_response=event,
        outputs_prefix="MSISAC.Event",
        outputs_key_field="event_id",
        outputs=output,
    )


def retrieve_events_command(client: Client, args: Dict[str, Any]):
    """msisac-retrieve-events command: Returns a list of MS-ISAC events in a give span of days

    :type client: ``Client``
    :param Client: Client to use

    :type args: ``Dict[str, Any]``
    :param args:
        all command arguments, usually passed from ``demisto.args()``.
        ``args['days']`` The number of days to return alerts

    :return:
        A ``CommandResults`` object that is then passed to ``return_results``

    :rtype: ``CommandResults``
    """

    days = args.get("days", None)
    # The input from our custom fields could be ints so we want to make sure we always use string type comparison
    event_id_raw = args.get("event_id", None)
    if not days:
        raise ValueError("Number of days not specified")

    # event is our raw-response
    event_list = client.retrieve_events(days=days)["data"]

    # If there are no albert events in the search window, the data key will be a string.
    if isinstance(event_list, str):
        return event_list

    # We initialize raw_response so we can use it as a check after the for loop has completed
    # If we find the event ID then this will be overwritten otherwise we return a different output
    raw_response = None
    if event_id_raw:
        event_id = str(event_id_raw)
        # Use an incrementing index to return the proper list value when we find the event_id in the response
        index = 0
        for event in event_list:
            if str(event["event_id"]) == event_id:
                readable_output = tableToMarkdown(f"MS-ISAC Event {event_id} fetched", event_list[index])
                raw_response = event_list[index]
                outputs = event_list[index]
                break
            index += 1
        # If we found the event ID then raw_response would be populated.
        # If not we catch the null response to return a different message
        if not raw_response:
            readable_output = f"No Results\n--------\nEvent ID {event_id} was not found in the past {days} days"
            outputs = None
    else:
        readable_output = tableToMarkdown(f"MS-ISAC Event List Fetched for {days} Days", event_list)
        raw_response = event_list
        outputs = event_list

    return CommandResults(
        readable_output=readable_output,
        raw_response=raw_response,
        outputs_prefix="MSISAC.RetrievedEvents",
        outputs_key_field="event_id",
        outputs=outputs,
    )


def get_alert_command(client: Client, args: Dict[str, Any]):
    """msisac-get-event command: Returns an MS-ISAC event with detailed stream information

    :type client: ``Client``
    :param Client: Client to use

    :type args: ``Dict[str, Any]``
    :param args:
        all command arguments, usually passed from ``demisto.args()``.
        ``args['event_id']`` alert ID to return

    :return:
        A ``CommandResults`` object that is then passed to ``return_results``

    :rtype: ``CommandResults``
    """

    alert_id = args.get("alert_id", None)

    # error handling since API only returns 500 errors.
    if not alert_id:
        raise ValueError("alert_id not specified")
    elif not re.match(ALERT_ID_REGEX, alert_id):
        raise DemistoException('alert_id format invalid. Please use "alert-12345" or "12345"')

    # alert is our raw response
    alert = client.get_alert(alert_id=alert_id)

    return CommandResults(
        readable_output=tableToMarkdown(f"MS-ISAC Alert Details for {alert_id}", alert),
        raw_response=alert,
        outputs_prefix="MSISAC.Alert",
        outputs_key_field="alertId",
        outputs=alert,
    )


def retrieve_cases_command(client: Client, args: Dict[str, Any]):
    """msisac-retrieve-events command: Returns a list of MS-ISAC events in a give span of days

    :type client: ``Client``
    :param Client: Client to use

    :type args: ``Dict[str, Any]``
    :param args:
        all command arguments, usually passed from ``demisto.args()``.
        ``args['days']`` The number of days to return alerts

    :return:
        A ``CommandResults`` object that is then passed to ``return_results``

    :rtype: ``CommandResults``
    """

    timestamp = args.get("timestamp", "")

    case_list = client.retrieve_cases(timestamp=timestamp)

    readable_output = tableToMarkdown(f'MS-ISAC Case List Fetched since: {timestamp or "last 72 hours"}', case_list)

    return CommandResults(
        readable_output=readable_output,
        raw_response=case_list,
        outputs_prefix="MSISAC.RetrievedCases",
        outputs_key_field="case_Id",
        outputs=case_list,
    )


@logger
def fetch_incidents(client: Client, first_fetch: datetime, last_run: Dict) -> tuple[List[dict[str, Any]], Dict]:
    """Uses to fetch events into XSIAM
    Args:
        client: Client object with request
        first_fetch: String from when to fetch if first time. "%Y-%m-%dT%H:%M:%SZ"
        last_run: Last fetch object occurs.
    Returns:
        incidents, new last_run
    """

    fetch_time: datetime

    if not last_run.get("lastRun"):
        fetch_time = first_fetch.astimezone(timezone.utc)
    else:
        last_run_time = datetime.strptime(last_run.get("lastRun", ""), XSOAR_INCIDENT_DATE_FORMAT)
        fetch_time = last_run_time.astimezone(timezone.utc)

    retrieve_cases_data: list = client.retrieve_cases(timestamp=fetch_time.strftime(XSOAR_INCIDENT_DATE_FORMAT))

    cases_to_fetch: list[dict] = []
    latest_case_created_time: datetime = fetch_time
    latest_fetched_case: str = last_run.get("lastFetchedCase", "")

    case_id = latest_fetched_case
    for case in retrieve_cases_data:
        case_created_time = datetime.strptime(case.get("createdAt"), MSISAC_CREATED_TIME_FORMAT)
        case_id = case.get("caseId", "")

        # Make sure case was created after last fetch and was not previously fetched.
        if case_created_time > fetch_time and case_id != latest_fetched_case:
            case["alertData"] = []
            affected_ip = case.get("affectedIp")

            for alert_id in case.get("alertIds", []):
                # Populating alert data for each ingested case.
                get_alert_data = client.get_alert(alert_id=alert_id)

                case["alertData"].append(get_alert_data)

            cases_to_fetch.append(
                {
                    "name": f"MS-ISAC Case: {case_id} - Affected IP: {affected_ip}",
                    "occurred": case_created_time.strftime(XSOAR_INCIDENT_DATE_FORMAT),
                    "rawJSON": json.dumps(case),
                    # We are not using mirroring.
                    # This will show ingested event numbers in fetch history modal.
                    "dbotMirrorId": f"{case_id}",
                }
            )
            demisto.debug(f"Albert Event: {case_id} has been fetched.")
            if case_created_time > latest_case_created_time:
                latest_case_created_time = case_created_time
                latest_fetched_case = case_id

        else:
            demisto.debug(f"""
                Albert Case: {case_id} was not fetched.
                Case Created Time: {case_created_time.strftime(XSOAR_INCIDENT_DATE_FORMAT)}.
                Fetch Start Time: {fetch_time.strftime(XSOAR_INCIDENT_DATE_FORMAT)}.
                """)

    next_run_dict = {"lastRun": latest_case_created_time.strftime(XSOAR_INCIDENT_DATE_FORMAT), "lastFetchedCase": case_id}

    return cases_to_fetch, next_run_dict


""" MAIN FUNCTION """


def main():
    params = demisto.params()
    args = demisto.args()
    command = demisto.command()

    api_key = params.get("apikey", {}).get("credentials", {}).get("sshkey", "") or params.get("apikey", {}).get("password", "")

    base_url = urljoin(params["url"], API_ROUTE)

    verify_certificate = not params.get("insecure", False)
    proxy = params.get("proxy", False)

    demisto.debug(f"Command being called is {command}")
    try:
        headers = {"Authorization": f"Bearer {api_key}", "Accept": "application/json"}
        client = Client(base_url=base_url, verify=verify_certificate, headers=headers, proxy=proxy)

        if command == "test-module":
            result = test_module(client)
            return_results(result)

        elif command == "msisac-get-event":  # deprecated
            result = get_event_command(client, args)
            return_results(result)

        elif command == "msisac-retrieve-events":  # deprecated
            result = retrieve_events_command(client, args)
            return_results(result)

        elif command == "msisac-get-alert":
            result = get_alert_command(client, args)
            return_results(result)

        elif command == "msisac-retrieve-cases":
            result = retrieve_cases_command(client, args)
            return_results(result)

        elif command == "fetch-incidents":
            # Since arg_to_datetime returns Optional[datetime], but we are forcing a datetime object to be returned.
            # Because of this we need to use type hint casting to force the return.
            first_fetch: datetime = cast(datetime, arg_to_datetime(params.get("first_fetch", "1 day ago"), required=True))
            events, next_run = fetch_incidents(client=client, first_fetch=first_fetch, last_run=demisto.getLastRun())

            demisto.incidents(events)
            demisto.setLastRun(next_run)

    # Log exceptions and return errors
    except Exception as e:
        return_error(f"Failed to execute {command} command.\nError:\n{str(e)}")


""" ENTRY POINT """

if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
