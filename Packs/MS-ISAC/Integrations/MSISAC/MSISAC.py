import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


""" IMPORTS """

import json
import math

import urllib3

# Disable insecure warnings
urllib3.disable_warnings()


""" CONSTANTS """

API_ROUTE = "/api/v1"
MSISAC_FETCH_WINDOW_DEFAULT = 1
XSOAR_INCIDENT_DATE_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
MSISAC_S_TIME_FORMAT = "%Y-%m-%d %H:%M:%S"


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

        :type days: ``str``
        :param days: The number of days to search. This will be one or greater

        :return: dict containing the alert as returned from the API
        :rtype: ``Dict[str, Any]``
        """

        return self._http_request(method="GET", url_suffix=f"/albert/{days}", timeout=100, error_handler=self.error_handler)


""" HELPER FUNCTIONS """


@logger
def calculate_lookback_days(start_time: datetime, end_time: datetime) -> int:
    """Calculates the lookback period in days between two datetimes.

    Args:
        start_time: The start datetime.
        end_time: The end datetime.

    Returns:
        The number of days to look back, rounded according to round_down flag, with a minimum of 1.
    """

    if not (start_time or end_time):
        return MSISAC_FETCH_WINDOW_DEFAULT

    time_diff = end_time - start_time
    diff_in_days = time_diff.total_seconds() / (24 * 60 * 60)  # Calculate difference in days

    rounded_days = math.ceil(diff_in_days)

    days_param = max(MSISAC_FETCH_WINDOW_DEFAULT, rounded_days)
    return days_param


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

    client.retrieve_events(days=1)
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
        fetch_time = first_fetch
    else:
        fetch_time = datetime.strptime(last_run.get("lastRun", ""), XSOAR_INCIDENT_DATE_FORMAT)

    fetch_time_lookback_days: int = calculate_lookback_days(fetch_time, datetime.now())

    retrieve_events_data: dict = client.retrieve_events(days=fetch_time_lookback_days).get("data", [])

    events_to_fetch: list[dict] = []
    latest_event_s_time: datetime = fetch_time

    # API returns a list if there is albert event data. data key is a string if there is no data.
    if isinstance(retrieve_events_data, list):
        for event in retrieve_events_data:
            event_s_time = datetime.strptime(event.get("stime"), MSISAC_S_TIME_FORMAT)
            event_id = event.get("event_id", "")

            if event_s_time > fetch_time:  # Make sure event happened after last fetch
                event_description = event.get("description", "")
                # Populating stream data for each ingested event.
                get_event_data = client.get_event(event_id=event_id)
                event["stream"] = format_stream_data(get_event_data)
                events_to_fetch.append(
                    {
                        "name": f"{event_id} - {event_description}",
                        "occurred": event_s_time.strftime(XSOAR_INCIDENT_DATE_FORMAT),
                        "rawJSON": json.dumps(event),
                        # We are not using mirroring.
                        # This will show ingested event numbers in fetch history modal.
                        "dbotMirrorId": f"{event_id}",
                    }
                )
                demisto.debug(f"Albert Event: {event_id} has been fetched.")
                if event_s_time > latest_event_s_time:
                    latest_event_s_time = event_s_time

            else:
                demisto.debug(f"""
                    Albert Event: {event_id} was not fetched.
                    Event S_Time: {event_s_time.strftime(XSOAR_INCIDENT_DATE_FORMAT)}.
                    Fetch Start Time: {fetch_time.strftime(XSOAR_INCIDENT_DATE_FORMAT)}.
                    Fetch End Time: {datetime.now().strftime(XSOAR_INCIDENT_DATE_FORMAT)}.
                    """)

    else:
        demisto.debug(f"Here is the event data that was returned: {retrieve_events_data}")

    next_run_dict = {"lastRun": latest_event_s_time.strftime(XSOAR_INCIDENT_DATE_FORMAT)}

    return events_to_fetch, next_run_dict


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

        elif command == "msisac-get-event":
            result = get_event_command(client, args)
            return_results(result)

        elif command == "msisac-retrieve-events":
            result = retrieve_events_command(client, args)
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
