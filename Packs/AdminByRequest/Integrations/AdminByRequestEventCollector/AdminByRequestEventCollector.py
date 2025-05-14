"""
Event Collector Source file for AdminByRequest API.
"""

from typing import Any

import demistomock as demisto
import urllib3
from CommonServerPython import *
from CommonServerUserPython import *

# Disable insecure warnings
urllib3.disable_warnings()

""" CONSTANTS """

VENDOR = "Admin"
PRODUCT = "By_Request"
MAX_FETCH_AUDIT_LIMIT = 50000
MAX_FETCH_EVENT_LIMIT = 50000
MAX_FETCH_REQUEST_LIMIT = 5000
DATE_FORMAT_CALLS = "%Y-%m-%d"


class EventType:
    """
    This class defines an AdminByRequest API Event - used to dynamically store different types of events data.
    """

    def __init__(self, suffix: str, take: int, source_log_type: str, time_field: str, default_params: dict):
        """
        Prepare constructor for EventType class.
        Args:
            suffix: The url suffix of AdminByRequest API endpoint.
            take: Maximum events to fetch per API call.
            source_log_type: Key name for "source_log_type" field mapping inside XSIAM
            time_field: Key name for "_TIME" field mapping inside XSIAM
        """
        self.suffix = suffix
        self.take = take
        self.source_log_type = source_log_type
        self.time_field = time_field
        self.last_run_key = "start_id_" + suffix
        self.max_fetch = 1
        self.default_params = default_params


EVENT_TYPES: dict[str, EventType] = {
    "Auditlog": EventType(
        suffix="auditlog", take=10000, source_log_type="auditlog", time_field="startTimeUTC", default_params={}
    ),
    "Events": EventType(suffix="events", take=10000, source_log_type="events", time_field="eventTimeUTC", default_params={}),
    "Requests": EventType(
        suffix="requests", take=1000, source_log_type="request", time_field="requestTime", default_params={"wantscandetails": 1}
    ),
}

""" CLIENT CLASS """


class Client(BaseClient):
    """Client class to interact with the service API"""

    def __init__(self, base_url: str, api_key: str, verify: bool, use_proxy: bool) -> None:
        """
        Prepare constructor for Client class.

        Calls the constructor of BaseClient class and updates the header with the authentication token.

        Args:
            base_url: The url of AdminByRequest instance.
            api_key: The Api key for AdminByRequest API - specific for every licensing.
            verify: True if verify SSL certificate is checked in integration configuration, False otherwise.
            use_proxy: True if the proxy server needs to be used, False otherwise.
        """

        super().__init__(base_url=base_url, verify=verify, proxy=use_proxy)

        self._api_key = api_key
        self._headers: dict[str, Any] = {"apiKey": self._api_key}

    def get_events_request(self, url_suffix: str, params: dict) -> dict:
        """Retrieve the detections from AdminByRequest  API."""
        return self._http_request("GET", url_suffix=url_suffix, params=params, resp_type="json")


""" HELPER FUNCTIONS """


def remove_first_run_params(params: dict[str, Any]) -> None:
    """
    Remove the "First Run" items from the param dictionary.

    Args:
        params (Dict[str, Any]): Integration parameters.

    """
    if "startdate" in params:
        params.pop("startdate")
    if "enddate" in params:
        params.pop("enddate")


def validate_fetch_events_params(last_run: dict, event_type: EventType, use_last_run_as_params: bool) -> tuple[dict, str, str]:
    """
    Validate and update the params needed for the api call
    Args:
        last_run (dict): The last_run dictionary having the state of previous cycle.
        event_type (EventType): Event Type to fetch from API
        use_last_run_as_params (boolean): Flag that sign do we use the last-run as params for the API call
    Returns:
        Tuple[dict, str, str]: A tuple containing:
            - API call parameters.
            - URL suffix for the API endpoint.
            - Key used to update the `last_run` dictionary.
    """

    suffix = event_type.suffix
    key = event_type.last_run_key

    if use_last_run_as_params:
        params = last_run
    elif key in last_run:
        # Not First fetch: Use last run's tracking ID as startid.
        params = {**event_type.default_params, "startid": last_run[key]}
    else:
        # First-time fetch: use today's date for time-based fetch (except for 'requests')
        today = get_current_time().strftime(DATE_FORMAT_CALLS)
        date_params = {} if suffix == "requests" else {"startdate": today, "enddate": today}

        params = {**event_type.default_params, **date_params}

    # Limit the number of records per fetch
    params["take"] = min(event_type.take, event_type.max_fetch)

    return params, suffix, key


def fetch_events_list(client: Client, last_run: dict, event_type: EventType, use_last_run_as_params) -> list[dict[str, Any]]:
    """
    Main Function that Handles the Fetch action to the API service of AdminByRequest.
    Args:
        client (Client): The client object used to interact with the AdminByRequest service.
        last_run (dict): The last_run dictionary having the state of previous cycle.
        event_type (EventType): Event Type to fetch from API
        use_last_run_as_params (bool): Flag that sign do we use the last-run as params for the API call

    Returns:
        list[dict[str, Any]]: List of records retrieved from the api call.
    """
    params, suffix, last_run_key = validate_fetch_events_params(last_run, event_type, use_last_run_as_params)
    time_field, source_log_type = event_type.time_field, event_type.source_log_type
    fetch_limit = event_type.max_fetch
    last_id: int = 0
    output: list[dict[str, Any]] = []
    while True:
        try:
            # API call
            events = list(client.get_events_request(url_suffix=suffix, params=params))
        except DemistoException as error:
            err_type = getattr(error, "exception", None)
            # If we have a Connection error with the server - return clean error message
            if isinstance(err_type, requests.exceptions.ConnectionError):
                clean_msg = str(error).split("\nError Type")[0]
                raise DemistoException(f"AdminByRequest: During fetch, exception occurred {clean_msg}")
            else:
                raise DemistoException(f"AdminByRequest: During fetch, exception occurred {str(error)}")

        if not events:
            break

        for event in events:
            #  Updates each records in the list with _TIME and source_log_type fields
            #  based on specific fields for each EventType.
            last_id = event["id"]
            event["_TIME"] = time_field
            event["source_log_type"] = source_log_type

            output.append(event)

            if len(output) >= fetch_limit:
                # update last run and return because we reach limit
                last_run.update({last_run_key: int(last_id + 1)})
                return output

        # If it was the first run, we have a first run "params values"
        remove_first_run_params(params)
        params["startid"] = last_id + 1

    # If we got at list one entity to add to output - update last ID
    if last_id:
        last_run.update({last_run_key: int(last_id + 1)})

    return output


def set_event_type_fetch_limit(params: dict[str, Any]) -> list[EventType]:
    """
    Parses the event types to fetch from parameters and returns a dictionary mapping
    each selected event type's suffix to its corresponding max fetch limit.

    Args:
        params (Dict[str, Any]): Integration parameters.

    Returns:
        list[EventType]: List of event type to fetch from the api call.
    """
    event_types_to_fetch = argToList(params.get("event_types_to_fetch", []))
    event_types_to_fetch = [event_type.strip() for event_type in event_types_to_fetch]

    max_auditlog_per_fetch = arg_to_number(params.get("max_auditlog_per_fetch")) or MAX_FETCH_AUDIT_LIMIT
    max_events_per_fetch = arg_to_number(params.get("max_events_per_fetch")) or MAX_FETCH_EVENT_LIMIT
    max_requests_per_fetch = arg_to_number(params.get("max_requests_per_fetch")) or MAX_FETCH_REQUEST_LIMIT

    event_types = []
    if "Auditlog" in event_types_to_fetch:
        EVENT_TYPES["Auditlog"].max_fetch = max_auditlog_per_fetch
        event_types.append(EVENT_TYPES["Auditlog"])

    if "Events" in event_types_to_fetch:
        EVENT_TYPES["Events"].max_fetch = max_events_per_fetch
        event_types.append(EVENT_TYPES["Events"])

    if "Requests" in event_types_to_fetch:
        EVENT_TYPES["Requests"].max_fetch = max_requests_per_fetch
        event_types.append(EVENT_TYPES["Requests"])

    return event_types


def prepare_list_output(records: List[dict[str, Any]]) -> str:
    """Prepare human-readable output.

    Args:
        records: List of entities response from the API.

    Returns:
        markdown string to be displayed in the war room.
    """
    hr_outputs = []
    for rec in records:
        hr_output = {
            "ID": rec.get("id"),
            "Type": rec.get("type"),
            "Status": rec.get("status"),
            "Reason": rec.get("reason"),
            "Request Time": rec.get("requestTime"),
            "Start Time": rec.get("startTime"),
            "Event Text": rec.get("eventText"),
            "Event Time": rec.get("eventTime"),
        }
        hr_outputs.append(hr_output)

    return tableToMarkdown(name="AdminByRequests Record(s)", t=hr_outputs, removeNull=True)


""" COMMAND FUNCTIONS """


def test_module(client: Client) -> str:
    """
    Tests the connection to the service by calling each one of the api endpoints.
    Args:
        client (Client): The client object used to interact with the service.
    Returns:
        str: 'ok' if the connection is successful. If an authorization error occurs, an appropriate error message is returned.
    """
    event_types = list(EVENT_TYPES.values())
    for e in event_types:
        e.max_fetch = 1
    last_run: dict[str, Any] = {}
    fetch_events(client, last_run, event_types)
    return "ok"


def fetch_events(
    client: Client, last_run: dict, fetch_events_types: list[EventType], use_last_run_as_params: bool = False
) -> tuple[list[dict[str, Any]], dict]:
    """Fetch the specified AdminByRequest entity records.

     Args:
        client (Client): The client object used to interact with the AdminByRequest service.
        last_run (dict): The last_run dictionary having the state of previous cycle.
        fetch_events_types (list[EventType]) : list of Event Types to fetch from API
        use_last_run_as_params (bool): Flag that sign do we use the last-run as params for the API call

    Returns:
         - List of new records to be pushed into XSIAM.
         - Updated last_run dictionary.
    """
    demisto.debug("AdminByRequest fetch_events invoked")
    events = []

    for event_type in fetch_events_types:
        output = fetch_events_list(client, last_run, event_type, use_last_run_as_params)
        events.extend(output)

    demisto.debug(f"AdminByRequest next_run is {last_run}")

    return events, last_run


def get_events(client: Client, args: dict) -> CommandResults:
    """
    Inner Test Function to make sure the integration works
    Args:
        client: AdminByRequest client to be used.
        args: command arguments.

    Returns: Command results object that contain the results.
    """
    max_events = arg_to_number(args.get("limit")) or None
    # User start date in the get events arguments, else get from today
    first_fetch = arg_to_datetime(args.get("first_fetch")) or get_current_time()
    first_fetch_date = first_fetch.strftime(DATE_FORMAT_CALLS)

    call_type: str = args.get("event_type", "")
    if not max_events:
        if call_type == "Auditlog":
            max_events = MAX_FETCH_AUDIT_LIMIT
        elif call_type == "Events":
            max_events = MAX_FETCH_EVENT_LIMIT
        else:
            max_events = MAX_FETCH_REQUEST_LIMIT

    event_type = EVENT_TYPES[call_type]
    event_type.max_fetch = max_events

    first_parm = {"startdate": first_fetch_date}

    last_run_to_use_as_params = {**event_type.default_params, **first_parm}

    output, _ = fetch_events(client, last_run_to_use_as_params, [event_type], use_last_run_as_params=True)
    human_readable = prepare_list_output(output)

    command_results = CommandResults(
        readable_output=human_readable,
        outputs=output,
        outputs_prefix="AdminByRequest." + call_type,
    )
    return command_results


def main():
    """main function, parses params and runs command functions"""
    params = demisto.params()
    args = demisto.args()
    command = demisto.command()

    # get the service API url
    base_url = params.get("url")
    verify_certificate = not argToBoolean(params.get("insecure", False))
    proxy = argToBoolean(params.get("proxy", False))
    api_key = params.get("credentials", {}).get("password")

    demisto.debug(f"Command being called is {command}")
    try:
        client = Client(base_url=base_url, api_key=api_key, verify=verify_certificate, use_proxy=proxy)
        events: List[dict[str, Any]]
        if command == "test-module":
            # Command made to test the integration
            result = test_module(client)
            return_results(result)
        elif command == "fetch-events":
            fetch_events_types = set_event_type_fetch_limit(params)
            last_run = demisto.getLastRun()
            events, next_run = fetch_events(client, last_run, fetch_events_types)
            if len(events):
                demisto.debug(f"Sending {len(events)} events to XSIAM AdminByRequest, before server call.")
                send_events_to_xsiam(events=events, vendor=VENDOR, product=PRODUCT)
            demisto.setLastRun(next_run)
            demisto.debug(f"Successfully saved last_run= {demisto.getLastRun()}")
        elif command == "adminbyrequest-get-events":
            command_results = get_events(client, args)
            events = cast(List[dict[str, Any]], command_results.outputs)
            if events and argToBoolean(args.get("should_push_events", False)):
                demisto.debug(f"Sending {len(events)} events.")
                send_events_to_xsiam(events=events, vendor=VENDOR, product=PRODUCT)
            return_results(command_results)
        else:
            raise NotImplementedError(f"Command {command} is not implemented")

    # Log exceptions and return errors
    except Exception as e:
        return_error(f"Failed to execute {command} command.\nError:\n{str(e)}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
