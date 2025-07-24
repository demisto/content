import demistomock as demisto  # noqa: F401
import urllib3
from CommonServerPython import *  # noqa: F401
from typing import Any
from datetime import datetime, timedelta

# Disable insecure warnings
urllib3.disable_warnings()

""" CONSTANTS """

SAP_CLOUD = "SAP CLOUD FOR CUSTOMER"
STRFTIME_FORMAT = "%d-%m-%Y %H:%M:%S"
VENDOR = "SAP"
PRODUCT = "C4C"
URL_SUFFIX = "/sap/c4c/odata/ana_businessanalytics_analytics.svc/"
INIT_SKIP = 0
DEFAULT_TOP = 1000  # Max number of events that are retrieved from the api response
MAX_EVENTS_PER_FETCH = 10000
DEFAULT_LIMIT_OF_EVENTS = 10
DEFAULT_DAYS_FROM_START = 2
DATE_FORMAT = "%Y-%m-%dT%H:%M:%SZ"  # ISO8601 format with UTC

""" CLIENT CLASS """


class Client(BaseClient):
    """
    Client to use in the SAP Cloud for Customer integration. Overrides BaseClient
    """

    def __init__(self, base_url, base64String, verify):
        super().__init__(base_url=base_url, verify=verify, ok_codes=(200, 201, 202))
        self.credentials = {"Authorization": f"Basic {base64String}", "Content-Type": "application/json"}

    def http_request(
        self,
        method,
        url_suffix,
        params=None,
        data=None,
        headers=None,
        files=None,
        json=None,
        without_credentials=False,
        resp_type="json",
    ):
        """
        A wrapper for requests lib to send our requests and handle requests and responses better.
        """
        headers = headers or {}
        if not without_credentials:
            headers.update(self.credentials)
        res = super()._http_request(
            method=method,
            url_suffix=url_suffix,
            headers=headers,
            params=params,
            data=data,
            json_data=json,
            files=files,
            resp_type=resp_type,
            error_handler=self.error_handler,
            retries=2,
        )
        return res

    def error_handler(self, res: requests.Response) -> None:  # pragma: no cover
        """
        Error handler to call by super()._http_request in case an error was occurred.
        Handles specific HTTP status codes and raises a DemistoException.
        Args:
            res (requests.Response): The HTTP response object.
        """
        # Handle error responses gracefully
        if res.status_code == 401:
            raise DemistoException(f"{SAP_CLOUD} - Got unauthorized from the server. Check the credentials. {res.text}")
        elif res.status_code == 204:
            return
        elif res.status_code == 404:
            raise DemistoException(f"{SAP_CLOUD} - The resource was not found at {res.url}. {res.text}")
        raise DemistoException(f"{SAP_CLOUD} - Error in API call {res.status_code} - {res.text}")


""" COMMAND FUNCTIONS """


def encode_to_base64(input_string: str) -> str:
    """
    Encodes a given string into its Base64 representation.

    Args:
      input_string: The string to be encoded.

    Returns:
      The Base64 encoded string.
    """
    bytes_string = input_string.encode("utf-8")
    encoded_bytes = base64.b64encode(bytes_string)
    encoded_string = encoded_bytes.decode("utf-8")
    return encoded_string


def client_api_call(client: Client, report_id: str, params: dict):
    """
    Executes a GET request to the SAP Cloud API for a specific report.

    This helper function constructs the full URL using a predefined `URL_SUFFIX`
    and the provided `report_id`, then sends an HTTP GET request with the
    given parameters.

    Args:
        client (Client): The client object configured to make HTTP requests.
        report_id (str): The identifier for the specific report to query.
        params (dict): A dictionary of query parameters to be appended to the URL
                       (e.g., "$top", "$filter", "$format", "$select").

    Returns:
        dict: The parsed JSON response from the SAP Cloud API.
    """
    res = client.http_request(
        method="GET",
        url_suffix=f"{URL_SUFFIX}{report_id}?",
        params=params,
    )
    return res


def is_valid_timestamp(timestamp_str: str):
    """
    Validates if a given timestamp string is parseable by dateparser.

    This function attempts to parse the input timestamp string. If parsing fails,
    it logs a debug message and raises a DemistoException, indicating a potential
    issue with the SAP timezone configuration.

    Args:
        timestamp_str (str): The timestamp string to validate, typically originating
                             from a 'CTIMESTAMP' field in an API response.
                             Expected format (though dateparser is flexible): "DD.MM.YYYY HH:MM:SS UTC(+-)Num".

    Raises:
        DemistoException: If the `timestamp_str` cannot be parsed, suggesting
                          an unsupported SAP timezone configuration or an invalid format.
    """
    if not dateparser.parse(timestamp_str):
        demisto.debug(f"Parsing Error: Could not parse CTIMESTAMP '{timestamp_str}'.")
        raise DemistoException("""SAP timezone configuration is not supported, kindly see the readme and description file on how
                               to configure the correct timezone""")


def test_module(client: Client, report_id: str) -> str:
    """
    Tests API connectivity and authentication.
    Args:
        client (Client): The client object to use for API requests.
        report_id (str): The ID of the report to use for testing.
    Returns:
        str: 'ok' if the test passed, otherwise raises an exception.
    """
    if not report_id:
        raise DemistoException("Report ID is a mandatory parameter for test-module. Please provide a Report ID.")

    params = {"$inlinecount": "allpages", "$filter": "CUSER eq 'ASAHAYA'", "$top": 2, "$format": "json", "$select": "CTIMESTAMP"}
    res = client_api_call(client, report_id, params)
    timestamp_str = res["d"]["results"][0]["CTIMESTAMP"]
    is_valid_timestamp(timestamp_str)
    return "ok"


def get_current_utc_time() -> datetime:
    """
    Returns the current UTC time as an aware datetime object.

    Returns:
        datetime: The current time in UTC with timezone information.
    """
    return datetime.now(timezone.utc)


def convert_utc_to_offset(utc_dt: datetime, offset_hour: float) -> datetime:
    """
    Converts a UTC datetime object to a specified UTC offset.

    This function adjusts the timezone of a given UTC datetime object
    to a new timezone defined by `offset_hour`, representing the same
    point in time.

    Args:
        utc_dt (datetime): A timezone datetime object representing a point in UTC time.
        offset_hour (float): The desired timezone offset from UTC in hours
                             (e.g., `+2.0` for UTC+2, `-5.0` for UTC-5).

    Returns:
        datetime: A datetime object representing the original time,
                  adjusted to the new `offset_hour` timezone.
    """
    utc_with_offset = timezone(timedelta(hours=offset_hour))
    return utc_dt.astimezone(utc_with_offset)


def get_end_date(start_date_str: str, days: int = 2) -> str:
    """
    Calculates an end date by adding a specified number of days to a given start date.

    The start date string is parsed, converted to UTC, and then the timedelta is applied.
    The resulting end date is returned as a formatted string.

    Args:
        start_date_str (str): The start date as a string, expected to be in
                              the format defined by `STRFTIME_FORMAT` (e.g., "DD-MM-YYYY HH:MM:SS").
        days (int, optional): The number of days to add to the start date.
                              Defaults to 2.

    Returns:
        str: The calculated end date as a string, formatted according to `STRFTIME_FORMAT`.
    """
    start_date = datetime.strptime(start_date_str, STRFTIME_FORMAT)
    start_date = start_date.replace(tzinfo=timezone.utc)

    end_date = start_date + timedelta(days=days)

    return end_date.strftime(STRFTIME_FORMAT)


def add_time_to_events(events: list):
    """Adds the _time key to the events.

    This function iterates through a list of event dictionaries and, for each event,
    adds a new key "_time". The value for "_time" is taken from the existing "CTIMESTAMP" key
    within the same event dictionary. If the "CTIMESTAMP" key does not exist, "_time" will be None.

    Args:
        events (list[Any]): A list of dictionaries, where each dictionary represents an event.
                             Each event dictionary is expected to potentially contain a "CTIMESTAMP" key.

    Returns:
        None: This function modifies the input `events` list in-place and does not return a new object.
    """
    is_valid_timestamp(events[0]["CTIMESTAMP"])

    for event in events:
        parsed_datetime = dateparser.parse(event.get("CTIMESTAMP"))
        utc_datetime = parsed_datetime.astimezone(timezone.utc)  # type: ignore
        formatted_time = utc_datetime.strftime(DATE_FORMAT)
        event["_time"] = formatted_time


def get_events_command(client: Client, report_id: str, args: dict) -> tuple[List[Dict], CommandResults]:
    """
    Retrieves events from the SAP Cloud for Customer API based on provided parameters.

    Args:
        client (Client): The API client to use for the request.
        report_id (str): The ID of the report to fetch events from.
        args (dict): Command arguments, including:
            - 'start_date' (str): Start date for event retrieval (formatted as DD-MM-YYYY HH:MM:SS).
            - 'days_from_start' (int, optional): Number of days from the start_date to define the end of the retrieval period.
                                                 Defaults to 2 days.
            - 'limit' (int, optional): Maximum number of events to retrieve. Defaults to 10.

    Returns:
        tuple[List[Dict], CommandResults]: A tuple containing:
            - A list of events (List[Dict]): The raw list of retrieved events.
            - CommandResults: The command results object with a human-readable output table and raw response.
    """
    limit: int = arg_to_number(args.get("limit")) or DEFAULT_LIMIT_OF_EVENTS
    start_date: Optional[str] = args.get("start_date")
    if not start_date:
        # Handle the case where start_date is missing, as it's required for get_events
        raise DemistoException("start_date argument is missing. Cannot retrieve events.")

    days_from_start: int = arg_to_number(args.get("days_from_start")) or DEFAULT_DAYS_FROM_START
    end_date: str = get_end_date(start_date, days=days_from_start)

    skip_count = 0
    all_events: list[dict[str, Any]] = []

    while limit > 0:
        top = min(DEFAULT_TOP, limit)
        response = get_events(client, report_id, skip=skip_count, top=top, start_date=start_date, end_date=end_date)
        if response:
            all_events.extend(response)
            # Since DEFAULT_TOP is always <= limit, incrementing skip_count by DEFAULT_TOP or top makes no difference here.
            skip_count += DEFAULT_TOP
            limit -= len(response)
        else:
            demisto.debug("No more events exist or no response received, breaking...")
            break

    hr = tableToMarkdown(name=f"Events from {SAP_CLOUD}", t=all_events, removeNull=True, is_auto_json_transform=True)
    return all_events, CommandResults(readable_output=hr, raw_response=all_events)


def get_events(
    client: Client, report_id: str, skip: int, top: int, start_date: str, end_date: str
) -> Optional[List[Dict[str, Any]]]:
    """
    Get a list of events from the SAP Cloud for Customer API.

    Args:
        client (Client): The client object to use for API requests.
        report_id (str): The ID of the report to fetch events from.
        skip (int): Number of items to skip for pagination.
        top (int): Maximum number of events to return in this request.
        start_date (str): Fetch events that are newer than or equal to this time (formatted as DD-MM-YYYY HH:MM:SS).
        end_date (str): Fetch events that are older than or equal to this time
        (formatted as DD-MM-YYYY HH:MM:SS). Defaults to None.

    Returns:
        Optional[List[Dict[str, Any]]]: A list of events, or None if an error occurs.
    """

    filter = f"CTIMESTAMP ge '{start_date}' and CTIMESTAMP le '{end_date}'"
    params = {"$filter": filter, "$skip": skip, "$top": top, "$format": "json", "$inlinecount": "allpages"}

    res = client_api_call(client, report_id, params)
    demisto.debug(f"{params=}")

    return res.get("d", {}).get("results", [])


def get_timestamp_offset_hour(client: Client, report_id: str) -> float:
    """
    Retrieves the timezone offset in hours by fetching a sample event's timestamp
    for a specific user from the SAP Cloud API.

    This function makes an API request to fetch a single event. It then parses the timestamp
    from this event to determine the UTC offset. This offset is assumed to
    be representative of the server's timezone configuration.

    Args:
        client (Client): The client object used to make API requests.
        report_id (str): The ID of the report to query for events.

    Returns:
        float: The timezone offset from UTC in hours (e.g., 2.0 for UTC+2, -5.0 for UTC-5).
    """
    params = {"$inlinecount": "allpages", "$filter": "CUSER eq 'OSAWYERR'", "$top": 1, "$format": "json"}
    res = client_api_call(client, report_id, params)
    timestamp_str = res["d"]["results"][0]["CTIMESTAMP"]
    is_valid_timestamp(timestamp_str)
    dt_object = dateparser.parse(timestamp_str)
    offset_timedelta = dt_object.tzinfo.utcoffset(dt_object)  # type: ignore
    offset_hour = offset_timedelta.total_seconds() / 3600  # type: ignore
    return offset_hour


def fetch_events(client: Client, params: dict, last_run: dict) -> tuple[dict, list[Any]]:
    """
    Fetches events from SAP Cloud API based on a specified report ID and date range.

    Prerequisites:
    - The technical user configured in SAP C4C for this integration must have its timezone set to a UTC format.
        This is crucial for accurate timestamp filtering and to prevent errors during event fetching.
        Refer to the integration's documentation for more details.

    Args:
        client (Client): The client object to use for API requests.
        params (dict): Integration parameters, expected to contain 'report_id' and optionally 'max_fetch'.
        last_run (dict): The last run object from Demisto, potentially containing 'last_fetch' and 'timezone_offset'.

    Returns:
        tuple[dict, list]: A tuple containing the next run dictionary and a list of all fetched events.
            - The first element is a dictionary representing the next run state, including:
                - 'last_fetch' (str): The timestamp (in STRFTIME_FORMAT) marking the end of the current fetch period,
                  which will be the start for the next fetch.
                - 'timezone_offset' (float): The timestamp offset in hours used for the current fetch.
            - The second element is a list of dictionaries, where each dictionary represents a fetched event.
              Events are retrieved in batches until 'max_events_per_fetch' is reached or no more events are available.

    Raises:
        DemistoException: If 'report_id' is not provided in 'params' or is not a string.
    """
    now_utc = get_current_utc_time()
    demisto.debug(f"the last run is {last_run=}")
    demisto.debug("Starting the SAP C4C fetch events command.")

    report_id = params.get("report_id")
    if not isinstance(report_id, str):
        raise DemistoException("Report ID must be provided in the integration parameters and must be a string.")
    max_events_per_fetch = arg_to_number(params.get("max_fetch")) or MAX_EVENTS_PER_FETCH
    all_events: list[dict[str, Any]] = []
    skip_count = INIT_SKIP

    timestamp_offset_hour = last_run.get("timezone_offset")
    if not timestamp_offset_hour:
        timestamp_offset_hour = get_timestamp_offset_hour(client, report_id)
    demisto.debug(f"Using timezone offset: {timestamp_offset_hour} hours.")

    end_date_for_filter_dt = convert_utc_to_offset(now_utc, timestamp_offset_hour)
    end_date_for_filter_str = end_date_for_filter_dt.strftime(STRFTIME_FORMAT)

    start_date_for_filter_str = last_run.get("last_fetch")
    if not start_date_for_filter_str:
        # If no last_fetch, start 1 minute before the end_date to ensure no gaps and initial fetch.
        start_date_for_filter_dt = end_date_for_filter_dt - timedelta(minutes=1)
        start_date_for_filter_str = start_date_for_filter_dt.strftime(STRFTIME_FORMAT)

    demisto.debug(f"Getting events from: {start_date_for_filter_str}")
    demisto.debug(f"Getting events until: {end_date_for_filter_str}")

    while max_events_per_fetch > 0:
        top = min(DEFAULT_TOP, max_events_per_fetch)
        response = get_events(
            client, report_id, skip=skip_count, top=top, start_date=start_date_for_filter_str, end_date=end_date_for_filter_str
        )
        if response:
            all_events.extend(response)
            # Since DEFAULT_TOP is always <= max_events_per_fetch, incrementing skip_count by DEFAULT_TOP or top makes no
            # difference here.
            skip_count += DEFAULT_TOP
            # Decrease max_events_per_fetch by the number of events received.
            max_events_per_fetch -= len(response)
        else:
            demisto.debug("No more events exist or no response received, breaking...")
            break

    demisto.debug(f"Finished fetching. Total events collected: {len(all_events)}.")
    # Set next_run to the current time marking the start of this fetch
    next_run = {"last_fetch": end_date_for_filter_str, "timezone_offset": timestamp_offset_hour}
    return next_run, all_events


def main():
    """
    Initiate integration command
    """
    command = demisto.command()
    demisto.debug(f"Command being called is {command}")
    args = demisto.args()
    params = demisto.params()

    # init credentials
    user_name = demisto.get(params, "username.identifier")
    password = demisto.get(params, "username.password")
    server_url = params.get("url", "").strip("/")
    report_id = params.get("report_id")
    try:
        base64String = encode_to_base64(user_name + ":" + password)  # type: ignore
        client = Client(
            base_url=server_url,
            base64String=base64String,
            verify=not params.get("insecure", False),
        )

        if command == "test-module":
            # This call is made when clicking the integration 'Test' button.
            return_results(test_module(client, report_id))  # Let test_module handle validation

        elif command == "sap-cloud-get-events":
            events, results = get_events_command(client, report_id, args)
            should_push_events = argToBoolean(args.get("should_push_events", "false"))
            if should_push_events and events:
                add_time_to_events(events)
                send_events_to_xsiam(events, vendor=VENDOR, product=PRODUCT)
            return_results(results)

        elif command == "fetch-events":
            last_run = demisto.getLastRun() or {}
            next_run, events = fetch_events(client, params, last_run)
            if events:
                add_time_to_events(events)
                demisto.debug("Successfully added _time to events")
                send_events_to_xsiam(events, vendor=VENDOR, product=PRODUCT)
            demisto.setLastRun(next_run)
            demisto.debug(f"Successfully saved last_run= {demisto.getLastRun()}")

        else:
            raise NotImplementedError(f"Command {command} is not implemented")

    except Exception as e:
        return_error(f"Failed to execute {command} command.\nError:\n{str(e)}")


if __name__ in ("__main__", "__builtin__", "builtins"):  # pragma: no cover
    main()
