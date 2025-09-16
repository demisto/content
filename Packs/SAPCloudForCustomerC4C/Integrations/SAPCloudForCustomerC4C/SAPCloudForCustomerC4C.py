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
            demisto.debug("There is no content to return in the response.")
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


def get_events_api_call(client: Client, report_id: str, params: dict):
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

    Raises:
        DemistoException: If the response is empty or not in expected format.

    Notes:
        Time Format Requirements:
        - Timestamps must follow the format: DD.MM.YYYY HH:MM:SS UTC±Offset
        - This format specifies the date, time, and UTC offset explicitly.
        - Examples:
            "23.07.2025 12:00:51 UTC-2"   # UTC-2
            "26.07.2025 21:04:32"   # UTC
            "15.08.2025 18:30:00 UTC+05:00"   # UTC+5

    """
    res = client.http_request(
        method="GET",
        url_suffix=f"{URL_SUFFIX}{report_id}?",
        params=params,
    )
    return res


def fetch_timestamp(client: Client, report_id: str, start: str, end: str) -> Optional[str]:
    """
    Queries the SAP API to retrieve the first available 'CTIMESTAMP' within a specified time range.

    This helper function constructs a filter query using the provided start and end datetime
    boundaries to fetch events from the SAP Cloud report via the API. It returns the timestamp
    of the earliest event found within that interval or None if no events are available.

    Args:
        client (Client): The client object used to make API requests.
        report_id (str): The identifier of the SAP report to query.
        start (str): The start datetime for filtering events.
        end (str): The end datetime for filtering events.

    Returns:
        Optional[str]: The 'CTIMESTAMP' string from the first event within the time range,
                       or None if no events are found.

    Raises:
        DemistoException: If the API response is empty or has an unexpected structure.
    """
    filter_query = f"CTIMESTAMP ge '{start}' and CTIMESTAMP le '{end}'"
    params = {"$inlinecount": "allpages", "$filter": filter_query, "$top": 1, "$format": "json"}

    res = get_events_api_call(client, report_id, params)
    if not res:
        raise DemistoException(f"Empty response received from {SAP_CLOUD} API.")
    if "d" not in res or "results" not in res["d"]:
        raise DemistoException(f"Unexpected response structure from {SAP_CLOUD} API. Response: {res}")

    results = res["d"]["results"]
    return results[0]["CTIMESTAMP"] if results else None


def response_validation(client: Client, report_id: str) -> str:
    """
    Validates the structure and timestamp of a response from an SAP Cloud report.

    This function queries the SAP API for events within a specified time range
    (yesterday minus 5 minutes), and verifies that the response contains the expected
    structure and a valid 'CTIMESTAMP' field. If no events are found, it retries with
    a broader 6-hours window. The retrieved timestamp is then validated using
    `dateparser` to ensure it can be correctly parsed.

    Args:
        client (Client): The client object used to make API requests.
        report_id (str): The ID of the report to query.

    Returns:
        str: The original 'CTIMESTAMP' string if the response structure is valid and parsing succeeds.

    Raises:
        DemistoException: If the response structure is invalid, no events are returned,
                          or the timestamp cannot be parsed.
    """
    now = get_current_utc_time()
    end_date = (now - timedelta(days=1)).strftime(STRFTIME_FORMAT)
    start_date = (now - timedelta(days=1, minutes=5)).strftime(STRFTIME_FORMAT)

    timestamp_str = fetch_timestamp(client, report_id, start_date, end_date)

    # Try larger time range if nothing returned
    if not timestamp_str:
        start_date_fallback = (now - timedelta(days=1, hours=6)).strftime(STRFTIME_FORMAT)
        timestamp_str = fetch_timestamp(client, report_id, start_date_fallback, end_date)

        if not timestamp_str:
            demisto.debug(
                f"No events were found in the specified time range from yesterday {start_date_fallback} - {end_date}."
                f"Unable to retrieve a sample timestamp for validation."
            )
            raise DemistoException(
                f"Unable to retrieve a sample timestamp for validation (sample range: {start_date_fallback} - {end_date})"
                "Please ensure that the system time configuration is correct."
            )

    # Validate timestamp
    if not dateparser.parse(timestamp_str):
        demisto.debug(f"Parsing Error: Could not parse CTIMESTAMP '{timestamp_str}'.")
        raise DemistoException(
            f"""SAP timezone configuration is not supported. The current timestamp is: {timestamp_str},
            while the integration supports UTC time formats (for example: 'UTC -2', 'UTC +3').
            For more information, see the Timezone configuration section in the integration documentation file."""
        )

    return timestamp_str


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
        raise DemistoException("Report ID is a mandatory parameter, please provide it.")

    response_validation(client, report_id)
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


def add_time_to_events(events: list[dict]) -> list[dict]:
    """
    Adds the '_time' key to each event, converting the original timestamp to UTC.

    This function iterates through a list of event dictionaries and creates a new list
    where each event includes a '_time' field. The '_time' value is derived from the
    existing 'CTIMESTAMP' key, parsed and converted to UTC timezone.

    Args:
        events (list[dict]): A list of dictionaries representing events. Each event is
                             expected to contain a 'CTIMESTAMP' key with a timestamp string.

    Returns:
        list[dict]: A new list of events, each with an added '_time' field in UTC format.
    """

    if not events:
        return []

    updated_events = []
    for event in events:
        c_timestamp = event.get("CTIMESTAMP")
        parsed_datetime = dateparser.parse(c_timestamp, settings={"DATE_ORDER": "DMY"})  # type: ignore
        utc_datetime = parsed_datetime.astimezone(timezone.utc)  # type: ignore
        formatted_time = utc_datetime.strftime(DATE_FORMAT)
        new_event = event.copy()
        new_event["_time"] = formatted_time
        updated_events.append(new_event)

    return updated_events


def get_events_command(client: Client, report_id: str, args: dict) -> tuple[List[Dict], CommandResults]:
    """
    Retrieves events from the SAP Cloud for Customer API based on provided parameters,
    handling pagination and validating timestamps.

    This function:
    - Validates the timestamp format of the first event to ensure compatibility before fetching bulk data.
    - Retrieves events using paginated API calls according to the specified limit, start date, and duration.
    - Aggregates all retrieved events into a single list.
    - Returns both the raw events list and a CommandResults object containing a human-readable markdown table and the raw data.

    Args:
        client (Client): The API client instance used to make requests.
        report_id (str): The report ID to fetch events from.
        args (dict): Command arguments, including:
            - 'start_date' (str): Start date for event retrieval in "DD-MM-YYYY HH:MM:SS" format.
            - 'days_from_start' (int, optional): Number of days from the start_date to define the retrieval window (default: 2).
            - 'limit' (int, optional): Maximum number of events to retrieve (default: 10).

    Returns:
        tuple[List[Dict], CommandResults]:
            - List[Dict]: A list of event dictionaries retrieved from the API.
            - CommandResults: Contains a markdown table of events for display and the raw events data.

    Raises:
        DemistoException: If the 'start_date' argument is missing or if timestamp validation fails (via `response_validation`).
    """
    limit: int = arg_to_number(args.get("limit")) or DEFAULT_LIMIT_OF_EVENTS
    start_date: Optional[str] = args.get("start_date")
    if not start_date:
        # Handle the case where start_date is missing, as it's required for get_events
        raise DemistoException("start_date argument is missing. Cannot retrieve events.")

    # Validate the first timestamp format before processing the full list
    _ = response_validation(client, report_id)

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
        end_date (str): Fetch events that are older than or equal to this time (formatted as DD-MM-YYYY HH:MM:SS).

            Note: Although the filter uses `le` (less than or equal), based on testing,
            the API does **not** include events that exactly match the upper bound (`end_date`).
            This means `le` behaves as **less than** (`<`) rather than less than or equal (`<=`).
            For example, the filter:
                CTIMESTAMP ge '28-07-2025 10:11:00' and CTIMESTAMP le '28-07-2025 10:12:00'
            actually retrieves events where:
                '28-07-2025 10:11:00' <= event timestamp < '28-07-2025 10:12:00'

            The API does not support the `lt` operator, so `le` is used instead, but it effectively
            acts as a strict upper bound.

    Returns:
        Optional[List[Dict[str, Any]]]: A list of events, or None if an error occurs.
    """

    filter = f"CTIMESTAMP ge '{start_date}' and CTIMESTAMP le '{end_date}'"
    params = {"$filter": filter, "$skip": skip, "$top": top, "$format": "json", "$inlinecount": "allpages"}

    demisto.debug(f"Performing the get events call with - {params=}.")
    res = get_events_api_call(client, report_id, params)

    return res.get("d", {}).get("results", [])


def get_timestamp_offset_hour(client: Client, report_id: str) -> float:
    """
    Retrieves the timezone offset in hours by fetching and validating a sample event's timestamp.

    This function requests a single event for a specific user from the SAP Cloud API,
    validates the timestamp format using `response_validation`, and then parses it to
    determine the UTC offset in hours. The offset reflects the timezone configured on
    the SAP Cloud server and is used for consistent time calculations.

    Args:
        client (Client): The client instance used to make API calls.
        report_id (str): The ID of the report to query for events.

    Returns:
        float: The timezone offset from UTC in hours (e.g., 2.0 for UTC+2, -5.0 for UTC-5).

    Raises:
        DemistoException: If the timestamp cannot be validated or parsed properly via `response_validation`.
    """
    timestamp_str = response_validation(client, report_id)
    dt_object = dateparser.parse(timestamp_str)
    offset_timedelta = dt_object.tzinfo.utcoffset(dt_object)  # type: ignore
    offset_hour = offset_timedelta.total_seconds() / 3600  # type: ignore
    return offset_hour


def fetch_events(client: Client, params: dict, last_run: dict) -> tuple[dict, list[Any]]:
    """
    Fetches events from SAP Cloud API based on a specified report ID and date range.

    Prerequisites:
    - The technical user configured in SAP C4C for this integration must have its timezone set to a UTC format
        (UTC with an offset, for example 'UTC -2', 'UTC +3').
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
    """
    now_utc = get_current_utc_time()
    demisto.debug(f"the last run is {last_run=}")
    demisto.debug("Starting the SAP C4C fetch events command.")

    report_id = str(params.get("report_id"))
    max_events_per_fetch = arg_to_number(params.get("max_fetch")) or MAX_EVENTS_PER_FETCH
    all_events: list[dict[str, Any]] = []
    skip_count = INIT_SKIP

    timestamp_offset_hour = last_run.get("timezone_offset")
    # If this is the first fetch, calculate the timezone offset by using an API call.
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

    demisto.debug(f"Getting events from: {start_date_for_filter_str} to: {end_date_for_filter_str}")

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
    # Setting the next_run - last_fetch to the current time (which is the end time of this fetch)
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
        base64String = encode_to_base64(f"{user_name}:{password}")  # type: ignore
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
                events = add_time_to_events(events)
                send_events_to_xsiam(events, vendor=VENDOR, product=PRODUCT)
            return_results(results)

        elif command == "fetch-events":
            last_run = demisto.getLastRun() or {}
            next_run, events = fetch_events(client, params, last_run)
            if events:
                events = add_time_to_events(events)
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
